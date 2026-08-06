import asyncio
import datetime
import json
import logging
import re
import sys
from dataclasses import dataclass
from typing import Annotated

import josepy as jose
import requests
from acme import challenges, client, crypto_util, errors, messages
from certbot._internal.display import obj as display_obj
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, File, Header, HTTPException
from pydantic import AliasChoices
from pydantic import Field as PydanticField
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlmodel import Field, Session, SQLModel, create_engine, select

display_obj.set_display(display_obj.FileDisplay(sys.stdout, False))

LETSENCRYPT_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"
ZEROSSL_DIRECTORY_URL = "https://acme.zerossl.com/v2/DV90"

# CAs that refuse to create an account without External Account Binding credentials.
EAB_REQUIRED_CAS = {"zerossl"}


class Settings(BaseSettings):
    dns_auth_url: str = "http://localhost:8080/update"
    dns_auth_propagation_delay: int = 5
    email: str

    # Ordered, comma-separated list of CAs to try. The first one is the primary,
    # the rest are fallbacks used only when the preceding CA fails.
    ca_order: str = "letsencrypt"

    # ACME_URL / EAB_KID / EAB_HMAC_KEY are the pre-multi-CA names of these settings
    # and are still honoured so existing deployments keep working.
    letsencrypt_acme_url: str = PydanticField(
        default=LETSENCRYPT_DIRECTORY_URL,
        validation_alias=AliasChoices("letsencrypt_acme_url", "acme_url"),
    )
    letsencrypt_eab_kid: str | None = PydanticField(
        default=None, validation_alias=AliasChoices("letsencrypt_eab_kid", "eab_kid")
    )
    letsencrypt_eab_hmac_key: str | None = PydanticField(
        default=None, validation_alias=AliasChoices("letsencrypt_eab_hmac_key", "eab_hmac_key")
    )

    zerossl_acme_url: str = ZEROSSL_DIRECTORY_URL
    zerossl_eab_kid: str | None = None
    zerossl_eab_hmac_key: str | None = None

    db_file_name: str = "database.db"
    log_level: str = "DEBUG"
    issuing_timeout: int = 120
    domain_suffix: str

    model_config = SettingsConfigDict(env_file=".env")


settings = Settings()
logging.getLogger("").setLevel(logging.getLevelName(settings.log_level))
logging.debug("This will get logged")


@dataclass(frozen=True)
class AcmeProvider:
    """A single upstream CA the service can issue certificates through."""

    name: str
    directory_url: str
    eab_kid: str | None
    eab_hmac_key: str | None


def build_providers(local_settings: Settings) -> list[AcmeProvider]:
    """Turn the flat settings into the ordered list of CAs to try.

    Raises ValueError on a misconfiguration so the service fails at startup
    rather than on the first certificate request.
    """
    known = {
        "letsencrypt": AcmeProvider(
            name="letsencrypt",
            directory_url=local_settings.letsencrypt_acme_url,
            eab_kid=local_settings.letsencrypt_eab_kid,
            eab_hmac_key=local_settings.letsencrypt_eab_hmac_key,
        ),
        "zerossl": AcmeProvider(
            name="zerossl",
            directory_url=local_settings.zerossl_acme_url,
            eab_kid=local_settings.zerossl_eab_kid,
            eab_hmac_key=local_settings.zerossl_eab_hmac_key,
        ),
    }

    names = [name.strip().lower() for name in local_settings.ca_order.split(",") if name.strip()]
    if not names:
        raise ValueError("ca_order must name at least one CA")
    if len(names) != len(set(names)):
        raise ValueError(f"ca_order must not repeat a CA: {names}")

    providers = []
    for name in names:
        if name not in known:
            raise ValueError(f"Unknown CA '{name}' in ca_order. Known CAs: {sorted(known)}")
        provider = known[name]
        if name in EAB_REQUIRED_CAS and not (provider.eab_kid and provider.eab_hmac_key):
            raise ValueError(
                f"CA '{name}' requires External Account Binding credentials: "
                f"set {name.upper()}_EAB_KID and {name.upper()}_EAB_HMAC_KEY"
            )
        providers.append(provider)
    return providers


CA_PROVIDERS = build_providers(settings)
logging.info("Configured CAs, in order of preference: %s", [p.name for p in CA_PROVIDERS])


class DnsAuthError(RuntimeError):
    """Publishing the DNS-01 challenge record failed.

    This is our own infrastructure, not the CA's, so falling back to another CA
    would fail the same way.
    """


class CaAttemptError(RuntimeError):
    """Issuing through one CA failed in a way another CA might handle."""


def extract_identifiers(csr_pem: bytes) -> tuple[list[str], list[str]]:
    """Extract DNS and IP identifiers from a CSR.
    :param csr_pem: The CSR in PEM format.
    :return: A tuple of lists of DNS and IP identifiers.
    """
    csr = x509.load_pem_x509_csr(csr_pem)
    dns_names = crypto_util.get_names_from_subject_and_extensions(csr.subject, csr.extensions)
    dns_names = [name.lower() for name in dns_names]
    try:
        san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        ip_names = []
    else:
        ip_names = san_ext.value.get_values_for_type(x509.IPAddress)
    return dns_names, ip_names


def validate_csr(csr_pem: bytes, allowed_domains: list[str]) -> None:
    """Reject a CSR the client is not allowed to have signed.

    Checked once per request, before any CA is contacted: these are client
    errors, so retrying them against a fallback CA would only waste time.
    """
    dns_names, ip_names = extract_identifiers(csr_pem)
    logging.info("DNS names: %s", dns_names)
    logging.info("IP names: %s", ip_names)
    if ip_names:
        raise HTTPException(status_code=422, detail="IP identifiers in CSR are not supported")

    not_allowed = sorted(set(dns_names) - set(allowed_domains))
    if not_allowed:
        raise HTTPException(
            status_code=422,
            detail=f"Requested domains are not allowed: {not_allowed}. Allowed: {allowed_domains}",
        )


sqlite_url = f"sqlite:///{settings.db_file_name}"

connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, connect_args=connect_args)


class CertbotBackendAccount(SQLModel, table=True):
    id: int | None = Field(primary_key=True, default=None)
    eab_kid: str | None = Field()
    eab_hmac_key: str | None = Field()
    email: str = Field()
    directory_url: str = Field()

    jwk: bytes = Field()  # PEM encoded account key
    account_uri: str = Field()  # it will allow us to save one API call to get account info


class CertificateIssuer:
    def __init__(self, provider: AcmeProvider, engine):
        self.engine = engine
        self.email = settings.email

        self.acc_key = None
        self.directory = None
        self.client_acme = None
        self.regr = None
        self.upstream_account = None
        self.provider_name = provider.name
        self.eab_kid = provider.eab_kid
        self.eab_hmac_key = provider.eab_hmac_key
        self.directory_url = provider.directory_url

    def create_account_key(self):
        return jose.JWKRSA(
            key=rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        )

    def get_acme_client_and_account(self):
        # Register account and accept TOS
        with Session(self.engine) as session:
            account_db_entry = session.exec(
                select(CertbotBackendAccount)
                .where(CertbotBackendAccount.email == self.email)
                .where(CertbotBackendAccount.eab_kid == self.eab_kid)
                .where(CertbotBackendAccount.eab_hmac_key == self.eab_hmac_key)
                .where(CertbotBackendAccount.directory_url == self.directory_url)
            ).first()

            # First, initialize the account key, client network instance and the directory
            if account_db_entry is None:
                self.acc_key = self.create_account_key()
                logging.debug("No account_db_entry found, new acc_key: %s", self.acc_key)
                directory_url = self.directory_url
            else:
                logging.debug("Found account_db_entry = %s", account_db_entry)
                logging.debug("acc_key = %s", account_db_entry.jwk)
                self.acc_key = jose.JWK.json_loads(account_db_entry.jwk.decode("utf8"))
                directory_url = account_db_entry.directory_url

            net = client.ClientNetwork(self.acc_key, user_agent="serles-acme")

            self.directory = client.ClientV2.get_directory(directory_url, net)
            self.client_acme = client.ClientV2(self.directory, net=net)

            # Then, take care of the account
            if account_db_entry is None:
                account_db_entry = CertbotBackendAccount()
                session.add(account_db_entry)

                if self.eab_kid and self.eab_hmac_key:
                    eab = messages.ExternalAccountBinding.from_data(
                        account_public_key=self.acc_key,
                        kid=self.eab_kid,
                        hmac_key=self.eab_hmac_key,
                        directory=self.directory,
                    )
                    reg_msg = messages.NewRegistration.from_data(
                        email=self.email, terms_of_service_agreed=True, external_account_binding=eab
                    )
                else:
                    reg_msg = messages.NewRegistration.from_data(
                        email=self.email, terms_of_service_agreed=True
                    )

                self.regr = self.client_acme.new_account(reg_msg)
                account_db_entry.account_uri = self.regr.uri
                account_db_entry.jwk = self.acc_key.json_dumps().encode("utf8")
                account_db_entry.email = self.email
                account_db_entry.eab_kid = self.eab_kid
                account_db_entry.eab_hmac_key = self.eab_hmac_key
                account_db_entry.directory_url = self.directory_url
                session.commit()
            else:
                self.client_acme.net.account = {"uri": account_db_entry.account_uri}

            self.upstream_account = account_db_entry

    async def validate_challenges(self, orderr: messages.OrderResource, deadline: datetime.datetime):
        authz_list = orderr.authorizations

        for authz in authz_list:
            # Choosing challenge.
            # authz.body.challenges is a set of ChallengeBody objects.
            for challb in authz.body.challenges:
                if datetime.datetime.now() > deadline:
                    raise errors.TimeoutError()

                # Find the supported challenge.
                if isinstance(challb.chall, challenges.DNS01):
                    response, validation = challb.response_and_validation(self.client_acme.net.key)

                    domain_name = authz.body.identifier.value
                    validation_name = challb.validation_domain_name(domain_name)

                    logging.debug(
                        "Performing challenge for %s with %s=%s", domain_name, validation_name, validation
                    )

                    data = {"domain": validation_name.lower() + ".", "txt": validation}
                    # Our DNS server for ACME challenges is typically run on the same machine,
                    # so we don't really need async http here
                    try:
                        authenticator_response = requests.post(
                            settings.dns_auth_url, data=json.dumps(data), timeout=10
                        )
                    except requests.RequestException as exc:
                        raise DnsAuthError(f"DNS server at {settings.dns_auth_url} is unreachable") from exc
                    if authenticator_response.status_code != 200:
                        raise DnsAuthError(f"Failed to update DNS record: {authenticator_response.text}")

                    await asyncio.sleep(settings.dns_auth_propagation_delay)

                    # Let the CA server know that we are ready for the challenge.
                    self.client_acme.answer_challenge(challb, response)

    async def poll_authorizations(
        self, orderr: messages.OrderResource, deadline: datetime.datetime
    ) -> messages.OrderResource:
        """Poll Order Resource for status.
        This is copied from certbot's acme/client.py and modified to be async.
        """
        responses = []
        for url in orderr.body.authorizations:
            while datetime.datetime.now() < deadline:
                authzr = self.client_acme._authzr_from_response(self.client_acme._post_as_get(url), uri=url)
                if authzr.body.status != messages.STATUS_PENDING:  # pylint: disable=no-member
                    responses.append(authzr)
                    break
                await asyncio.sleep(1)
        # If we didn't get a response for every authorization, we fell through
        # the bottom of the loop due to hitting the deadline.
        if len(responses) < len(orderr.body.authorizations):
            raise errors.TimeoutError()
        failed = []
        for authzr in responses:
            if authzr.body.status != messages.STATUS_VALID:
                for chall in authzr.body.challenges:
                    if chall.error is not None:
                        failed.append(authzr)
        if failed:
            raise errors.ValidationError(failed)
        return orderr.update(authorizations=responses)

    async def poll_finalization(
        self,
        orderr: messages.OrderResource,
        deadline: datetime.datetime,
        fetch_alternative_chains: bool = False,
    ) -> messages.OrderResource:
        """
        Poll an order that has been finalized for its status.
        If it becomes valid, obtain the certificate.
        It taken from certbot's acme/client.py and modified to be async.

        :returns: finalized order (with certificate)
        :rtype: messages.OrderResource
        """

        while datetime.datetime.now() < deadline:
            await asyncio.sleep(1)
            response = self.client_acme._post_as_get(orderr.uri)
            body = messages.Order.from_json(response.json())
            if body.status == messages.STATUS_INVALID:
                if body.error is not None:
                    raise errors.IssuanceError(body.error)
                raise errors.Error(
                    "The certificate order failed. No further information was provided by the server."
                )
            if body.status == messages.STATUS_VALID and body.certificate is not None:
                certificate_response = self.client_acme._post_as_get(body.certificate)
                orderr = orderr.update(body=body, fullchain_pem=certificate_response.text)
                if fetch_alternative_chains:
                    alt_chains_urls = self.client_acme._get_links(certificate_response, "alternate")
                    alt_chains = [self.client_acme._post_as_get(url).text for url in alt_chains_urls]
                    orderr = orderr.update(alternative_fullchains_pem=alt_chains)
                return orderr
        raise errors.TimeoutError()

    async def sign(self, csr):
        """Issue a certificate for an already-validated CSR through this CA.

        Any failure attributable to the CA is raised as CaAttemptError so the
        caller can move on to the next CA in the chain. A DnsAuthError means our
        own DNS side is broken and is left to propagate.
        """
        deadline = datetime.datetime.now() + datetime.timedelta(seconds=settings.issuing_timeout)
        try:
            self.get_acme_client_and_account()

            orderr = self.client_acme.new_order(csr)
            logging.debug("orderr: %s", orderr)

            logging.debug("Got order status: %s", orderr.body.status)
            if orderr.body.status == messages.STATUS_PENDING:
                await self.validate_challenges(orderr, deadline)
                orderr = await self.poll_authorizations(orderr, deadline)

                # According to 7.1.6, we can assume that the order transitions to "ready" state
                # once all the authorizations are verified (i.e. are "valid")

                # what a nice way to update a single field
                orderr = orderr.update(body=orderr.body.update(status=messages.STATUS_READY))

            logging.debug("Got order status (2): %s", orderr.body.status)
            if orderr.body.status == messages.STATUS_READY:
                # Finalize the order
                orderr = self.client_acme.begin_finalization(orderr)

            logging.debug("Got order status (3): %s", orderr.body.status)
            if orderr.body.status in [messages.STATUS_PROCESSING, messages.STATUS_VALID]:
                orderr = await self.poll_finalization(orderr, deadline)
                return orderr.fullchain_pem

            logging.debug("Got order status (4): %s", orderr.body.status)
            raise CaAttemptError(f"{self.provider_name}: order ended in status '{orderr.body.status}'")
        except errors.TimeoutError as exc:
            raise CaAttemptError(
                f"{self.provider_name}: timed out after {settings.issuing_timeout}s"
            ) from exc
        except (errors.Error, requests.RequestException) as exc:
            raise CaAttemptError(f"{self.provider_name}: {exc}") from exc


def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


app = FastAPI()


@app.on_event("startup")
def on_startup():
    create_db_and_tables()


@app.post("/api/v1/issue")
async def issue_cert(
    csr: Annotated[bytes, File()], x_forwarded_tls_client_cert_info: Annotated[str, Header()]
):

    def parse_cn(input: str) -> str:
        """Parse the subject CN from the x-forwarded header."""
        # FIXME: Traefik wraps CNs with the Subject="%" and encodes them in URL format,
        # could not find proper way to parse it
        pat = re.compile("Subject%3D%22CN%3Dwirenboard-(.*?)%22")
        match = pat.search(input)
        if match:
            return "wirenboard-" + match.group(1)
        return ""

    logging.debug("Got CSR: %s", csr.decode("utf8"))
    logging.debug("Got x_cert_subject_dn: %s", x_forwarded_tls_client_cert_info)
    try:
        cn = parse_cn(x_forwarded_tls_client_cert_info)
        logging.debug("Extracted CN: %s", cn)
    except Exception as e:
        logging.error("Failed to parse subject DN", exc_info=e)
        raise HTTPException(status_code=422, detail="Invalid subject DN") from e

    match = re.fullmatch(r"wirenboard-([A-Za-z0-9]+)", cn)
    if not match:
        raise HTTPException(status_code=422, detail="Invalid CN format")
    wb_serial = match.group(1).lower()
    logging.debug("Extracted wb serial from CN: %s", wb_serial)

    allowed_domains = [f"*.{wb_serial}.{settings.domain_suffix}", f"{wb_serial}.{settings.domain_suffix}"]

    validate_csr(csr, allowed_domains)

    # Try the configured CAs in order, so that an outage or a rate limit at the
    # primary CA does not take certificate issuance down with it.
    last_error = None
    for provider in CA_PROVIDERS:
        logging.info("Requesting a certificate for %s from %s", wb_serial, provider.name)
        try:
            fullchain_pem = await CertificateIssuer(provider, engine).sign(csr)
        except DnsAuthError as exc:
            # Our own DNS side is broken; another CA would hit the same wall.
            logging.error("DNS-01 challenge could not be published", exc_info=exc)
            raise HTTPException(
                status_code=503, detail="Failed to publish the DNS-01 challenge record"
            ) from exc
        except CaAttemptError as exc:
            logging.warning("CA %s failed to issue a certificate: %s", provider.name, exc)
            last_error = exc
            continue

        logging.info("Got a certificate for %s from %s", wb_serial, provider.name)
        logging.debug("resulting cert chain %s", fullchain_pem)
        return {"fullchain_pem": fullchain_pem}

    raise HTTPException(
        status_code=502,
        detail=f"All configured CAs failed to issue a certificate. Last error: {last_error}",
    )

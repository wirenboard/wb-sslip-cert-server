# wb-sslip-cert-server

This services handles certificate generation and renewal through an ACME CA
(ZeroSSL and/or Let's Encrypt).

* It takes requests from PLCs (signed with the PLC hardware crypto module)
* Then it generates a certificate request to the CA
* It passes DNS challenge text to the sslip's wildcard-dns-http-server service
* After DNS challenge is complete, it obtains the signed certificate from the CA and returns it to the PLC

It's deployed as a Docker container, see **infra** repository for details.

## Configuration

Everything is configured through environment variables; a `.env` file next to
`main.py` is read as well.

| Variable | Default | Meaning |
| --- | --- | --- |
| `EMAIL` | — | **Required.** ACME account e-mail, shared by all CAs |
| `DOMAIN_SUFFIX` | — | **Required.** Zone the PLC domains live under, e.g. `example.com`. A PLC with serial `ABC` gets `abc.<suffix>` and `*.abc.<suffix>` |
| `CA_ORDER` | `zerossl,letsencrypt` | Ordered list of CAs to try, see below |
| `ZEROSSL_ACME_URL` | `https://acme.zerossl.com/v2/DV90` | ZeroSSL ACME directory |
| `ZEROSSL_EAB_KID` / `ZEROSSL_EAB_HMAC_KEY` | unset | **Required** when `zerossl` is in `CA_ORDER`, which it is by default |
| `LETSENCRYPT_ACME_URL` | `https://acme-v02.api.letsencrypt.org/directory` | Let's Encrypt ACME directory; point at `https://acme-staging-v02.api.letsencrypt.org/directory` for testing |
| `LETSENCRYPT_EAB_KID` / `LETSENCRYPT_EAB_HMAC_KEY` | unset | Optional; Let's Encrypt does not need EAB |
| `DNS_AUTH_URL` | `http://localhost:8080/update` | Where to publish the DNS-01 TXT record |
| `DNS_AUTH_PROPAGATION_DELAY` | `5` | Seconds to wait after publishing the record before telling the CA to check it |
| `ISSUING_TIMEOUT` | `120` | Deadline **per CA attempt**, in seconds |
| `DB_FILE_NAME` | `database.db` | SQLite file holding the cached ACME accounts. Relative paths resolve against `/app` in the container |
| `LOG_LEVEL` | `DEBUG` | Root logger level |

`ACME_URL`, `EAB_KID` and `EAB_HMAC_KEY` are the older names of the three
`LETSENCRYPT_*` variables and still work.

`ISSUING_TIMEOUT` is per attempt, so the worst case for one request is
`ISSUING_TIMEOUT × len(CA_ORDER)`. Keep the PLC-side HTTP timeout above that.

### The DNS-01 side

For every challenge the service sends this to `DNS_AUTH_URL` and expects `200`:

```json
{"domain": "_acme-challenge.abc.example.com.", "txt": "<validation value>"}
```

Anything else — a non-200, or an unreachable host — answers the PLC with `503`
and does **not** try the next CA, since the next CA would need the same record.

## Certificate authorities

`CA_ORDER` is a comma-separated, ordered list of CAs. The first one is the
primary; the rest are fallbacks, tried only when the preceding CA fails to
issue. Falling back covers a CA-side problem — an outage, a rate limit, a
rejected order — so that one CA having a bad day doesn't stop issuance.

The default is ZeroSSL first, Let's Encrypt as the fallback:

```
CA_ORDER=zerossl,letsencrypt
```

**ZeroSSL requires EAB credentials, so `ZEROSSL_EAB_KID` and
`ZEROSSL_EAB_HMAC_KEY` are mandatory under the default `CA_ORDER`** — the
service refuses to start without them. A deployment that wants Let's Encrypt
only must say so explicitly:

```
CA_ORDER=letsencrypt
```

Failures that are *not* the CA's fault do not trigger a fallback:

* an invalid or out-of-scope CSR is rejected once, up front, with `422`
* a failure to publish the DNS-01 record is our own DNS side, so it returns
  `503` immediately — another CA would hit the same wall

When every configured CA fails, the response is `502` with the last CA's error.

Unknown CA names, duplicates, and a ZeroSSL entry without EAB credentials are
rejected at startup, not on the first request.

ZeroSSL's EAB KID and HMAC key come from the "Developer" section of the ZeroSSL
dashboard. An ACME account is registered separately per CA and cached in the
database, keyed by directory URL, e-mail and EAB credentials.

## Deployment

The **infra** repository is the source of truth for the real deployment. The
compose file below is a self-contained illustration of how the pieces fit
together and spells out every environment variable the service reads.

```yaml
services:
  cert-server:
    image: ghcr.io/wirenboard/wb-sslip-cert-server:main
    restart: unless-stopped
    depends_on:
      - wildcard-dns
    volumes:
      # ACME accounts live here — see "Persist the database" below
      - cert-server-db:/app/data
    environment:
      # --- required ---
      EMAIL: acme@example.com
      DOMAIN_SUFFIX: example.com

      # --- certificate authorities ---
      CA_ORDER: zerossl,letsencrypt
      ZEROSSL_ACME_URL: https://acme.zerossl.com/v2/DV90
      ZEROSSL_EAB_KID: ${ZEROSSL_EAB_KID:?set it in .env}
      ZEROSSL_EAB_HMAC_KEY: ${ZEROSSL_EAB_HMAC_KEY:?set it in .env}
      LETSENCRYPT_ACME_URL: https://acme-v02.api.letsencrypt.org/directory
      # Let's Encrypt needs no EAB, so these stay unset:
      # LETSENCRYPT_EAB_KID: ""
      # LETSENCRYPT_EAB_HMAC_KEY: ""

      # --- DNS-01 challenge ---
      DNS_AUTH_URL: http://wildcard-dns:8080/update
      DNS_AUTH_PROPAGATION_DELAY: "5"

      # --- misc ---
      DB_FILE_NAME: /app/data/database.db
      ISSUING_TIMEOUT: "120"
      LOG_LEVEL: INFO
    labels:
      traefik.enable: "true"
      traefik.http.routers.cert-server.rule: Host(`cert.example.com`)
      traefik.http.routers.cert-server.entrypoints: websecure
      traefik.http.routers.cert-server.tls: "true"
      # TLSOption with clientAuth: requireAndVerifyClientCert + the WB CA,
      # defined in Traefik's dynamic configuration
      traefik.http.routers.cert-server.tls.options: wb-mtls@file
      traefik.http.routers.cert-server.middlewares: pass-client-cert
      traefik.http.middlewares.pass-client-cert.passtlsclientcert.info.subject.commonname: "true"
      traefik.http.services.cert-server.loadbalancer.server.port: "8000"

  wildcard-dns:
    # Whatever image the infra repo uses for sslip's wildcard-dns-http-server;
    # it has to answer POST /update as described in "The DNS-01 side" above
    image: wildcard-dns-http-server:latest
    restart: unless-stopped
    ports:
      - "53:53/udp"

  traefik:
    image: traefik:v3
    restart: unless-stopped
    ports:
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./traefik:/etc/traefik:ro

volumes:
  cert-server-db:
```

Secrets go in a `.env` file next to the compose file rather than into the
compose file itself:

```
ZEROSSL_EAB_KID=...
ZEROSSL_EAB_HMAC_KEY=...
```

### Never expose the service directly

Authorisation is entirely based on the `X-Forwarded-Tls-Client-Cert-Info`
header: the PLC serial is parsed out of the client certificate's CN, and that
serial decides which domains the CSR may cover. The service trusts the header
as it arrives, so whoever can reach it directly can forge the header and get a
certificate for **any** PLC serial in the zone.

Only the reverse proxy that actually verified the client certificate may reach
port 8000. Do not publish it with `ports:`.

### Persist the database

`DB_FILE_NAME` points at the SQLite file caching the registered ACME accounts.
Left on the container filesystem it is lost whenever the container is recreated,
and the service then registers a brand-new ACME account on the next request —
which walks straight into the CA's new-account rate limits after a few deploys.
Keep it on a volume, as above.

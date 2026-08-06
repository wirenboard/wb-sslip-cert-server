# wb-sslip-cert-server

This services handles certificate generation and renewal through an ACME CA
(Let's Encrypt and/or ZeroSSL).

* It takes requests from PLCs (signed with the PLC hardware crypto module)
* Then it generates a certificate request to the CA
* It passes DNS challenge text to the sslip's wildcard-dns-http-server service
* After DNS challenge is complete, it obtains the signed certificate from the CA and returns it to the PLC

It's deployed as a Docker container, see **infra** repository for details.

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

### Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `CA_ORDER` | `zerossl,letsencrypt` | Ordered list of CAs to try |
| `EMAIL` | — | Account e-mail, shared by all CAs |
| `ISSUING_TIMEOUT` | `120` | Deadline **per CA attempt**, in seconds |
| `LETSENCRYPT_ACME_URL` | Let's Encrypt production directory | |
| `LETSENCRYPT_EAB_KID` / `LETSENCRYPT_EAB_HMAC_KEY` | unset | Optional; Let's Encrypt does not need EAB |
| `ZEROSSL_ACME_URL` | `https://acme.zerossl.com/v2/DV90` | |
| `ZEROSSL_EAB_KID` / `ZEROSSL_EAB_HMAC_KEY` | unset | **Required** when `zerossl` is in `CA_ORDER`, which it is by default |

`ACME_URL`, `EAB_KID` and `EAB_HMAC_KEY` are the older names of the three
`LETSENCRYPT_*` variables and still work.

Note that `ISSUING_TIMEOUT` is per attempt, so the worst-case time for a request
is `ISSUING_TIMEOUT × len(CA_ORDER)`. Keep the PLC-side HTTP timeout above that.

ZeroSSL requires External Account Binding: take the KID and HMAC key from the
"Developer" section of the ZeroSSL dashboard. An ACME account is registered
separately per CA and cached in the local database, keyed by directory URL,
e-mail and EAB credentials.
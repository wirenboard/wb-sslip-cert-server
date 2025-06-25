# wb-sslip-cert-server

This services handles letsencrypt certificate generation and renewal.

* It takes requests from PLCs (signed with the PLC hardware crypto module)
* Then it generates a certificate request to LE
* It passes DNS challenge text to the sslip's wildcard-dns-http-server service
* After DNS challenge is complete, it obtains the signed certificate from LE and returns it to the PLC

It's deployed as a Docker container, see **infra** repository for details.
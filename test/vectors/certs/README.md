# Certificate/CMS Vector Sources

This directory contains imported upstream vectors plus a small set of derived fixtures/snapshots.

## Upstream repositories

- OpenSSL: `https://github.com/openssl/openssl` at commit `5971d32cfbf6ee34b0b4681ed693baddfe3573b4`
- BearSSL: `https://github.com/bearssl/bearssl` at commit `3d9be2f60b7764e46836514bcd6e453abdfa864a`
- PKI.js: `https://github.com/PeculiarVentures/PKI.js` at commit `1bb60c22567a8608f296a2d06ddc06bd2da7125e`
- encrypted-dns (old): `https://github.com/paulmillr/encrypted-dns` at commit `5291280e5ffc19a497a555ae37ba7afa3a41b52c`
- encrypted-dns (jiya): `https://github.com/jiya-mira/encrypted-dns` at commit `85e27c8386bda716e2ffcfcf014e8d065b5eeeb9`

## Per-test-case source mapping

- `bearssl/*`
  - source repo url: `https://github.com/bearssl/bearssl` at commit `3d9be2f60b7764e46836514bcd6e453abdfa864a`
  - source path in repo: `test/x509/*`
  - local count: `52`
  - mapping rule: same basename (`test/vectors/certs/bearssl/<name>` <- `test/x509/<name>`)
  - status: exact copy of the upstream directory subset

- `openssl/*`
  - source repo url: `https://github.com/openssl/openssl` at commit `5971d32cfbf6ee34b0b4681ed693baddfe3573b4`
  - source path in repo: `test/certs/*`
  - local count: `331`
  - mapping rule: same basename (`test/vectors/certs/openssl/<name>` <- `test/certs/<name>`)
  - status: exact copy of the upstream directory subset

- `openssl-d2i/*`
  - source repo url: `https://github.com/openssl/openssl` at commit `5971d32cfbf6ee34b0b4681ed693baddfe3573b4`
  - source path in repo: `test/d2i-tests/*`
  - local count: `10`
  - mapping rule: same basename (`test/vectors/certs/openssl-d2i/<name>` <- `test/d2i-tests/<name>`)
  - status: exact copy of the upstream directory subset

- `openssl-cms/*`
  - source repo url: `https://github.com/openssl/openssl` at commit `5971d32cfbf6ee34b0b4681ed693baddfe3573b4`
  - source path in repo: `test/recipes/80-test_cms_data/*`
  - local count: `7`
  - mapping rule: same basename (`test/vectors/certs/openssl-cms/<name>` <- `test/recipes/80-test_cms_data/<name>`)
  - status: exact copy of the upstream directory subset

- `PKI.js/smime-test.eml`
  - source repo url: `https://github.com/PeculiarVentures/PKI.js` at commit `1bb60c22567a8608f296a2d06ddc06bd2da7125e`
  - source path in repo: `examples/SMIMEVerificationExample/TestSMIME.eml`
  - import type: exact copy

- `PKI.js/ecc-recipient-private-key.pem`
  - source repo url: `https://github.com/PeculiarVentures/PKI.js` at commit `1bb60c22567a8608f296a2d06ddc06bd2da7125e`
  - source path in repo: `test/ECCCMSSharedInfo_before_RFC5753.spec.ts`
  - source location: `test/ECCCMSSharedInfo_before_RFC5753.spec.ts:7`
  - source symbol: `recipientPrivateKeyPem` (embedded PEM string)
  - import type: extracted exact text block

- `PKI.js/ecc-recipient-cert.pem`
  - source repo url: `https://github.com/PeculiarVentures/PKI.js` at commit `1bb60c22567a8608f296a2d06ddc06bd2da7125e`
  - source path in repo: `test/ECCCMSSharedInfo_before_RFC5753.spec.ts`
  - source location: `test/ECCCMSSharedInfo_before_RFC5753.spec.ts:14`
  - source symbol: `recipientCertificatePem` (embedded PEM string)
  - import type: extracted exact text block

- `PKI.js/ecc-recipient-cert.der`
  - source repo url: `https://github.com/PeculiarVentures/PKI.js` at commit `1bb60c22567a8608f296a2d06ddc06bd2da7125e`
  - source path in repo: `test/ECCCMSSharedInfo_before_RFC5753.spec.ts`
  - source location: `test/ECCCMSSharedInfo_before_RFC5753.spec.ts:14`
  - source symbol: `recipientCertificatePem`
  - import type: DER decoded from the embedded PEM

- `PKI.js/ecc-enveloped.cms`
  - source repo url: `https://github.com/PeculiarVentures/PKI.js` at commit `1bb60c22567a8608f296a2d06ddc06bd2da7125e`
  - source path in repo: `test/ECCCMSSharedInfo_before_RFC5753.spec.ts`
  - source location: `test/ECCCMSSharedInfo_before_RFC5753.spec.ts:34`
  - source symbol: `envelopedDataPem` (embedded PEM CMS)
  - import type: extracted exact text block

- `PKI.js/ecc-enveloped.der`
  - source repo url: `https://github.com/PeculiarVentures/PKI.js` at commit `1bb60c22567a8608f296a2d06ddc06bd2da7125e`
  - source path in repo: `test/ECCCMSSharedInfo_before_RFC5753.spec.ts`
  - source location: `test/ECCCMSSharedInfo_before_RFC5753.spec.ts:34`
  - source symbol: `envelopedDataPem`
  - import type: DER decoded from the embedded PEM CMS

- `PKI.js/cms-signed-issue170.der`
  - source repo url: `https://github.com/PeculiarVentures/PKI.js` at commit `1bb60c22567a8608f296a2d06ddc06bd2da7125e`
  - source path in repo: `test/cmsSignedComplexExample.spec.ts`
  - source location: `test/cmsSignedComplexExample.spec.ts:40`
  - source symbol: `testData` in `it("Special test case for issue #170")`
  - import type: base64 decoded fixture

- `encrypted-dns/cloudflare-https-old.mobileconfig`
  - source repo url: `https://github.com/paulmillr/encrypted-dns` at commit `5291280e5ffc19a497a555ae37ba7afa3a41b52c`
  - source path in repo: `signed/cloudflare-https.mobileconfig`
  - import type: exact copy

- `encrypted-dns/cloudflare-https-jiya.mobileconfig`
  - source repo url: `https://github.com/jiya-mira/encrypted-dns` at commit `85e27c8386bda716e2ffcfcf014e8d065b5eeeb9`
  - source path in repo: `signed/cloudflare-https.mobileconfig`
  - import type: exact copy

- `encrypted-dns/cloudflare-https-jiya.der`
  - source repo url: `https://github.com/jiya-mira/encrypted-dns` at commit `85e27c8386bda716e2ffcfcf014e8d065b5eeeb9`
  - source path in rpeo: `signed/cloudflare-https.mobileconfig`
  - source location: `signed/cloudflare-https.mobileconfig` (binary CMS; no line numbers)
  - import type: extracted signer chain cert from CMS `CertificateSet` (index `2`, sha256 `8c0434f940b2ab877a73d59470e4867a83f3f6e11f6755340c12216b63a6e80b`)

## Hash verification result

Hash provenance scan against the upstream repositories listed above, at the pinned commits:

- total non-markdown files in `test/vectors/certs`: `410`
- exact upstream matches: `403`
  - OpenSSL: `348`
  - BearSSL: `52`
  - PKI.js file copy: `1`
  - encrypted-dns old/jiya mobileconfig: `2`
- non-direct-copy files: `7`
  - PKI.js embedded-constant extractions / DER decodes: `6`
  - encrypted-dns signer cert extraction: `1`

## Rebuild notes

To rebuild imported vectors from scratch, copy by path rules above and re-run the extraction transforms for embedded PKI.js constants and encrypted-dns signer cert extraction.

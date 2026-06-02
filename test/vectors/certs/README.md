# Certificate/CMS Vector Sources

This directory contains imported upstream vectors plus a small set of derived fixtures/snapshots.

## Upstream sources

- OpenSSL: `https://github.com/openssl/openssl` at commit `5971d32cfbf6ee34b0b4681ed693baddfe3573b4`
- BearSSL: `https://github.com/bearssl/bearssl` at commit `3d9be2f60b7764e46836514bcd6e453abdfa864a`
- PKI.js: `https://github.com/PeculiarVentures/PKI.js` at commit `1bb60c22567a8608f296a2d06ddc06bd2da7125e`
- encrypted-dns (old): `https://github.com/paulmillr/encrypted-dns` at commit `5291280e5ffc19a497a555ae37ba7afa3a41b52c`
- encrypted-dns (jiya): `https://github.com/jiya-mira/encrypted-dns` at commit `85e27c8386bda716e2ffcfcf014e8d065b5eeeb9`
- NIST PKITS:
  - data archive: `https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents/PKITS_data.zip`
  - test-suite document: `https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents/PKITS.pdf`
  - version: `1.0.1`, document date: `2011-04-14`
  - downloaded locally on `2026-05-26`
  - `PKITS_data.zip` sha256: `592f66030d2eff80fced7ad022e197d96b7ee4ccce7da9df9c9b2007b1665665`
  - `PKITS.pdf` sha256: `506913f4b727704ee1b52b17aa472dc6fbcf01e41e7ad88ba505f29c1a74d9ea`
- NIST Path Discovery Test Suite:
  - data archive: `https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents/PathDiscoveryTestSuite.zip`
  - test-suite document: `https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents/PathDiscoveryTestSuite.pdf`
  - version: draft `0.1.1`, document date: `2005-06-03`
  - downloaded locally on `2026-05-26`
  - `PathDiscoveryTestSuite.zip` sha256: `ab0681c26ab4c940419842f49482633a7b8db4e6b86e2fb227ff72f009cf9415`
  - `PathDiscoveryTestSuite.pdf` sha256: `5dc968caf73b6a41e9831e19155c9d8348fc9b89445715c4cccd1537a687a888`

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

- `pkits/{certs,crls,certpairs,smime}/*`
  - source archive url: `https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents/PKITS_data.zip`
  - source document url: `https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents/PKITS.pdf`
  - source archive sha256: `592f66030d2eff80fced7ad022e197d96b7ee4ccce7da9df9c9b2007b1665665`
  - source document sha256: `506913f4b727704ee1b52b17aa472dc6fbcf01e41e7ad88ba505f29c1a74d9ea`
  - source paths in archive: `certs/*`, `crls/*`, `certpairs/*`, `smime/*`
  - local count: `1150` (`405` certificates, `173` CRLs, `348` crossCertificatePair objects, `224` S/MIME messages)
  - mapping rule: preserve archive path below `test/vectors/certs/pkits/` (`test/vectors/certs/pkits/<path>` <- `<path>`)
  - status: exact extraction of the PKITS X.509 object set described by `PKITS.pdf` section 6.1 plus the S/MIME messages described by section 6.2
  - omitted archive paths: `pkcs12/*` (PKCS#12 containers/private keys) and LDAP helper files

- `path-discovery/Path Discovery Test Suite/{End Entity Certs,Trust Anchor Certs,smime}/*`
  - source archive url: `https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents/PathDiscoveryTestSuite.zip`
  - source document url: `https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents/PathDiscoveryTestSuite.pdf`
  - source archive sha256: `ab0681c26ab4c940419842f49482633a7b8db4e6b86e2fb227ff72f009cf9415`
  - source document sha256: `5dc968caf73b6a41e9831e19155c9d8348fc9b89445715c4cccd1537a687a888`
  - source paths in archive: `Path Discovery Test Suite/End Entity Certs/*`, `Path Discovery Test Suite/Trust Anchor Certs/*`, `Path Discovery Test Suite/smime/*`
  - local count: `153` (`75` end-entity certificates, `3` trust-anchor certificates, `75` S/MIME messages)
  - mapping rule: preserve archive path below `test/vectors/certs/path-discovery/` (`test/vectors/certs/path-discovery/<path>` <- `<path>`)
  - status: exact extraction of the certificate and S/MIME message files relevant to local X.509/CMS parsing and path-building tests
  - omitted archive paths: `Path Discovery Test Suite/pkcs12/*` (PKCS#12 containers/private keys)
  - note: this package does not implement HTTP/LDAP certificate retrieval, so these vectors are imported as local object/message fixtures rather than remote-discovery fixtures

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

- `encrypted-dns/cloudflare-signer-jiya.der`
  - source repo url: `https://github.com/jiya-mira/encrypted-dns` at commit `85e27c8386bda716e2ffcfcf014e8d065b5eeeb9`
  - source path in repo: `signed/cloudflare-https.mobileconfig`
  - source location: `signed/cloudflare-https.mobileconfig` (binary CMS; no line numbers)
  - import type: extracted signer chain cert from CMS `CertificateSet` (index `2`, sha256 `8c0434f940b2ab877a73d59470e4867a83f3f6e11f6755340c12216b63a6e80b`)

## Hash verification result

Hash provenance scan against the upstream sources listed above, at the pinned commits/hashes:

- total non-markdown files in `test/vectors/certs`: `1713`
- exact upstream matches: `1706`
  - OpenSSL: `348`
  - BearSSL: `52`
  - NIST PKITS archive entries: `1150`
  - NIST Path Discovery Test Suite archive entries: `153`
  - PKI.js file copy: `1`
  - encrypted-dns old/jiya mobileconfig: `2`
- non-direct-copy files: `7`
  - PKI.js embedded-constant extractions / DER decodes: `6`
  - encrypted-dns signer cert extraction: `1`

## Rebuild notes

To rebuild imported vectors from scratch, copy by path rules above and re-run the extraction transforms for embedded PKI.js constants and encrypted-dns signer cert extraction.
To rebuild the PKITS subset, extract `certs/*`, `crls/*`, `certpairs/*`, and `smime/*` from `PKITS_data.zip` into `test/vectors/certs/pkits/`, preserving those archive paths.
To rebuild the Path Discovery subset, extract `Path Discovery Test Suite/End Entity Certs/*`, `Path Discovery Test Suite/Trust Anchor Certs/*`, and `Path Discovery Test Suite/smime/*` from `PathDiscoveryTestSuite.zip` into `test/vectors/certs/path-discovery/`, preserving those archive paths.

# Changelog for micro-key-producer

## 0.10.1 (2026-08-29)

- pgp: added legacy CFB key protection option, exposed packet helpers
- gpgkp: fixed status-fd on pipes, identity verification, key path handling and `-u` check
- x509: made verification reject weak (small-order) Ed25519 public keys
- asn1, convert: reworked BER tag parsing, expanded WebCrypto converters
- Added input validation to ipns, otp, password and tor modules

## 0.10.0 (2026-08-14)

- password: change format
- pgp: default to argon2 keys
- General hardening
- Fix scure-base import issues
- Deps updates

## 0.9.0 (2026-06-14)

- Lots of hardening related to May 2026 self-audit
  - pgp and x509 submodules are now stable and covered by lots of tests
- asn1: new submodule
- bls submodule was moved into separate [micro-eth-signer](https://github.com/paulmillr/micro-eth-signer) package

## 0.8.6 (2026-04-23)

- Add support for custom curves in x509 certs

## 0.8.5 (2026-02-27)

- Bugfixes for x509 submodule

## 0.8.4 (2026-02-27)

- Bugfixes for x509 submodule

## 0.8.3 (2026-02-25)

- `micro-key-producer/x509.js` new submodule for X.509 TLS certificates

## 0.8.2 (2025-09-18)

- Add back export maps for text editor autocompletion

## 0.8.1 (2025-08-25)

- Add gpgkp binary: Sign git commits without gnupg.
- Upgrade to noble v2 release

## 0.8.0 (2025-08-20)

- The package is now ESM-only. ESM can finally be loaded from common.js on node v20.19+
  - Node v20.19 is now the minimum required version
  - Package imports now work correctly in bundler-less environments, such as browsers
  - Reduces npm package size (traffic consumed)
  - Reduces unpacked npm size (on-disk space)
- Add gpgkp: Sign git commits without gnupg.
- Add convert: WebCrypto-compatible JWK, DER, PKCS#8, SPKI converter
- Upgrade to noble v2 beta

## 0.7.6 (2025-04-24)

- Bump deps
- pgp: Ensure no default createdAt in secondary methods

## 0.7.5 (2025-01-18)

- Re-upload 0.7.4

## 0.7.4 (2025-01-18)

- Use ts verbatimModuleSyntax for native typescript support in node.js (type stripping)

## 0.7.3 (2025-01-10)

- Fix import errors happening in latest noble versions
- Use typescript isolatedDeclarations for friendler doc auto-gen
- Publish package to JSR

## 0.7.2 (2024-11-23)

- Bump dependencies
- Improve parser and minifier friendliness

## 0.7.1 (2024-10-03)

- Bump noble and scure dependencies, make them less strict (using `^version`)

### New Contributors

- @huckym made their first contribution in https://github.com/paulmillr/micro-key-producer/pull/25

## 0.7.0 (2024-06-03)

- The package is now called micro-key-producer.
- It integrates previous packages micro-otp, micro-password-generator, bls12-381-keygen and ed25519-keygen.

## 0.6.2 (2024-05-17)

- Move files from lib into root to improve typescript autocompletion
- Update dependency micro-packed

## 0.6.1 (2024-05-11)

- PGP: Improve date validation
- PGP: Expose fast getKeyId

## 0.6.0 (2024-05-05)

- All functions are now synchronous. No more `await`.

## 0.5.0 (2024-03-24)

- The package is now hybrid cjs-esm.
- Updated noble dependencies.

## 0.4.11 (2024-02-14)

- Bump dependencies

## 0.4.10 (2023-10-13)

- Refactor imports, reduce code duplication
- Improve documentation

## 0.4.9 (2023-08-28)

- GitHub CI auto-publish

## 0.4.8 (2023-08-28)

- ipns address by @0xc0de4c0ffee in https://github.com/paulmillr/ed25519-keygen/pull/10

### New Contributors

- @0xc0de4c0ffee made their first contribution in https://github.com/paulmillr/ed25519-keygen/pull/10

## 0.4.7 (2023-08-28)

- Switch CI to pnpm

## 0.4.6 (2023-08-28)

- Added IPNS address support
- Updated dependencies
- CI: test on node.js v18 and v20

## 0.4.5 (2023-05-12)

- CI: auto-publish to NPM on GitHub release

## 0.4.4 (2023-05-12)

- Maintenance release

## 0.4.3 (2023-04-27)

- CI: upgrade node.js to v20

## 0.4.2 (2023-04-12)

- Bump dependencies

## 0.4.1 (2023-03-20)

- Removed unnecessary byte length requirement in `sign`
- Removed `verify` ensureBytes, added tests

## 0.4.0 (2023-03-16)

- Switch from noble-ed25519 to noble-curves

## 0.3.0 (2023-01-28)

- Merged SLIP0010 HDKey functionality from https://github.com/paulmillr/micro-ed25519-hdkey package

## 0.2.4 (2022-08-30)

- Added utils
- Fixed issues

## 0.2.3 (2022-08-27)

- Dep update

## 0.2.2 (2022-07-21)

- Set up CI, fixed build step

## 0.2.1 (2022-07-17)

- ESM

## 0.2.0 (2022-07-16)

- Also export publicKeyBytes

## 0.1.2 (2022-06-29)

- Import fixes

## 0.1.1 (2022-06-29)

- Fix typescript issues

## 0.1.0 (2022-06-28)

- Initial release

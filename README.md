# ed25519-keygen

Generate ed25519 keys for SSH, PGP (GPG), TOR, IPNS and SLIP-0010 hdkey.

- Pure JS, no CLI tools are involved
- Can generate both deterministic and random keys
- Uses [noble-curves](https://github.com/paulmillr/noble-curves) under the hood

Includes SLIP-0010 (ed BIP32) HDKey implementation, funded by the Kin Foundation for
[Kinetic](https://github.com/kin-labs/kinetic). For the apps made with the library, check out:
[terminal7 WebRTC terminal multiplexer](https://github.com/tuzig/terminal7)

## Usage

> npm install ed25519-keygen

The package exports six modules:

- [`ed25519-keygen/ssh`](#sshseed-username) for SSH key generation
- [`ed25519-keygen/pgp`](#pgpseed-user-password) for
  [RFC 4880](https://datatracker.ietf.org/doc/html/rfc4880) +
  [RFC 6637](https://datatracker.ietf.org/doc/html/rfc6637)
- [`ed25519-keygen/tor`](#torseed) for TOR onion addresses
- [`ed25519-keygen/ipns`](#ipnsseed) for IPNS addresses
- [`ed25519-keygen/hdkey`](#hdkey) for
  [SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md)/[BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
  HDKey
- [`ed25519-keygen/utils`](#randombyteslength) for cryptographically secure random number generator
  (CSPRNG)

Use it in the following way:

```ts
import ssh from 'ed25519-keygen/ssh';
import pgp from 'ed25519-keygen/pgp';
import tor from 'ed25519-keygen/tor';
import { randomBytes } from 'ed25519-keygen/utils';
```

## `ssh(seed, username)`

- `seed: Uint8Array`
- `username: string`
- Returns
  `{ fingerprint: string, privateKey: string, publicKey: string, publicKeyBytes: Uint8Array }`

```js
import ssh from 'ed25519-keygen/ssh';
import { randomBytes } from 'ed25519-keygen/utils';
const sseed = randomBytes(32);
const skeys = await ssh(sseed, 'user@example.com');
console.log(skeys.fingerprint);
console.log(skeys.privateKey);
console.log(skeys.publicKey);
/*
SHA256:3M832z6j5R6mQh4TTzVG5KVs2IbvythcS6VPiEixMJg
-----BEGIN OPENSSH PRIVATE KEY-----

b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACB7IzMcWzDbGACJFPmt8hDZGedH6W1w0SGuY1Ut+oIlxQAAAJh8wUpUfMFK
VAAAAAtzc2gtZWQyNTUxOQAAACB7IzMcWzDbGACJFPmt8hDZGedH6W1w0SGuY1Ut+oIlxQ
AAAEBPTJHsreF9Losr930Yt/8DseFi66G7vK8QF/Kd8fcRlXsjMxxbMNsYAIkU+a3yENkZ
50fpbXDRIa5jVS36giXFAAAAEHVzZXJAZXhhbXBsZS5jb20BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsjMxxbMNsYAIkU+a3yENkZ50fpbXDRIa5jVS36giXF user@example.com
*/
```

## `pgp(seed, user, password)`

- `seed: Uint8Array`
- `user: string`
- `password: string`
- `createdAt: number` - (default: 0) timestamp corresponding to key creation time
- Returns `{ keyId: string, privateKey: string, publicKey: string, publicKeyBytes: Uint8Array }`

Creates keys compatible with GPG. GPG is a commonly known utility that supports PGP protocol.
Quirks:

1. Generated private and public keys would have different representation, however, **their
   fingerprints would be the same**. This is because AES encryption is used to hide the keys, and
   AES requires different IV / salt.
2. The function is slow (~725ms on Apple M1), because it uses S2K to derive keys.
3. "warning: lower 3 bits of the secret key are not cleared" happens even for keys generated with
   GnuPG 2.3.6, because check looks at item as Opaque MPI, when it is just MPI: see
   [bugtracker URL](https://dev.gnupg.org/rGdbfb7f809b89cfe05bdacafdb91a2d485b9fe2e0).

```js
import * as pgp from 'ed25519-keygen/pgp';
import { randomBytes } from 'ed25519-keygen/utils';
const pseed = randomBytes(32);
const pkeys = await pgp.getKeys(pseed, 'user@example.com', 'password');
console.log(pkeys.keyId);
console.log(pkeys.privateKey);
console.log(pkeys.publicKey);
/*
ca88e2a8afd9cdb8
-----BEGIN PGP PRIVATE KEY BLOCK-----

lIYEAAAAABYJKwYBBAHaRw8BAQdA0TSxOgyxDIuJh0afj457vpf7IZJsnyVu+HG2
k/v1F0P+BwMCpkzMdFodxiHwgVurmhm72ikz5FqdF8WJEBy0VC8ovbXkNz9oCi31
grwUafRgb874q0n99Q6Kh1cDMwMNF6vjQvgusaJQtvy75Y0pkNEnKrQQdXNlckBl
eGFtcGxlLmNvbYiUBBMWCgA8FiEELCHHdWxwPnwIbwzfyojiqK/ZzbgFAgAAAAAC
GwMFCwkIBwIDIgIBBhUKCQgLAgQWAgMBAh4HAheAAAoJEMqI4qiv2c24nyABALvn
+XR0T4AeohBNL+h88o2tgPazB1GtKo1FhMb8cpaDAQCRr8Ml3Ow5ijijFBQ0aqG4
1D43SIinNvQFD59o85YfBZyLBAAAAAASCisGAQQBl1UBBQEBB0C8acmhByJtlAZo
7T2lVQa0iCo0RBm/CgMJKO+3/NaHGgMBCAf+BwMCJsLfz4M3/KrwyBBBRu8MTvjq
pY5FjFcJGoPRhYHX+/ZATZf4cRrA0LX3zDi1nudO1f755Q4ALWjPXNXMMBkmKjHJ
p5WaAFm7xMdxEvXYaIh4BBgWCgAgFiEELCHHdWxwPnwIbwzfyojiqK/ZzbgFAgAA
AAACGwwACgkQyojiqK/ZzbikkgEAod4RMOLsVngAH/WFBWQi+Ee5hZ4nXsfasDsT
hNEnaqcBAI5h/ss8SU/gOmx/uiGJTCpp8VRAac+VbeU5XU//aLwA
=oOli
-----END PGP PRIVATE KEY BLOCK-----

-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEAAAAABYJKwYBBAHaRw8BAQdA0TSxOgyxDIuJh0afj457vpf7IZJsnyVu+HG2
k/v1F0O0EHVzZXJAZXhhbXBsZS5jb22IlAQTFgoAPBYhBCwhx3VscD58CG8M38qI
4qiv2c24BQIAAAAAAhsDBQsJCAcCAyICAQYVCgkICwIEFgIDAQIeBwIXgAAKCRDK
iOKor9nNuJ8gAQC75/l0dE+AHqIQTS/ofPKNrYD2swdRrSqNRYTG/HKWgwEAka/D
JdzsOYo4oxQUNGqhuNQ+N0iIpzb0BQ+faPOWHwW4OAQAAAAAEgorBgEEAZdVAQUB
AQdAvGnJoQcibZQGaO09pVUGtIgqNEQZvwoDCSjvt/zWhxoDAQgHiHgEGBYKACAW
IQQsIcd1bHA+fAhvDN/KiOKor9nNuAUCAAAAAAIbDAAKCRDKiOKor9nNuKSSAQCh
3hEw4uxWeAAf9YUFZCL4R7mFnidex9qwOxOE0SdqpwEAjmH+yzxJT+A6bH+6IYlM
KmnxVEBpz5Vt5TldT/9ovAA=
=4hZe
-----END PGP PUBLIC KEY BLOCK-----
*/

// Also, you can explore existing keys internal structure
console.log(await pgp.pubArmor.decode(keys.publicKey));
const privDecoded = await pgp.privArmor.decode(keys.privateKey);
console.log(privDecoded);
// And receive raw private keys as bigint
console.log({
  ed25519: await pgp.decodeSecretKey('password', privDecoded[0].data),
  cv25519: await pgp.decodeSecretKey('password', privDecoded[3].data),
});
```

## `tor(seed)`

Generates TOR addresses.

- `seed: Uint8Array`
- Returns `{ privateKey: string, publicKey: string, publicKeyBytes: Uint8Array }`

```js
import tor from 'ed25519-keygen/tor';
import { randomBytes } from 'ed25519-keygen/utils';
const tseed = randomBytes(32);
const tkeys = await tor(tseed);
console.log(tkeys.privateKey);
console.log(tkeys.publicKey);
/*
ED25519-V3:EOl78M2gARYOyp4BDltfzxSR3dA/LLTXZLb2imgOwFuYC5ISIUxsQ42ywzHaxvc03mahmaLziuyN0+f8EhM+4w==
rx724x3oambzxr46pkbdckdqyut5x5lhsneru3uditf4nuyuf4uou6qd.onion
*/
```

## `ipns(seed)`

Generates IPNS addresses.

- `seed: Uint8Array`
- Returns
  `{ privateKey: string, publicKey: string, base36: string, base32: string, base16: string, contenthash: string}`

```js
import ipns from 'ed25519-keygen/ipns';
import { randomBytes } from 'ed25519-keygen/utils';
const iseed = randomBytes(32);
const ikeys = await ipns(iseed);
console.log(ikeys.privateKey);
console.log(ikeys.publicKey);
console.log(ikeys.base16);
console.log(ikeys.base32);
console.log(ikeys.base36);
console.log(ikeys.contenthash);
/*
0x080112400681d6420abb1ba47acd5c03c8e5ee84185a2673576b262e234e50c46d86f59712c8299ec2c51dffbbcb4f9fccadcee1424cb237e9b30d3cd72d47c18103689d
0x017200240801122012c8299ec2c51dffbbcb4f9fccadcee1424cb237e9b30d3cd72d47c18103689d
ipns://f017200240801122012c8299ec2c51dffbbcb4f9fccadcee1424cb237e9b30d3cd72d47c18103689d
ipns://bafzaajaiaejcaewifgpmfri57654wt47zsw45ykcjszdp2ntbu6nolkhygaqg2e5
ipns://k51qzi5uqu5dgnfwbc46une4upw1vc9hxznymyeykmg6rev1513yrnbyrwmmql
0xe501017200240801122012c8299ec2c51dffbbcb4f9fccadcee1424cb237e9b30d3cd72d47c18103689d
*/
```

## hdkey

SLIP-0010 hierarchical deterministic (HD) wallets for implementation. Based on code from
[scure-bip32](https://github.com/paulmillr/scure-bip32). Check out
[scure-bip39](https://github.com/paulmillr/scure-bip39) if you also need mnemonic phrases.

- SLIP-0010 publicKey is 33 bytes (see
  [this issue](https://github.com/satoshilabs/slips/issues/1251)), if you want 32-byte publicKey,
  use `.publicKeyRaw` getter
- SLIP-0010 vectors fingerprint is actually `parentFingerprint`
- SLIP-0010 doesn't allow deriving non-hardened keys for Ed25519, however some other libraries treat
  non-hardened keys (`m/0/1`) as hardened (`m/0'/1'`). If you want this behaviour, there is a flag
  `forceHardened` in `derive` method

```ts
import { HDKey } from 'ed25519-keygen/hdkey';
const hdkey1 = HDKey.fromMasterSeed(seed);

// props
[hdkey1.depth, hdkey1.index, hdkey1.chainCode];
console.log(hdkey2.privateKey, hdkey2.publicKey);
console.log(hdkey3.derive("m/0/2147483647'/1'"));
const sig = hdkey3.sign(hash);
hdkey3.verify(hash, sig);
```

Note: `chainCode` property is essentially a private part of a secret "master" key, it should be
guarded from unauthorized access.

The full API is:

```ts
class HDKey {
  public static HARDENED_OFFSET: number;
  public static fromMasterSeed(seed: Uint8Array | string): HDKey;

  readonly depth: number = 0;
  readonly index: number = 0;
  readonly chainCode: Uint8Array | null = null;
  readonly parentFingerprint: number = 0;
  public readonly privateKey: Uint8Array;

  get fingerprint(): number;
  get fingerprintHex(): string;
  get parentFingerprintHex(): string;
  get pubKeyHash(): Uint8Array;
  get publicKey(): Uint8Array;
  get publicKeyRaw(): Uint8Array;

  derive(path: string, forceHardened = false): HDKey;
  deriveChild(index: number): HDKey;
  sign(hash: Uint8Array): Uint8Array;
  verify(hash: Uint8Array, signature: Uint8Array): boolean;
}
```

## utils

```ts
import { randomBytes } from 'ed25519-keygen/utils';
const key = randomBytes(32);
```

CSPRNG for secure generation of random Uint8Array. Utilizes webcrypto under the hood.

## License

MIT (c) Paul Miller [(https://paulmillr.com)](https://paulmillr.com), see LICENSE file.

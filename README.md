# ed25519-keygen

Generate ed25519 keys deterministically for SSH, PGP (GPG) and TOR.

Does not use CLI utils, everything is done programmatically in pure JS.

## Usage

> npm install ed25519-keygen

The package exports four modules:

- [`ed25519-keys/ssh`](#sshseed-username) for SSH key generation
- [`ed25519-keys/pgp`](#pgpseed-user-password) for [RFC 4880](https://datatracker.ietf.org/doc/html/rfc4880) + [RFC 6637](https://datatracker.ietf.org/doc/html/rfc6637)
- [`ed25519-keys/tor`](#torseed) for TOR onion addresses
- [`ed25519-keys/utils`](#randombyteslength) for cryptographically secure random number generator (CSPRNG)

Use it in the following way:

```ts
import ssh from 'ed25519-keys/ssh';
import pgp from 'ed25519-keys/pgp';
import tor from 'ed25519-keys/tor';
import { randomBytes } from 'ed25519-keys/utils';
```

## `ssh(seed, username)`

- `seed: Uint8Array`
- `username: string`
- Returns `{ fingerprint: string, privateKey: string, publicKey: string, publicKeyBytes: Uint8Array }`

```js
import ssh from 'ed25519-keys/ssh';
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

Creates keys compatible with GPG. GPG is a commonly known utility that supports PGP protocol. Quirks:

1. Generated private and public keys would have different representation,
however, **their fingerprints would be the same**. This is because AES encryption is used to
hide the keys, and AES requires different IV / salt.
2. The function is slow (~725ms on Apple M1), because it uses S2K to derive keys.
3. "warning: lower 3 bits of the secret key are not cleared"
  happens even for keys generated with GnuPG 2.3.6, because check looks at item as Opaque MPI, when it is just MPI: see [bugtracker URL](https://dev.gnupg.org/rGdbfb7f809b89cfe05bdacafdb91a2d485b9fe2e0).

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

### `randomBytes(length)`

- `byteLength: number` default is `32`
- Returns `Uint8Array` filled with cryptographically secure random bytes

## License

MIT (c) Paul Miller [(https://paulmillr.com)](https://paulmillr.com), see LICENSE file.


# micro-key-producer

Produces secure keys and passwords.

- 🔓 Secure: audited [noble](https://paulmillr.com/noble/) cryptography
- 🔻 Tree-shakeable: unused code is excluded from your builds
- 🎲 Produce known (deterministic) and random keys
- 🔑 SSH, PGP, TOR, IPNS, SLIP10 keys
- 🪙 BLS12-381 keys for ETH validators
- 📟 Generate secure passwords & OTP 2FA codes

Used in: [terminal7 WebRTC terminal multiplexer](https://github.com/tuzig/terminal7).

## Usage

> `npm install micro-key-producer`

> `jsr add jsr:@paulmillr/micro-key-producer`

```ts
import ssh from 'micro-key-producer/ssh.js';
import pgp from 'micro-key-producer/pgp.js';
import * as pwd from 'micro-key-producer/password.js';
import * as otp from 'micro-key-producer/otp.js';
import tor from 'micro-key-producer/tor.js';
import ipns from 'micro-key-producer/ipns.js';
import slip10 from 'micro-key-producer/slip10.js';
import { randomBytes } from 'micro-key-producer/utils.js';
```

- [Key generation: known and random seeds](#key-generation-known-and-random-seeds)
  - [SSH keys](#generate-ssh-keys)
  - [PGP keys](#generate-pgp-keys)
  - [Secure passwords](#generate-secure-passwords)
  - [2FA OTP codes](#generate-2fa-otp-codes)
  - [BLS keys for ETH validators](#generate-bls-keys-for-eth-validators)
  - [TOR keys and addresses](#generate-tor-keys-and-addresses)
  - [IPNS addresses](#generate-ipns-addresses)
  - [SLIP10 ed25519 hdkeys](#generate-slip10-ed25519-hdkeys)
- [Low-level API](#low-level-api)
  - [PGP key generation](#pgp-key-generation)
  - [Password generation](#password-generation)
    - [Bruteforce estimation and ZXCVBN score](#bruteforce-estimation-and-zxcvbn-score)
    - [Mask control characters](#mask-control-characters)
    - [Design rationale](#design-rationale)
    - [What do we want from passwords?](#what-do-we-want-from-passwords)
  - [SLIP10 API](#slip10-api)

### Key generation: known and random seeds

Every method takes a seed (key), from which the formatted result is produced.

A seed can be **known** (a.k.a. deterministic - it will always produce the same result), or **random**.

```js
// known: (deterministic) Uses known mnemonic (handled in separate package)
import { mnemonicToSeedSync } from '@scure/bip39';
const mnemonic = 'letter advice cage absurd amount doctor acoustic avoid letter advice cage above';
const knownSeed = mnemonicToSeedSync(mnemonic, '');

// random: Uses system's CSPRNG to produce new random seed
import { randomBytes } from 'micro-key-producer/utils.js';
const randSeed = randomBytes(32);
```

### Generate SSH keys

```js
import ssh from 'micro-key-producer/ssh.js';
import { randomBytes } from 'micro-key-producer/utils.js';

const seed = randomBytes(32);
const key = ssh(seed, 'user@example.com');
console.log(key.fingerprint, key.privateKey, key.publicKey);
// SHA256:3M832z6j5R6mQh4TTzVG5KVs2Ibvy...
// -----BEGIN OPENSSH PRIVATE KEY----- ...
// ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...
```

The PGP (GPG) keys conform to
[RFC 4880](https://datatracker.ietf.org/doc/html/rfc4880) &
[RFC 6637](https://datatracker.ietf.org/doc/html/rfc6637). Only ed25519 algorithm is currently supported.

### Generate PGP keys

```js
import pgp, { getKeyId } from 'micro-key-producer/pgp.js';
import { randomBytes } from 'micro-key-producer/utils.js';

const seed = randomBytes(32);
const email = 'user@example.com';
const pass = 'password';
const createdAt = Date.now(); // optional; timestamp >= 0

const keyId = getKeyId(seed);
const key = pgp(seed, email, pass, createdAt);
console.log(key.fingerprint, key.privateKey, key.publicKey);
// ca88e2a8afd9cdb8
// -----BEGIN PGP PRIVATE KEY BLOCK-----...
// -----BEGIN PGP PUBLIC KEY BLOCK-----...
```

### Generate BLS keys for ETH validators

```js
import { mnemonicToSeedSync } from '@scure/bip39';
import { createDerivedEIP2334Keystores } from 'micro-key-producer/bls.js';

const password = 'my_password';
const mnemonic = 'letter advice cage absurd amount doctor acoustic avoid letter advice cage above';
const keyType = 'signing'; // or 'withdrawal'
const indexes = [0, 1, 2, 3]; // create 4 keys

const keystores = createDerivedEIP2334Keystores(
  password
  'scrypt',
  mnemonicToSeedSync(mnemonic, ''),
  keyType,
  indexes
);
```

Conforms to EIP-2333 / EIP-2334 / EIP-2335. Online demo: [eip2333-tool](https://iancoleman.io/eip2333/)

### Generate secure passwords

```js
import * as pwd from 'micro-key-producer/password.js';
import { randomBytes } from '@noble/hashes/utils';

const seed = randomBytes(32);
const pass = pwd.secureMask.apply(seed).password;
// wivfi1-Zykrap-fohcij, will change on each run
// secureMask is format from iOS keychain, see "Detailed API" section
```

Supports iOS / macOS Safari Secure Password from Keychain. Optional zxcvbn score for password bruteforce estimation

### Generate 2FA OTP codes

```js
import * as otp from 'micro-key-producer/otp.js';
otp.hotp(otp.parse('ZYTYYE5FOAGW5ML7LRWUL4WTZLNJAMZS'), 0n); // 549419
otp.totp(otp.parse('ZYTYYE5FOAGW5ML7LRWUL4WTZLNJAMZS'), 0); // 549419
```

Conforms to [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238).

### Generate TOR keys and addresses

```js
import tor from 'micro-key-producer/tor.js';
import { randomBytes } from 'micro-key-producer/utils.js';
const seed = randomBytes(32);
const key = tor(seed);
console.log(key.privateKey, key.publicKey);
// ED25519-V3:EOl78M2gA...
// rx724x3oambzxr46pkbd... .onion
```

### Generate IPNS addresses

```js
import ipns from 'micro-key-producer/ipns.js';
import { randomBytes } from 'micro-key-producer/utils.js';
const seed = randomBytes(32);
const k = ipns(seed);
console.log(k.privateKey, k.publicKey, k.base16, k.base32, k.base36, k.contenthash);
// 0x080112400681d6420abb1b...
// 0x017200240801122012c829...
// ipns://f0172002408011220...
// ipns://bafzaajaiaejcaewi...
// ipns://k51qzi5uqu5dgnfwb...
// 0xe501017200240801122012...
```

### Generate SLIP10 ed25519 hdkeys

```js
import slip10 from 'micro-key-producer/slip10.js';
import { randomBytes } from 'micro-key-producer/utils.js';

const seed = randomBytes(32);
const hdkey1 = slip10.fromMasterSeed(seed);

// props
[hdkey1.depth, hdkey1.index, hdkey1.chainCode];
console.log(hdkey2.privateKey, hdkey2.publicKey);
console.log(hdkey3.derive("m/0/2147483647'/1'"));
const sig = hdkey3.sign(hash);
hdkey3.verify(hash, sig);
```

SLIP10 (ed25519 BIP32) HDKey implementation has been funded by the Kin Foundation for
[Kinetic](https://github.com/kin-labs/kinetic).

## Low-level details

### PGP key generation

1. Generated private and public keys would have different representation, however, **their
   fingerprints would be the same**. This is because AES encryption is used to hide the keys, and
   AES requires different IV / salt.
2. The function is slow (~725ms on Apple M1), because it uses S2K to derive keys.
3. "warning: lower 3 bits of the secret key are not cleared" happens even for keys generated with
   GnuPG 2.3.6, because check looks at item as Opaque MPI, when it is just MPI: see
   [bugtracker URL](https://dev.gnupg.org/rGdbfb7f809b89cfe05bdacafdb91a2d485b9fe2e0).

```js
import * as pgp from 'micro-key-producer/pgp';
import { randomBytes } from 'micro-key-producer/utils';
const pseed = randomBytes(32);
pgp.getKeyId(pseed); // fast
const pkeys = pgp.getKeys(pseed, 'user@example.com', 'password');
console.log(pkeys.keyId);
console.log(pkeys.privateKey);
console.log(pkeys.publicKey);

// Also, you can explore existing keys internal structure
console.log(pgp.pubArmor.decode(keys.publicKey));
const privDecoded = pgp.privArmor.decode(keys.privateKey);
console.log(privDecoded);
// And receive raw private keys as bigint
console.log({
  ed25519: pgp.decodeSecretKey('password', privDecoded[0].data),
  cv25519: pgp.decodeSecretKey('password', privDecoded[3].data),
});
```

### Password generation

#### Bruteforce estimation and ZXCVBN score

```js
import * as pwd from 'micro-key-producer/password.js';
console.log(pwd.secureMask.estimate);

// Output
{
  score: 'somewhat guessable', // ZXCVBN Score
  // Guess times
  guesses: {
    online_throttling: '1y 115mo', // Throttled online attack
    online: '1mo 10d', // Online attack
    // Offline attack (salte, slow hash function like bcrypt, scrypt, PBKDF2, argon, etc)
    slow: '57min 36sec',
    fast: '0 sec' // Offline attack
  },
  // Estimated attack costs (in $)
  costs: {
    luks: 1.536122841572242, // LUKS (Linux FDE)
    filevault2: 0.2308740987992559, // FileVault 2 (macOS FDE)
    macos: 0.03341598798410283, // MaccOS v10.8+ passwords
    pbkdf2: 0.011138662661367609 // PBKDF2 (PBKDF2-HMAC-SHA256)
  }
}
```

#### Mask control characters

| Mask | Description                        | Example       |
| ---- | ---------------------------------- | ------------- |
| 1    | digits                             | 4, 7, 5, 0    |
| @    | symbols                            | !, @, %, ^    |
| v    | vowels                             | a, e, i       |
| c    | consonant                          | b, c, d       |
| a    | letter (vowel or consonant)        | a, b, e, c    |
| V    | uppercase vowel                    | A, E, I       |
| C    | uppercase consonant                | B, C, D       |
| A    | uppercase letter                   | A, B, E, C    |
| l    | lower and upper case letters       | A, b, C       |
| n    | same as 'l', but also digits       | A, 1, b, 2, C |
| \*   | same as 'n', but also symbols      | A, 1, !, b, @ |
| s    | syllable (same as 'cv')            | ca, re, do    |
| S    | Capitalized syllable (same as 'Cv) | Ca, Ti, Je    |
|      | All other characters used as is    |               |

Examples:

- Mask: `Cvccvc-cvccvc-cvccv1` will generate `Mavmuq-xadgys-poqsa5`
- Mask `@Ss-ss-ss` will generate: `*Tavy-qyjy-vemo`

#### Design rationale

Most strict password rules (so password will be accepted everywhere):

- at least one upper-case character
- at least one lower-case character
- at least one symbol
- at least one digit
- length greater or equal to 8
  These rules don't significantly increase password entropy (most humans will use mask like 'Aaaaaa1@' or any other popular mask),
  but they means that we cannot simple use mask like `********`, since it can generate passwords which won't satisfy these rules.

#### What do we want from passwords?

- **_length_**: entering 32 character password for FDE via IPMI java applet on remote server is pretty painful.
  -> 12-16 probably ok, anything with more characters has chance to be truncated by service.
- **_readability_**: entering '!#%!$#Y^&\*#%@#!!1' from air-gapped pc is hard.
- **_entropy_**:
  - 32 bit is likely to be brutforced via network
  - 64 bit: 22 days && 1.6k$ at 4x V100: https://blog.trailofbits.com/2019/11/27/64-bits-ought-to-be-enough-for-anybody/
    but it is simple loop, if there is something like pbkdf before password, it will significantly slowdown everything
  - 80 bits is probably outside of budget for most attackers (btc hash rate) even if there is major speedup for specific algorithm
  - For websites and services we don't care much about entropy, since passwords are unique and there is no re-usage,
    however for FDE / server password entropy is pretty important
- no fancy and unique mask by default: we don't want to fingeprint users
- any mask will leak eventually (even if user choices personal mask, there will be password leaks from websites),
  so we cannot calculate entropy by `******` mask, we need to calculate entropy for specific mask (which is smaller).
- Password generator should be reversible, that way we can easily proof entropy/strength of password.

### SLIP10 API

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

Note: `chainCode` property is essentially a private part of a secret "master" key, it should be
guarded from unauthorized access.

The full API is:

```js
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

## License

MIT (c) Paul Miller [(https://paulmillr.com)](https://paulmillr.com), see LICENSE file.

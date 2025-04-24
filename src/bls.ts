import { ctr } from '@noble/ciphers/aes';
import { ensureBytes, numberToBytesBE } from '@noble/curves/abstract/utils';
import { bls12_381 } from '@noble/curves/bls12-381';
import { hkdf } from '@noble/hashes/hkdf';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { scrypt } from '@noble/hashes/scrypt';
import { sha256 } from '@noble/hashes/sha2';
import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  isBytes,
  randomBytes,
  utf8ToBytes,
} from '@noble/hashes/utils';

/*
Implements:

- EIP-2333: BLS12-381 Key Generation
- EIP-2334: BLS12-381 Deterministic Account Hierarchy
- EIP-2335: BLS12-381 Keystore

The standards are not used anywhere outside of eth validator keys as per 2024.
*/

const { getPublicKey } = bls12_381;
const { Fr } = bls12_381.fields;

// Octet Stream to Integer
function os2ip(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i]!;
    result <<= 8n;
    result += BigInt(byte);
  }
  return result;
}

// Integer to Octet Stream
function i2osp(value: number, length: number): Uint8Array {
  if (value < 0 || value >= 1n << BigInt(8 * length)) {
    throw new Error(`bad I2OSP call: value=${value} length=${length}`);
  }
  const res = Array.from({ length }).fill(0) as number[];
  for (let i = length - 1; i >= 0; i--) {
    res[i] = value & 0xff;
    value >>>= 8;
  }
  return new Uint8Array(res);
}

function ikmToLamportSK(ikm: Uint8Array, salt: Uint8Array) {
  const okm = hkdf(sha256, ikm, salt, undefined, 32 * 255);
  return Array.from({ length: 255 }, (_, i) => okm.slice(i * 32, (i + 1) * 32));
}

function assertUint32(index: number) {
  if (!Number.isSafeInteger(index) || index < 0 || index > 2 ** 32 - 1) {
    throw new TypeError('Expected valid uint32 number');
  }
}

function parentSKToLamportPK(parentSK: Uint8Array, index: number) {
  parentSK = ensureBytes('parentSK', parentSK);
  assertUint32(index);
  const salt = i2osp(index, 4);
  const ikm = parentSK;
  const lamport0 = ikmToLamportSK(ikm, salt);
  const notIkm = ikm.map((byte) => ~byte);
  const lamport1 = ikmToLamportSK(notIkm, salt);
  const lamportPK = lamport0.concat(lamport1).map((part) => sha256(part));
  return sha256(concatBytes(...lamportPK));
}

/**
 * Low-level primitive from EIP2333, generates key from bytes.
 * KeyGen from https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-keygen
 * @param ikm - secret octet string
 * @param keyInfo - additional key information
 */
export function hkdfModR(ikm: Uint8Array, keyInfo: Uint8Array = new Uint8Array()): Uint8Array {
  ikm = ensureBytes('IKM', ikm);
  keyInfo = ensureBytes('key information', keyInfo);
  let salt = utf8ToBytes('BLS-SIG-KEYGEN-SALT-');
  let SK = 0n;
  const input = concatBytes(ikm, Uint8Array.from([0x00]));
  const label = concatBytes(keyInfo, Uint8Array.from([0x00, 0x30]));
  while (SK === 0n) {
    salt = sha256(salt);
    const okm = hkdf(sha256, input, salt, label, 48);
    SK = Fr.create(os2ip(okm));
  }
  return numberToBytesBE(SK, 32);
}

export function deriveMaster(seed: Uint8Array): Uint8Array {
  return hkdfModR(seed);
}

export function deriveChild(parentKey: Uint8Array, index: number): Uint8Array {
  return hkdfModR(parentSKToLamportPK(parentKey, index));
}

export function deriveSeedTree(seed: Uint8Array, path: string): Uint8Array {
  if (typeof path !== 'string') throw new Error('Derivation path must be string');
  const indices = path.split('/');
  if (indices.shift() !== 'm') throw new Error('First character of path must be "m"');
  let sk = deriveMaster(seed);
  const nodes = indices.map((i) => Number.parseInt(i));
  for (const node of nodes) sk = deriveChild(sk, node);
  return sk;
}

export const EIP2334_KEY_TYPES = ['withdrawal', 'signing'] as const;
export type EIP2334KeyType = (typeof EIP2334_KEY_TYPES)[number];
export function deriveEIP2334Key(
  seed: Uint8Array,
  type: EIP2334KeyType,
  index: number
): {
  key: Uint8Array;
  path: string;
} {
  if (!isBytes(seed)) throw new Error('Valid seed expected');
  if (!EIP2334_KEY_TYPES.includes(type)) throw new Error('Valid keystore type expected');
  assertUint32(index);
  // m / purpose / coin_type /  account / use
  // - purpose: always 12381
  // - coin_type: always 3600 (eth2 bls12-381 keys)
  // EIP-2334 specifies following derivation paths:
  // m/12381/3600/0/0   for withdrawal
  // m/12381/3600/0/0/0 for signing (sub account for withdrawal)
  const path = `m/12381/3600/${index}/0${type === 'signing' ? '/0' : ''}`;
  return { key: deriveSeedTree(seed, path), path };
}

/**
 * Derives signing key from withdrawal key without access to seed
 * @param withdrawalKey - result of deriveEIP2334Key(seed, 'withdrawal', index)
 * @returns same as deriveEIP2334Key(seed, 'signing', index), but without access to seed
 * @example
 * const signing = bls.deriveEIP2334Key(seed, 'signing', 0);
 * const withdrawal = bls.deriveEIP2334Key(seed, 'withdrawal', 0);
 * const derivedSigning = bls.deriveEIP2334SigningKey(withdrawal.key);
 * deepStrictEqual(derivedSigning, signing.key);
 */
export function deriveEIP2334SigningKey(withdrawalKey: Uint8Array, index = 0): Uint8Array {
  withdrawalKey = ensureBytes('withdrawal key', withdrawalKey, 32);
  assertUint32(index);
  return deriveChild(withdrawalKey, index);
}

function normalizePassword(s: string): string {
  let out = '';
  for (const chr of s.normalize('NFKD')) {
    const code = chr.charCodeAt(0);
    // C0 are the control codes between 0x00 - 0x1F(inclusive) and C1 codes
    // lie between 0x80 and 0x9F(inclusive). Delete, commonly known as “backspace”,
    // is the UTF - 8 character 7F which must also be stripped.
    // Note that space(Sp UTF - 8 0x20) is a valid character in passwords despite it
    // being a pseudo - control character.
    if ((0x00 <= code && code <= 0x1f) || (0x7f <= code && code <= 0x9f)) continue;
    out += chr;
  }
  return out;
}

function UUIDv4(buf: Uint8Array): string {
  buf = Uint8Array.from(buf);
  // UUID version
  buf[6] = (buf[6] & 0x0f) | 0x40;
  // RFC 4122
  buf[8] = (buf[8] & 0x3f) | 0x80;
  const parts = [
    buf.subarray(0, 4),
    buf.subarray(4, 6),
    buf.subarray(6, 8),
    buf.subarray(8, 10),
    buf.subarray(10),
  ];
  return parts.map(bytesToHex).join('-');
}

// Note: dklen, not dkLen, because lowercase is used inside of serialized json keystores
const KDFS = {
  scrypt: { dklen: 32, n: 262144, r: 8, p: 1 },
  pbkdf2: { dklen: 32, c: 262144, prf: 'hmac-sha256' },
};

type KDFParams<T extends KDFType> = (typeof KDFS)[T];
type KDFType = keyof typeof KDFS;

export type Keystore<T extends KDFType> = {
  version: number; // Always 4 for BLS keys
  description?: string;
  pubkey?: string; // Pubkey is optional
  path: string; // Optional, but always exists (empty string if not present)
  uuid: string;
  crypto: {
    kdf: { function: T; params: KDFParams<T> & { salt: string }; message: '' };
    checksum: { function: 'sha256'; params: {}; message: string };
    cipher: { function: 'aes-128-ctr'; params: { iv: string }; message: string };
  };
};

// Non-strict version just validates same way as json schema from spec
// Maybe worth exporting?
function validateKeystore<T extends KDFType>(store: Keystore<T>, strict = true) {
  if (typeof store !== 'object' || store === null) throw new Error('keystore should be object');
  if (store.version !== 4)
    throw new Error('keystore: wrong version, only version=4 is supported for BLS keys for now');
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(store.uuid))
    throw new Error('keystore: wrong uuid');
  if (store.pubkey !== undefined && typeof store.pubkey !== 'string')
    throw new Error('keystore: wrong pubkey type, should be string');
  if (store.description !== undefined && typeof store.description !== 'string')
    throw new Error('keystore: wrong description type, should be string');
  const crypto = store.crypto;
  if (typeof crypto !== 'object' || crypto === null)
    throw new Error('keystore.crypto should be object');
  for (const k in crypto) {
    if (strict && !['kdf', 'checksum', 'cipher'].includes(k))
      throw new Error(`keystore: unknown crypto module: ${k}`);
    const mod = crypto[k as keyof Keystore<T>['crypto']];
    if (typeof mod !== 'object' || mod === null)
      throw new Error(`keystore.crypto.${k} should be object`);
    if (typeof mod.function !== 'string')
      throw new Error(`keystore.crypto.${k}.function should be string`);
    if (typeof mod.params !== 'object' || mod.params === null)
      throw new Error(`keystore.crypto.${k}.params should be object`);
    if (typeof mod.message !== 'string')
      throw new Error(`keystore.crypto.${k}.message should be string`);
  }
  if (strict) {
    if (!KDFS[crypto.kdf.function])
      throw new Error('keystore: only script and pbkdf2 kdf supported in version 4');
    if (crypto.checksum.function !== 'sha256')
      throw new Error('keystore: only sha256 checksum supported in version 4');
    if (crypto.cipher.function !== 'aes-128-ctr')
      throw new Error('keystore: only aes-128-ctr cipher supported in version 4');
    const kdf = crypto.kdf.params;
    if (typeof kdf.salt !== 'string') throw new Error(`keystore.crypto.kdf.salt should be string`);
    // Not sure if we need this validation, if encryption key was derived using insecure params,
    // we cannot do much here (it already happened!), I don't see reasons not to decrypt
    // const expKdf = KDFS[crypto.kdf.function];
    // for (const k in expKdf) {
    //   if (kdf[k] !== expKdf[k]) {
    //     throw new Error(`keystore.crypto.kdf.params.${k} should be ${expKdf[k]}`);
    //   }
    // }
    if (typeof crypto.cipher.params.iv !== 'string')
      throw new Error(`keystore.crypto.cipher.params.iv should be string`);
  }
}

function deriveEIP2335Key(password: string, salt: Uint8Array, kdf: KDFType): Uint8Array {
  const pass = utf8ToBytes(normalizePassword(password));
  if (kdf === 'scrypt') {
    const { n: N, r, p, dklen: dkLen } = KDFS[kdf];
    return scrypt(pass, salt, { N, r, p, dkLen });
  } else if (kdf === 'pbkdf2') {
    const { c, dklen: dkLen } = KDFS[kdf];
    return pbkdf2(sha256, pass, salt, { c, dkLen });
  } else {
    throw new Error(`Unsupported KDF: ${kdf}`);
  }
}
/**
 * Decrypts EIP2335 Keystore
 * NOTE: it validates publicKey if present (which mean you can use it from store if decryption is success)
 * @param store - js object
 * @param password - password
 * @returns decrypted secret and optionally path
 * @example decryptEIP2335Keystore(JSON.parse(keystoreString), 'my_password');
 */
export function decryptEIP2335Keystore<T extends KDFType>(
  store: Keystore<T>,
  password: string
): Uint8Array {
  validateKeystore(store);
  const c = store.crypto;
  const checksumProvided = c.checksum.message;
  const ciphertext = hexToBytes(c.cipher.message);
  const salt = hexToBytes(c.kdf.params.salt);
  const iv = hexToBytes(c.cipher.params.iv);
  const key = deriveEIP2335Key(password, salt, c.kdf.function);
  // verify checksum
  const checksum = bytesToHex(sha256(concatBytes(key.subarray(16, 32), ciphertext)));
  if (checksum !== checksumProvided)
    throw new Error(`Checksum ${checksum} does not match ${checksumProvided}`);
  // decrypt
  const secret = ctr(key.subarray(0, 16), iv).decrypt(ciphertext);
  // verify pubkey
  // NOTE: it is optional, and encrypted value is not neccesarily private key according to EIP2335
  if (store.pubkey !== undefined) {
    const publicKey = bytesToHex(getPublicKey(secret));
    if (publicKey !== store.pubkey)
      throw new Error(`Pubkey ${publicKey} does not match ${store.pubkey}`);
  }
  key.fill(0);
  iv.fill(0);
  ciphertext.fill(0);
  return secret;
}

/**
 * Secure PRNG function like 'randomBytes' from '@noble/hashes/utils'
 */
export type RandFn = (bytes: number) => Uint8Array;

/**
 * Class for generation multiple keystores with same password
 * @example
 * const ctx = new EIP2335Keystore(password, 'scrypt');
 * const res = [0, 1, 2, 3].map((i) => ctx.createDerivedEIP2334(seed, keyType, i));
 * ctx.clean();
 * console.log(res); // res is array of encrypted keystores with same password
 */
export class EIP2335Keystore<T extends KDFType> {
  private destroyed = false;
  private readonly kdf: T;
  private readonly randomBytes: RandFn;
  private readonly key: Uint8Array;
  private readonly salt: Uint8Array;
  /**
   * Creates context for EIP2335 Keystore generation
   * @param password - password
   * @param kdf - scrypt | pbkdf2
   * @param _random - (optional) secure PRNG function like 'randomBytes' from '@noble/hashes/utils'
   */
  constructor(password: string, kdf: T, _random: RandFn = randomBytes) {
    this.kdf = kdf;
    // We need this for tests and also to allow usage in context where our randomBytes doesn't work (react-native?)
    this.randomBytes = _random;
    this.salt = this.randomBytes(32);
    this.key = deriveEIP2335Key(password, this.salt, kdf);
  }
  /**
   * Creates keystore in EIP2335 format.
   * @param secret - some secret value to encrypt (usually private keys)
   * @param path - optional derivation path if secret
   * @param description - optional description of secret
   * @param pubkey - optional public key. Required if secret is private key.
   */
  create(
    secret: Uint8Array,
    path: string = '', // EIP2335 allows storing not derived keys
    description: string = '',
    pubkey?: Uint8Array
  ): Keystore<T> {
    if (this.destroyed) throw new Error('EIP2335Keystore was destroyed.');
    const iv = this.randomBytes(16);
    const uuid = this.randomBytes(16);
    // seed, keyType, index checked inside deriveEIP2334Key;
    if (typeof description !== 'string') throw new Error('description should be string');
    const { key, kdf, salt } = this;
    const ciphertext = ctr(key.subarray(0, 16), iv).encrypt(secret);
    const checksum = bytesToHex(sha256(concatBytes(key.subarray(16), ciphertext)));
    const res: Keystore<T> = {
      version: 4,
      description,
      path,
      uuid: UUIDv4(uuid),
      crypto: {
        kdf: { function: kdf, params: { ...KDFS[kdf], salt: bytesToHex(salt) }, message: '' },
        checksum: { function: 'sha256', params: {}, message: checksum },
        cipher: {
          function: 'aes-128-ctr',
          params: { iv: bytesToHex(iv) },
          message: bytesToHex(ciphertext),
        },
      },
    };
    if (pubkey !== undefined) res.pubkey = bytesToHex(ensureBytes('public key', pubkey));
    return res;
  }
  /**
   * Creates keystore for derived private key (based on EIP2334 seed and index)
   * @param seed - EIP2334 seed to derive from
   * @param keyType - EIP2334 key type (withdrawal/signing)
   * @param index - account index
   * @param description - optional keystore description
   */
  createDerivedEIP2334(
    seed: Uint8Array,
    keyType: EIP2334KeyType,
    index: number,
    description: string = ''
  ): Keystore<T> {
    const { key: privKey, path } = deriveEIP2334Key(seed, keyType, index);
    const pubkey = bls12_381.getPublicKey(privKey);
    return this.create(privKey, path, description, pubkey);
  }

  /**
   * Clean internal key material
   */
  clean(): void {
    this.destroyed = true;
    this.key.fill(0);
    this.salt.fill(0);
  }
}

/**
 * Exports multiple keystore from derived seed
 * @param password - password for file encryption
 * @param kdf - scrypt | pbkdf2
 * @param seed - result of mnemonicToSeed()
 * @param keyType - signing | withdrawal
 * @param indexes - array of account indeces
 * @example
 * createDerivedEIP2334Keystores('my_password', 'scrypt', await mnemonicToSeed(mnemonic, ''), 'signing', [0, 1, 2, 3])
 */
export function createDerivedEIP2334Keystores<T extends KDFType>(
  password: string,
  kdf: T,
  seed: Uint8Array,
  keyType: EIP2334KeyType,
  indexes: number[]
): Keystore<T>[] {
  // NOTE: we can probably also cache key derivation for EIP2334 (since it is hierarchical and seed is same)
  for (const i of indexes) {
    // Assert 1M max keys and 32M stake
    if (!Number.isSafeInteger(i) || i < 0 || i > 2 ** 20 - 1) throw new Error('Invalid key index');
  }
  const ctx = new EIP2335Keystore(password, kdf);
  const res = indexes.map((i) => ctx.createDerivedEIP2334(seed, keyType, i));
  ctx.clean();
  return res;
}

// Internal methods for test purposes only
export const _TEST: {
  normalizePassword: typeof normalizePassword;
  deriveEIP2335Key: typeof deriveEIP2335Key;
} = /* @__PURE__ */ { normalizePassword, deriveEIP2335Key };

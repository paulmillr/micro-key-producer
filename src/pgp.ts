/*! micro-key-producer - MIT License (c) 2024 Paul Miller (paulmillr.com) */
import { cfb } from '@noble/ciphers/aes';
import { bytesToNumberBE, equalBytes, numberToHexUnpadded } from '@noble/curves/abstract/utils';
import { ed25519, x25519 } from '@noble/curves/ed25519';
import { ripemd160, sha1 } from '@noble/hashes/legacy';
import { sha256, sha512 } from '@noble/hashes/sha2';
import { sha3_256 } from '@noble/hashes/sha3';
import { type CHash, concatBytes, randomBytes } from '@noble/hashes/utils';
import { hex, utf8 } from '@scure/base';
import * as P from 'micro-packed';
import { base64armor } from './utils.js';

export type Bytes = Uint8Array;

// RFCS:
// - main: https://datatracker.ietf.org/doc/html/rfc4880
// - ecdh: https://datatracker.ietf.org/doc/html/rfc6637
// - ed25519: https://www.ietf.org/archive/id/draft-koch-eddsa-for-openpgp-04.txt
// - bis: https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis-10#section-5.2.3.1

function runAesCfb(keyLen: number, data: Bytes, key: Bytes, iv: Bytes, decrypt = false) {
  // NOTE: we need to validate key length here since file can be malformed
  if (keyLen !== key.length * 8) throw new Error('aes-cfb: wrong key length');
  if (iv.length !== 16) throw new Error('aes-cfb: wrong IV');
  // Packed does subarray and read is unaligned here
  // TODO: support unaligned reads in all AES?
  const keyCopy = key.slice();
  const ivCopy = iv.slice();
  const dataCopy = data.slice();
  const cipher = cfb(keyCopy, ivCopy);
  const res = decrypt ? cipher.decrypt(dataCopy) : cipher.encrypt(dataCopy);
  keyCopy.fill(0);
  ivCopy.fill(0);
  dataCopy.fill(0);
  return res;
}

function createAesCfb(len: number) {
  return {
    encrypt: (plaintext: Bytes, key: Bytes, iv: Bytes) => runAesCfb(len, plaintext, key, iv),
    decrypt: (ciphertext: Bytes, key: Bytes, iv: Bytes) =>
      runAesCfb(len, ciphertext, key, iv, true),
  };
}

// PGP Types
// Multiprecision Integers [RFC4880](https://datatracker.ietf.org/doc/html/rfc4880)
export const mpi: P.CoderType<bigint> = P.wrap({
  encodeStream: (w: P.Writer, value: bigint) => {
    let bitLen = 0;
    for (let v = value; v > 0n; v >>= 1n, bitLen++);
    P.U16BE.encodeStream(w, bitLen);
    w.bytes(hex.decode(numberToHexUnpadded(value)));
  },
  decodeStream: (r: P.Reader): bigint =>
    bytesToNumberBE(r.bytes((P.U16BE.decodeStream(r) + 7) >>> 3)),
});

// GnuGP violates spec by using non-zero stripped MPI's for secret keys (opaque MPI/SOS).
// We need to do the same to create equal keys.
// More info:
// - https://www.mhonarc.org/archive/html/ietf-openpgp/2019-10/msg00041.html
// - https://marc.info/?l=gnupg-devel&m=161518990118244&w=2
export const opaquempi: P.CoderType<Uint8Array> = P.wrap({
  encodeStream: (w: P.Writer, value: Bytes) => {
    P.U16BE.encodeStream(w, value.length * 8);
    w.bytes(value);
  },
  decodeStream: (r: P.Reader): Bytes => r.bytes((P.U16BE.decodeStream(r) + 7) >>> 3),
});

// ASN.1 OID (object identifier) without tag & length
// First two elements: [i0 * 40 + i1].
// Others: split in groups of 7 bit chunks, add 0x80 every byte except last(stop flag), like utf8.
const OID_MSB = 2 ** 7; // mask for 8 bit
const OID_NO_MSB = 2 ** 7 - 1; // mask for all bits except 8
export const oid: P.CoderType<string> = P.wrap({
  encodeStream: (w: P.Writer, value: string) => {
    const items = value.split('.').map((i) => +i);
    let oid = [items[0] * 40];
    if (items.length >= 2) oid[0] += items[1];
    for (let i = 2; i < items.length; i++) {
      const item = [];
      for (let n = items[i], mask = 0x00; n; n >>= 7, mask = OID_MSB)
        item.unshift((n & OID_NO_MSB) | mask);
      oid = oid.concat(item);
    }
    w.bytes(new Uint8Array(oid));
  },
  decodeStream: (r: P.Reader): string => {
    if (r.isEnd()) throw new Error('PGP: empty oid');
    const first = r.byte();
    let res = `${Math.floor(first / 40)}.${first % 40}`;
    for (let num = 0; !r.isEnd(); ) {
      const byte = r.byte();
      num = (num << 7) | (byte & OID_NO_MSB);
      if (byte & OID_MSB) continue;
      res += `.${num >>> 0}`;
      num = 0;
    }
    return res;
  },
});

export const PacketLen: P.CoderType<number> = P.wrap({
  encodeStream: (w: P.Writer, value: number) => {
    if (typeof value !== 'number') throw new Error(`PGP.PacketLen invalid length type, ${value}`);
    if (value < 192) w.byte(value);
    else if (value < 8383) {
      value -= 192;
      w.bytes(new Uint8Array([(value >> 8) + 192, value & 0xff]));
    } else if (value < 2 ** 32) {
      w.byte(0xff);
      P.U32BE.encodeStream(w, value);
    } else throw new Error(`PGP.PacketLen: length is too big: ${value}`);
  },
  decodeStream: (r: P.Reader): number => {
    let res;
    const first = r.byte();
    if (first < 192) res = first;
    else if (first < 224) res = ((first - 192) << 8) + r.byte() + 192;
    else if (first == 255) res = P.U32BE.decodeStream(r);
    else throw new Error('PGP.PacketLen: Partial body lengths unsupported');
    return res;
  },
});

// PGP Structures
const PGP_PACKET_VERSION = P.magic(P.hex(1), '04'); // only version 4 is supported

// Other (RSA/ElGamal/etc) is unsupported
const pubKeyEnum = P.map(P.U8, {
  ECDH: 18,
  ECDSA: 19,
  EdDSA: 22,
});

const ECEnum = P.map(P.prefix(P.U8, oid), {
  nistP256: '1.2.840.10045.3.1.7',
  nistP384: '1.3.132.0.34',
  nistP521: '1.3.132.0.35',
  brainpoolP256r1: '1.3.36.3.3.2.8.1.1.7',
  brainpoolP384r1: '1.3.36.3.3.2.8.1.1.11',
  brainpoolP512r1: '1.3.36.3.3.2.8.1.1.13',
  secp256k1: '1.3.132.0.10',
  curve25519: '1.3.6.1.4.1.3029.1.5.1',
  ed25519: '1.3.6.1.4.1.11591.15.1',
});

const HashEnum = P.map(P.U8, {
  md5: 1,
  sha1: 2,
  ripemd160: 3,
  sha224: 11,
  sha256: 8,
  sha384: 9,
  sha512: 10,
  sha3_256: 12,
  sha3_512: 14,
});

const Hash: Record<string, CHash> = { ripemd160, sha256, sha512, sha3_256, sha1 };

const EncryptionEnum = P.map(P.U8, {
  plaintext: 0,
  idea: 1,
  tripledes: 2,
  cast5: 3,
  blowfish: 4,
  aes128: 7,
  aes192: 8,
  aes256: 9,
  twofish: 10,
});

const EncryptionKeySize: Record<string, number> = {
  plaintext: 0,
  aes128: 16,
  aes192: 24,
  aes256: 32,
};

const CompressionEnum = P.map(P.U8, {
  uncompressed: 0,
  zip: 1,
  zlib: 2,
  bzip2: 3,
});
// bis4880
const AEADEnum = P.map(P.U8, {
  None: 0,
  EAX: 1,
  OCB: 2,
});

// https://datatracker.ietf.org/doc/html/rfc4880#section-3.7.1
const S2KEnum = P.map(P.U8, { simple: 0, salted: 1, iterated: 3 });
const S2K = P.tag(S2KEnum, {
  simple: P.struct({ hash: HashEnum }),
  salted: P.struct({ hash: HashEnum, salt: P.bytes(8) }),
  iterated: P.struct({ hash: HashEnum, salt: P.bytes(8), count: P.U8 }),
});

// https://datatracker.ietf.org/doc/html/rfc6637#section-9
const ECDSAPub = P.struct({ curve: ECEnum, pub: mpi });

const ECDHPub = P.struct({
  curve: ECEnum,
  pub: mpi,
  params: P.prefix(
    P.U8,
    P.struct({
      magic: P.magic(P.hex(1), '01'),
      hash: HashEnum,
      encryption: EncryptionEnum,
    })
  ),
});

export type PubKeyPacketAlgo = P.Values<{
  EdDSA: {
    TAG: 'EdDSA';
    data: P.StructInput<{
      curve: any;
      pub: any;
    }>;
  };
  ECDH: {
    TAG: 'ECDH';
    data: P.StructInput<{
      curve: any;
      pub: any;
      params: any;
    }>;
  };
}>;

export const PubKeyPacket: P.CoderType<
  P.StructInput<{
    version: undefined;
    created: number;
    algo: PubKeyPacketAlgo;
  }>
> = P.struct({
  version: PGP_PACKET_VERSION,
  created: P.U32BE,
  algo: P.tag(pubKeyEnum, {
    EdDSA: ECDSAPub,
    ECDH: ECDHPub,
  }),
});
type PubKeyType = P.UnwrapCoder<typeof PubKeyPacket>;
type PacketData = P.StructInput<{
  enc: any;
  S2K: any;
  iv: any;
  secret: any;
}>;

const PlainSecretKey = P.struct({
  secret: P.bytes(null),
});

const EncryptedSecretKey = P.struct({
  enc: EncryptionEnum,
  S2K,
  // IV as blocksize of algo. For AES it is 16 bytes, others is not supported
  iv: P.bytes(16),
  secret: P.bytes(null),
});

// NOTE: SecretKey is specific packet type as per spec. For user facing API we using 'privateKey'
const SecretKeyPacket: P.CoderType<
  P.StructInput<{
    pub: P.StructInput<{
      version: undefined;
      created: number;
      algo: PubKeyPacketAlgo;
    }>;
    type: P.Values<{
      plain: {
        TAG: 'plain';
        data: P.StructInput<{
          secret: any;
        }>;
      };
      encrypted: {
        TAG: 'encrypted';
        data: PacketData;
      };
      encrypted2: {
        TAG: 'encrypted2';
        data: PacketData;
      };
    }>;
  }>
> = P.struct({
  pub: PubKeyPacket,
  type: P.mappedTag(P.U8, {
    plain: [0x00, PlainSecretKey],
    // Skipping 'Any other value is a symmetric-key encryption algorithm identifier.'
    encrypted: [254, EncryptedSecretKey],
    // Same as above, but secret is with checksum
    encrypted2: [255, EncryptedSecretKey],
  }),
});
type SecretKeyType = P.UnwrapCoder<typeof SecretKeyPacket>;

// https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.1
const SigTypeEnum = P.map(P.U8, {
  binary: 0x00,
  text: 0x01,
  standalone: 0x02,
  certGeneric: 0x10,
  certPersona: 0x11,
  certCasual: 0x12,
  certPositive: 0x13,
  subkeyBinding: 0x18,
  keyBinding: 0x19,
  key: 0x1f,
  keyRevocation: 0x20,
  subkeyRevocation: 0x28,
  certRevocation: 0x30,
  timestamp: 0x40,
  thirdParty: 0x50,
});

// https://datatracker.ietf.org/doc/html/rfc4880.html#section-5.2.3.1
const signatureSubpacket = P.map(P.U8, {
  signatureCreationTime: 2,
  signatureExpirationTime: 3,
  exportableCertification: 4,
  trustSignature: 5,
  regularExpression: 6,
  revocable: 7,
  keyExpirationTime: 9,
  placeholderBackwardsCompatibility: 10,
  preferredEncryptionAlgorithms: 11,
  revocationKey: 12,
  issuer: 16,
  notationData: 20,
  preferredHashAlgorithms: 21,
  preferredCompressionAlgorithms: 22,
  keyServerPreferences: 23,
  preferredKeyServer: 24,
  primaryUserID: 25,
  policyURI: 26,
  keyFlags: 27,
  signersUserID: 28,
  reasonForRevocation: 29,
  features: 30,
  signatureTarget: 31,
  embeddedSignature: 32,
  // https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis-10#section-5.2.3.1
  issuerFingerprint: 33,
  preferredAEADAlgorithms: 34,
  intendedRecipientFingerprint: 35,
  attestedCertifications: 37,
  keyBlock: 38,
});

const SignatureSubpacket = P.prefix(
  PacketLen,
  P.tag(signatureSubpacket, {
    issuerFingerprint: P.struct({ version: PGP_PACKET_VERSION, fingerprint: P.hex(20) }),
    signatureCreationTime: P.U32BE,
    keyFlags: P.bitset([
      '_r',
      'shared',
      'auth',
      'split',
      'encrypt',
      'encryptComm',
      'sign',
      'certify',
    ]),
    preferredEncryptionAlgorithms: P.array(null, EncryptionEnum),
    preferredHashAlgorithms: P.array(null, HashEnum),
    preferredCompressionAlgorithms: P.array(null, CompressionEnum),
    preferredAEADAlgorithms: P.array(null, AEADEnum),
    features: P.bitset(['_r', '_r', '_r', '_r', '_r', 'v5Keys', 'aead', 'modDetect']),
    keyServerPreferences: P.bitset(['modDetect'], true),
    issuer: P.hex(8),
    primaryUserID: P.bool,
  })
);
const SignatureSubpackets = P.prefix(P.U16BE, P.array(null, SignatureSubpacket));

const SignatureHead = P.struct({
  version: PGP_PACKET_VERSION,
  type: SigTypeEnum,
  algo: pubKeyEnum,
  hash: HashEnum,
  hashed: SignatureSubpackets,
});

type SignatureHeadType = P.UnwrapCoder<typeof SignatureHead>;

const SignaturePacket = P.struct({
  head: SignatureHead,
  unhashed: SignatureSubpackets,
  hashPrefix: P.bytes(2),
  // 2: ec + dsa, 1 for rsa
  sig: P.array(null, mpi),
});

type SignatureType = P.UnwrapCoder<typeof SignaturePacket>;

const UserPacket = P.string(null);

// PGP Functions
const EXPBIAS6 = (count: number) => (16 + (count & 15)) << ((count >> 4) + 6);

function deriveKey(hash: string, len: number, password: Bytes, salt?: Bytes, count?: number) {
  // Important: there is difference between zero and empty count
  count = count === undefined ? 0 : EXPBIAS6(count);
  const data = salt ? concatBytes(salt, password) : password;
  let out = new Uint8Array([]);
  const hashC = Hash[hash];
  if (!hashC) throw new Error('PGP.deriveKey: unknown hash');
  const rounds = Math.ceil(len / hashC.outputLen);
  for (let r = 0; r < rounds; r++) {
    const h = hashC.create();
    // prefix
    if (r > 0) h.update(new Uint8Array(r));
    for (let c = Math.max(count, data.length); c > 0; ) {
      const take = Math.min(c, data.length);
      h.update(data.subarray(0, take));
      c -= take;
    }
    out = concatBytes(h.digest());
  }
  return out.subarray(0, len);
}

const Encryption: Record<string, ReturnType<typeof createAesCfb>> = {
  aes128: createAesCfb(128),
  aes192: createAesCfb(192),
  aes256: createAesCfb(256),
};

// https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.4
const hashTail = new Uint8Array([0x04, 0xff]);

const hashPubKey = P.struct({
  magic: P.magic(P.hex(1), '99'),
  pubKey: P.prefix(P.U16BE, PubKeyPacket),
});

const hashUser = P.struct({
  magic: P.magic(P.hex(1), 'b4'),
  user: P.prefix(P.U32BE, UserPacket),
});

const hashSelfCert = P.struct({ pubKey: hashPubKey, user: hashUser });
const hashSubKeyCert = P.struct({ pubKey: hashPubKey, subKey: hashPubKey });

function hashSignature(head: SignatureHeadType, data: any) {
  const hashC = Hash[head.hash];
  if (!hashC) throw new Error('PGP.hashSignature: unknown hash');
  const h = hashC.create();
  if (['certGeneric', 'certPersona', 'certCasual', 'certPositive'].includes(head.type))
    h.update(hashSelfCert.encode(data));
  else if (head.type === 'subkeyBinding') h.update(hashSubKeyCert.encode(data));
  else throw new Error('Unknown signature type');
  const sigData = SignatureHead.encode(head);
  h.update(sigData).update(hashTail).update(P.U32BE.encode(sigData.length));
  return h.digest();
}

// https://datatracker.ietf.org/doc/html/rfc4880#section-6.1
function crc24(data: Bytes) {
  let crc = 0xb704ce;
  for (let i = 0; i < data.length; i++) {
    crc ^= data[i] << 16;
    for (let j = 0; j < 8; j++) {
      crc <<= 1;
      if (crc & 0x1000000) crc ^= 0x1864cfb;
    }
  }
  return new Uint8Array([(crc >> 16) & 0xff, (crc >> 8) & 0xff, crc & 0xff]);
}

const PacketTags: Record<string, any> = {
  userId: UserPacket,
  signature: SignaturePacket,
  publicKey: PubKeyPacket,
  publicSubkey: PubKeyPacket,
  secretKey: SecretKeyPacket,
  secretSubkey: SecretKeyPacket,
};
// https://datatracker.ietf.org/doc/html/rfc4880#section-4.2
// Old packet: [1, version: 0, tag(4), lenType(2)] -- 8 bits
// New packet: [1, version: 1, tag(6)] + len(bytes) -> not supported, GPG generates version 0 for now
const PacketHead = P.struct({
  magic: P.magic(P.bits(1), 1),
  version: P.magic(P.bits(1), 0),
  // https://datatracker.ietf.org/doc/html/rfc4880#section-4.3
  tag: P.map(P.bits(4), {
    public_key_encrypted_session_key: 1,
    signature: 2,
    symmetric_key_encrypted_session_key: 3,
    onePassSignature: 4,
    secretKey: 5,
    publicKey: 6,
    secretSubkey: 7,
    compressedData: 8,
    encryptedData: 9,
    marker: 10,
    literalData: 11,
    trust: 12,
    userId: 13,
    publicSubkey: 14,
    userAttribute: 17,
    encryptedProtectedData: 18,
    modificationDetectionCode: 19,
  }),
  lenType: P.bits(2),
});

const Packet = P.wrap({
  encodeStream: (w: P.Writer, value: any) => {
    const data = PacketTags[value.TAG].encode(value.data);
    const lenType = data.length < 2 ** 8 ? 0 : data.length < 2 ** 16 ? 1 : 2;
    PacketHead.encodeStream(w, { tag: value.TAG, lenType });
    [P.U8, P.U16BE, P.U32BE][lenType].encodeStream(w, data.length);
    w.bytes(data);
  },
  decodeStream: (r: P.Reader): any => {
    const { tag, lenType } = PacketHead.decodeStream(r);
    const packetLen =
      lenType !== 3 ? [P.U8, P.U16BE, P.U32BE][lenType].decodeStream(r) : r.leftBytes;
    return { TAG: tag, data: PacketTags[tag].decode(r.bytes(packetLen)) };
  },
});

export const Stream: P.CoderType<any[]> = P.array(null, Packet);

// Key generation
const EDSIGN = P.array(null, P.U256BE);
function signData(
  head: SignatureHeadType,
  unhashed: any,
  data: any,
  privateKey: Bytes
): SignatureType {
  const hash = hashSignature(head, data);
  const hashPrefix = hash.subarray(0, 2);
  const sig = EDSIGN.decode(ed25519.sign(hash, privateKey)) as any;
  return { head, unhashed, hashPrefix, sig };
}

function decodeSecretChecksum(secret: Bytes) {
  const [data, checksum] = [secret.slice(0, -2), P.U16BE.decode(secret.slice(-2))];
  // Wow, third checksum algorithm in single spec!
  let ourChecksum = 0;
  for (let i = 0; i < data.length; i++) ourChecksum += data[i];
  ourChecksum %= 65536;
  if (ourChecksum !== checksum) throw new Error('PGP.secretKey: wrong checksum for plain encoding');
  return mpi.decode(data);
}

export function decodeSecretKey(password: string, key: SecretKeyType): bigint {
  if (key.type.TAG === 'plain') return decodeSecretChecksum(key.type.data.secret);
  const keyData = key.type.data;
  const data = keyData.S2K.data;
  const keyLen = EncryptionKeySize[keyData.enc];
  if (keyLen === undefined)
    throw new Error(`PGP.secretKey: unknown encryption mode=${keyData.enc}`);
  const encKey = deriveKey(
    data.hash,
    keyLen,
    utf8.decode(password),
    (data as any).salt,
    (data as any).count
  );
  const decrypted = Encryption[keyData.enc].decrypt(keyData.secret, encKey, keyData.iv);
  const decryptedKey = decrypted.subarray(0, -20);
  const checksum = Hash.sha1(decryptedKey);
  if (!equalBytes(decrypted.slice(-20), checksum))
    throw new Error('PGP.secretKey: invalid sha1 checksum');
  if (!['ECDH', 'ECDSA', 'EdDSA'].includes(key.pub.algo.TAG))
    throw new Error(`PGP.secretKey unsupported publicKey algorithm: ${key.pub.algo.TAG}`);
  // Decoded as generic MPI, not as OpaqueMPI
  if (key.type.TAG === 'encrypted2') return decodeSecretChecksum(decryptedKey);
  return mpi.decode(decryptedKey);
}

function createPrivKey(
  pub: PubKeyType,
  key: Bytes,
  password: string,
  salt: Bytes,
  iv: Bytes,
  hash = 'sha1',
  count = 240,
  enc = 'aes128'
): SecretKeyType {
  const keyLen = EncryptionKeySize[enc];
  if (keyLen === undefined) throw new Error(`PGP.secretKey: unknown encryption mode=${enc}`);
  const encKey = deriveKey(hash, keyLen, utf8.decode(password), salt, count);
  const keyBytes = opaquempi.encode(key);
  const secretClear = concatBytes(keyBytes, sha1(keyBytes));
  const secret = Encryption[enc].encrypt(secretClear, encKey, iv);
  const S2K = { TAG: 'iterated', data: { hash, salt, count } } as const;
  return { pub, type: { TAG: 'encrypted', data: { enc, S2K, iv, secret } } };
}

export const pubArmor: P.Coder<any[], string> = base64armor(
  'PGP PUBLIC KEY BLOCK',
  64,
  Stream,
  crc24
);
export const privArmor: P.Coder<any[], string> = base64armor(
  'PGP PRIVATE KEY BLOCK',
  64,
  Stream,
  crc24
);
function validateDate(timestamp: number) {
  if (!Number.isSafeInteger(timestamp) || timestamp < 0 || timestamp > 2 ** 46)
    throw new Error('invalid PGP key creation time: must be a valid UNIX timestamp');
}

function getPublicPackets(edPriv: Bytes, cvPriv: Bytes, createdAt: number) {
  validateDate(createdAt);
  const edPub = bytesToNumberBE(concatBytes(new Uint8Array([0x40]), ed25519.getPublicKey(edPriv)));
  const edPubPacket = {
    created: createdAt,
    algo: { TAG: 'EdDSA', data: { curve: 'ed25519', pub: edPub } },
  } as const;
  const cvPoint = x25519.scalarMultBase(cvPriv);
  const cvPub = bytesToNumberBE(concatBytes(new Uint8Array([0x40]), cvPoint));
  const cvPubPacket = {
    created: createdAt,
    algo: {
      TAG: 'ECDH',
      data: { curve: 'curve25519', pub: cvPub, params: { hash: 'sha256', encryption: 'aes128' } },
    },
  } as const;
  const fingerprint = hex.encode(sha1(hashPubKey.encode({ pubKey: edPubPacket })));
  const keyId = fingerprint.slice(-16);
  return { edPubPacket, fingerprint, keyId, cvPubPacket };
}

function getCerts(edPriv: Bytes, cvPriv: Bytes, user: string, createdAt: number) {
  // key settings same as in PGP to avoid fingerprinting since they are part of public key
  const preferredEncryptionAlgorithms = ['aes256', 'aes192', 'aes128', 'tripledes'];
  const preferredHashAlgorithms = ['sha512', 'sha384', 'sha256', 'sha224', 'sha1'];
  const preferredCompressionAlgorithms = ['zlib', 'bzip2', 'zip'];
  const preferredAEADAlgorithms = ['OCB', 'EAX'];

  const { edPubPacket, fingerprint, keyId, cvPubPacket } = getPublicPackets(
    edPriv,
    cvPriv,
    createdAt
  );

  const edCert = signData(
    {
      type: 'certPositive',
      algo: 'EdDSA',
      hash: 'sha512',
      hashed: [
        { TAG: 'issuerFingerprint', data: { fingerprint } },
        { TAG: 'signatureCreationTime', data: createdAt },
        { TAG: 'keyFlags', data: { sign: true, certify: true } },
        { TAG: 'preferredEncryptionAlgorithms', data: preferredEncryptionAlgorithms },
        { TAG: 'preferredAEADAlgorithms', data: preferredAEADAlgorithms },
        { TAG: 'preferredHashAlgorithms', data: preferredHashAlgorithms },
        { TAG: 'preferredCompressionAlgorithms', data: preferredCompressionAlgorithms },
        { TAG: 'features', data: { aead: true, v5Keys: true, modDetect: true } },
        { TAG: 'keyServerPreferences', data: { modDetect: true } },
      ],
    },
    [{ TAG: 'issuer', data: keyId }],
    { pubKey: { pubKey: edPubPacket }, user: { user } },
    edPriv
  );
  const cvCert = signData(
    {
      type: 'subkeyBinding',
      algo: 'EdDSA',
      hash: 'sha512',
      hashed: [
        { TAG: 'issuerFingerprint', data: { fingerprint } },
        { TAG: 'signatureCreationTime', data: createdAt },
        { TAG: 'keyFlags', data: { encrypt: true, encryptComm: true } },
      ],
    },
    [{ TAG: 'issuer', data: keyId }],
    { pubKey: { pubKey: edPubPacket }, subKey: { pubKey: cvPubPacket } },
    edPriv
  );
  return { edPubPacket, fingerprint, keyId, cvPubPacket, cvCert, edCert };
}

export function formatPublic(
  edPriv: Bytes,
  cvPriv: Bytes,
  user: string,
  createdAt: number
): string {
  const { edPubPacket, cvPubPacket, edCert, cvCert } = getCerts(edPriv, cvPriv, user, createdAt);
  return pubArmor.encode([
    { TAG: 'publicKey', data: edPubPacket },
    { TAG: 'userId', data: user },
    { TAG: 'signature', data: edCert },
    { TAG: 'publicSubkey', data: cvPubPacket },
    { TAG: 'signature', data: cvCert },
  ]);
}

export function formatPrivate(
  edPriv: Bytes,
  cvPriv: Bytes,
  user: string,
  password: string,
  createdAt = 0,
  edSalt: Uint8Array = randomBytes(8),
  edIV: Uint8Array = randomBytes(16),
  cvSalt: Uint8Array = randomBytes(8),
  cvIV: Uint8Array = randomBytes(16)
): string {
  const { edPubPacket, cvPubPacket, edCert, cvCert } = getCerts(edPriv, cvPriv, user, createdAt);
  const edSecret = createPrivKey(edPubPacket, edPriv, password, edSalt, edIV);
  const cvPrivLE = P.U256BE.encode(P.U256LE.decode(cvPriv));
  const cvSecret = createPrivKey(cvPubPacket, cvPrivLE, password, cvSalt, cvIV);
  return privArmor.encode([
    { TAG: 'secretKey', data: edSecret },
    { TAG: 'userId', data: user },
    { TAG: 'signature', data: edCert },
    { TAG: 'secretSubkey', data: cvSecret },
    { TAG: 'signature', data: cvCert },
  ]);
}

/**
 * Derives PGP key ID from the private key.
 * PGP key depends on its date of creation.
 */
export function getKeyId(
  edPrivKey: Bytes,
  createdAt = 0
): {
  edPubPacket: {
    readonly created: number;
    readonly algo: {
      readonly TAG: 'EdDSA';
      readonly data: {
        readonly curve: 'ed25519';
        readonly pub: bigint;
      };
    };
  };
  fingerprint: string;
  keyId: string;
  cvPubPacket: {
    readonly created: number;
    readonly algo: {
      readonly TAG: 'ECDH';
      readonly data: {
        readonly curve: 'curve25519';
        readonly pub: bigint;
        readonly params: {
          readonly hash: 'sha256';
          readonly encryption: 'aes128';
        };
      };
    };
  };
} {
  const { head: cvPrivate } = ed25519.utils.getExtendedPublicKey(edPrivKey);
  return getPublicPackets(edPrivKey, cvPrivate, createdAt);
}

/**
 * Derives PGP private key, public key and fingerprint.
 * Uses S2K KDF, which means it's slow. Use `getKeyId` if you want to get key id in a fast way.
 * PGP key depends on its date of creation.
 * NOTE: gpg: warning: lower 3 bits of the secret key are not cleared
 * happens even for keys generated with GnuPG 2.3.6, because check looks at item as Opaque MPI, when it is just MPI:
 * https://dev.gnupg.org/rGdbfb7f809b89cfe05bdacafdb91a2d485b9fe2e0
 */
export function getKeys(
  privKey: Bytes,
  user: string,
  password: string,
  createdAt = 0
): {
  keyId: string;
  privateKey: string;
  publicKey: string;
} {
  const { head: cvPrivate } = ed25519.utils.getExtendedPublicKey(privKey);
  const { keyId } = getPublicPackets(privKey, cvPrivate, createdAt);
  const publicKey = formatPublic(privKey, cvPrivate, user, createdAt);
  // The slow part
  const privateKey = formatPrivate(privKey, cvPrivate, user, password, createdAt);
  return { keyId, privateKey, publicKey };
}

export default getKeys;

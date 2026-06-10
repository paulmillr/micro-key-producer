/*! micro-key-producer - MIT License (c) 2024 Paul Miller (paulmillr.com) */
/**
 * PGP (GPG) key producer. Allows to deterministically generate ed25519 PGP keys.
 *
 * 1. Generated private and public keys would have different representation, however, **their
 * fingerprints would be the same**. This is because AES encryption is used to hide the keys, and
 * AES requires different IV / salt.
 * 2. The function is slow (400ms on Apple M4), because it uses S2K to derive keys.
 * 3. "warning: lower 3 bits of the secret key are not cleared" happens even for keys generated with
 * GnuPG 2.3.6, because check looks at item as Opaque MPI, when it is just MPI: see
 * [bugtracker URL](https://dev.gnupg.org/rGdbfb7f809b89cfe05bdacafdb91a2d485b9fe2e0).
 *
 * RFCS:
 * - main: https://datatracker.ietf.org/doc/html/rfc4880
 * - ecdh: https://datatracker.ietf.org/doc/html/rfc6637
 * - ed25519: https://www.ietf.org/archive/id/draft-koch-eddsa-for-openpgp-04.txt
 * - bis: https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis-10#section-5.2.3.1
 *
 * @module
 */
import { aeskw, cfb, gcm } from '@noble/ciphers/aes.js';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import {
  bytesToNumberBE,
  equalBytes,
  numberToBytesBE,
  numberToHexUnpadded,
} from '@noble/curves/utils.js';
import { argon2id } from '@noble/hashes/argon2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { md5, ripemd160, sha1 } from '@noble/hashes/legacy.js';
import { sha224, sha256, sha384, sha512 } from '@noble/hashes/sha2.js';
import { sha3_256, sha3_512 } from '@noble/hashes/sha3.js';
import {
  abytes,
  concatBytes,
  isBytes,
  randomBytes,
  type CHash,
  type TArg,
  type TRet,
} from '@noble/hashes/utils.js';
import { hex, utf8 } from '@scure/base';
import * as P from 'micro-packed';
import { oidName } from './asn1.ts';
import { astring, base64armor, deepFreeze } from './utils.ts';

/** Byte-array alias used across the PGP helpers. */
export type Bytes = Uint8Array;
const _0n = /* @__PURE__ */ BigInt(0);
const _1n = /* @__PURE__ */ BigInt(1);
function runAesCfb(
  keyLen: number,
  data: TArg<Bytes>,
  key: TArg<Bytes>,
  iv: TArg<Bytes>,
  decrypt = false
): TRet<Bytes> {
  // NOTE: we need to validate key length here since file can be malformed
  if (keyLen !== key.length * 8) throw new Error('aes-cfb: wrong key length');
  if (iv.length !== 16) throw new Error('aes-cfb: wrong IV');
  // RFC 4880 secret-key packets use the packet IV with plain CFB over the full
  // V4 secret-MPI stream, not the zero-IV + resync data-packet variant from
  // OpenPGP CFB mode.
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
  return res as TRet<Bytes>;
}

function createAesCfb(len: number) {
  return {
    encrypt: (plaintext: TArg<Bytes>, key: TArg<Bytes>, iv: TArg<Bytes>) =>
      runAesCfb(len, plaintext, key, iv),
    decrypt: (ciphertext: TArg<Bytes>, key: TArg<Bytes>, iv: TArg<Bytes>) =>
      runAesCfb(len, ciphertext, key, iv, true),
  };
}

// PGP Types
// Multiprecision Integers [RFC4880](https://datatracker.ietf.org/doc/html/rfc4880)
/**
 * RFC 4880 multi-precision integer coder.
 * @example
 * Encode one RFC 4880 multi-precision integer.
 * ```ts
 * import { mpi } from 'micro-key-producer/pgp.js';
 * mpi.encode(1n);
 * ```
 */
export const mpi: P.CoderType<bigint> = /* @__PURE__ */ deepFreeze(
  /* @__PURE__ */ P.wrap({
    encodeStream: (w: P.Writer, value: bigint) => {
      // RFC 4880 §3.2: a zero-valued MPI has bit length 0 and therefore carries no payload octets.
      if (value === _0n) return P.U16BE.encodeStream(w, 0);
      let bitLen = 0;
      for (let v = value; v > _0n; v >>= _1n, bitLen++);
      P.U16BE.encodeStream(w, bitLen);
      w.bytes(hex.decode(numberToHexUnpadded(value)));
    },
    decodeStream: (r: P.Reader): bigint => {
      const bitLen = P.U16BE.decodeStream(r);
      const bytes = r.bytes((bitLen + 7) >>> 3);
      // RFC 4880 §3.2 / RFC 9580 §3.2: length starts at the most significant
      // non-zero bit, and unused high bits in the first payload octet are zero.
      let realBitLen = 0;
      for (let i = 0; i < bytes.length; i++) {
        const byte = bytes[i];
        if (!byte) continue;
        let bits = 8;
        for (let mask = 0x80; !(byte & mask); mask >>= 1, bits--);
        realBitLen = (bytes.length - i - 1) * 8 + bits;
        break;
      }
      if (realBitLen !== bitLen) throw new Error('PGP.mpi: invalid bit length');
      return bitLen === 0 ? _0n : bytesToNumberBE(bytes);
    },
  })
);

// GnuGP violates spec by using non-zero stripped MPI's for secret keys (opaque MPI/SOS).
// We need to do the same to create equal keys.
// More info:
// - https://www.mhonarc.org/archive/html/ietf-openpgp/2019-10/msg00041.html
// - https://marc.info/?l=gnupg-devel&m=161518990118244&w=2
/**
 * Opaque MPI coder used by OpenPGP secret-key packets.
 * @example
 * Encode one opaque MPI for an OpenPGP secret-key packet.
 * ```ts
 * import { opaquempi } from 'micro-key-producer/pgp.js';
 * opaquempi.encode(new Uint8Array([1, 2]));
 * ```
 */
export const opaquempi: TRet<P.CoderType<Uint8Array>> = /* @__PURE__ */ deepFreeze(
  /* @__PURE__ */ P.prefix(
    /* @__PURE__ */ P.apply(P.U16BE, {
      encode: (bitLen: number): number => (bitLen + 7) >>> 3,
      decode: (len: number): number => len * 8,
    }),
    /* @__PURE__ */ P.bytes(null)
  ) as unknown as TRet<P.CoderType<Uint8Array>>
);

const openPGPLen = (name: string, twoOctetFirstMax: number): P.CoderType<number> => {
  const twoOctetMax = ((twoOctetFirstMax - 192) << 8) + 255 + 192;
  return P.wrap({
    encodeStream: (w: P.Writer, value: number) => {
      if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0)
        throw new Error(`${name} invalid length type, ${value}`);
      if (value < 192) w.byte(value);
      else if (value <= twoOctetMax) {
        value -= 192;
        w.bytes(new Uint8Array([(value >> 8) + 192, value & 0xff]));
      } else if (value < 2 ** 32) {
        w.byte(0xff);
        P.U32BE.encodeStream(w, value);
      } else throw new Error(`${name}: length is too big: ${value}`);
    },
    decodeStream: (r: P.Reader): number => {
      let res;
      const first = r.byte();
      if (first < 192) res = first;
      else if (first <= twoOctetFirstMax) res = ((first - 192) << 8) + r.byte() + 192;
      else if (first == 255) res = P.U32BE.decodeStream(r);
      else throw new Error(`${name}: Partial body lengths unsupported`);
      return res;
    },
  });
};

/**
 * OpenPGP packet-length coder.
 * RFC 9580 §4.2.1.2 limits packet-body two-octet lengths to first octets
 * 192..223; §4.2.1.4 reserves 224..254 for partial body lengths, which this
 * definite-length packet codec intentionally rejects.
 * @example
 * Encode one OpenPGP packet length.
 * ```ts
 * import { PacketLen } from 'micro-key-producer/pgp.js';
 * PacketLen.encode(191);
 * ```
 */
export const PacketLen: P.CoderType<number> = /* @__PURE__ */ deepFreeze(
  /* @__PURE__ */ openPGPLen('PGP.PacketLen', 223)
);

// RFC 9580 §5.2.3.7 decodes signature-subpacket first octets 192..254 as
// two-octet lengths; this differs from RFC 9580 §4.2.1.4 packet-body
// partial-length octets 224..254, so subpackets need their own length coder.
const SignatureSubpacketLen: P.CoderType<number> = /* @__PURE__ */ openPGPLen(
  'PGP.SignatureSubpacketLen',
  254
);

// PGP Structures
// Other (RSA/ElGamal/etc) is unsupported
// This module emits the older RFC 6637 / RFC 9580 legacy ECC packet IDs
// (18/22), but RFC 9580 §9.1 assigns fixed-width v6 IDs 25/27/28 and
// Appendix A uses Ed25519/X25519 packets that need to be preserved.
const pubKeyEnum = /* @__PURE__ */ P.map(P.U8, {
  ECDH: 18,
  ECDSA: 19,
  EdDSA: 22,
  X25519: 25,
  X448: 26,
  Ed25519: 27,
  Ed448: 28,
});

// Legacy OpenPGP ECC packets mostly follow the RFC 6637 / RFC 9580
// §9.2 OID set. RFC 9580 §9.2 Table 19 does not list secp256k1, but
// GnuPG 2.4.7 advertises and emits OID 1.3.132.0.10 for ECDSA/ECDH.
const ECEnum = /* @__PURE__ */ (() =>
  P.map(P.prefix(P.U8, oidName), {
    nistP256: 'P-256',
    nistP384: 'P-384',
    nistP521: 'P-521',
    brainpoolP256r1: 'brainpoolP256r1',
    brainpoolP384r1: 'brainpoolP384r1',
    brainpoolP512r1: 'brainpoolP512r1',
    secp256k1: 'secp256k1',
    curve25519: 'curve25519Legacy',
    ed25519: 'ed25519Legacy',
  }))();

// The packet registry still includes deprecated hash IDs for interoperability;
// concrete implementations live in `Hash` below and are intentionally smaller.
const HashEnum = /* @__PURE__ */ P.map(P.U8, {
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

// RFC 9580 §9.5 hash IDs accepted by `HashEnum` must be wired here for S2K
// and signature hashing; MD5 is legacy decode support, not a generated pref.
const Hash: Record<string, CHash> = {
  md5,
  ripemd160,
  sha224,
  sha256,
  sha384,
  sha512,
  sha3_256,
  sha3_512,
  sha1,
};

// The packet registry is broader than the AES-only implementation below; keep
// this parser map aligned with the current symmetric-key registry so preference
// lists and packet headers still decode.
const EncryptionEnum = /* @__PURE__ */ P.map(P.U8, {
  plaintext: 0,
  idea: 1,
  tripledes: 2,
  cast5: 3,
  blowfish: 4,
  aes128: 7,
  aes192: 8,
  aes256: 9,
  twofish: 10,
  // RFC 9580 §9.3 adds Camellia to the packet-level symmetric-key registry.
  // Concrete secret-key decryption remains limited by `EncryptionKeySize` / `Encryption`.
  camellia128: 11,
  camellia192: 12,
  camellia256: 13,
});

const EncryptionKeySize: Record<string, number> = {
  // Keep this table aligned with concrete `Encryption`: an entry here means
  // `decodeSecretKey()` derives a KEK and tries `Encryption[enc]`.
  // RFC 4880 §5.5.3 / RFC 9580 §5.5.3 use S2K usage 0 for unencrypted
  // secret-key data; algorithm id 0 is not a CFB cipher for usage 254/255.
  aes128: 16,
  aes192: 24,
  aes256: 32,
};

// Packet-level compression registry for preference subpackets; private and
// experimental ids have no stable string form in this API.
const CompressionEnum = /* @__PURE__ */ P.map(P.U8, {
  uncompressed: 0,
  zip: 1,
  zlib: 2,
  bzip2: 3,
});
// RFC 9580 §9.6 Table 25 reserves id 0 and assigns 1=EAX, 2=OCB, 3=GCM for AEAD algorithm ids.
const AEADEnum = /* @__PURE__ */ P.map(P.U8, {
  EAX: 1,
  OCB: 2,
  GCM: 3,
});
const lengthTable = (len: Readonly<Record<string, number>>, error: (name: string) => string) => {
  return (name = '') => {
    const size = len[name];
    if (typeof size !== 'number') throw new Error(error(name));
    return size;
  };
};
const aeadNonceLen = /* @__PURE__ */ lengthTable(
  {
    // RFC 9580 §9.6 Table 25 fixes nonce sizes: EAX=16, OCB=15, GCM=12.
    EAX: 16,
    OCB: 15,
    GCM: 12,
  },
  (aead) => `PGP.AEAD: unknown nonce length for ${aead}`
);
const AEAD_TAG_LEN = 16;
const AeadWithIVLen = /* @__PURE__ */ P.apply(AEADEnum, {
  encode: (aead) => ({ aead, ivLen: aeadNonceLen(aead) }),
  decode: (from) => from.aead,
});

const Argon2S2K = /* @__PURE__ */ P.validate(
  /* @__PURE__ */ P.struct({
    salt: /* @__PURE__ */ P.bytes(16),
    t: P.U8,
    p: P.U8,
    encodedM: P.U8,
  }),
  (s2k) => {
    // RFC 9580 §3.7.1.4: Argon2 S2K is 16-byte salt, nonzero t/p, and
    // encoded_m in 3+ceil(log2(p))..31, with Argon2id v=0x13 for the KDF.
    if (!s2k.t) throw new Error('PGP.S2K: Argon2 passes must be nonzero');
    if (!s2k.p) throw new Error('PGP.S2K: Argon2 parallelism must be nonzero');
    const min = 3 + Math.ceil(Math.log2(s2k.p));
    if (s2k.encodedM < min || s2k.encodedM > 31)
      throw new Error(`PGP.S2K: Argon2 encoded_m must be ${min}..31`);
    return s2k;
  }
);
type S2KType =
  | { TAG: 'simple'; data: { hash: string } }
  | { TAG: 'salted'; data: { hash: string; salt: Bytes } }
  | { TAG: 'iterated'; data: { hash: string; salt: Bytes; count: number } }
  | { TAG: 'argon2'; data: { salt: Bytes; t: number; p: number; encodedM: number } };
const S2KEnum: P.CoderType<string> = /* @__PURE__ */ P.map(P.U8, {
  simple: 0,
  salted: 1,
  iterated: 3,
  argon2: 4,
});
// RFC 4880 §3.7.1.1-§3.7.1.3 define the hash-based S2K bodies; RFC
// 9580 §3.7.1 Table 1 / §3.7.1.4 adds Argon2 as type 4 with a 20-octet
// specifier field after the type octet.
const S2K: P.CoderType<S2KType> = /* @__PURE__ */ P.tag(S2KEnum, {
  simple: /* @__PURE__ */ P.struct({ hash: HashEnum }),
  salted: /* @__PURE__ */ P.struct({ hash: HashEnum, salt: /* @__PURE__ */ P.bytes(8) }),
  iterated: /* @__PURE__ */ P.struct({
    hash: HashEnum,
    salt: /* @__PURE__ */ P.bytes(8),
    count: P.U8,
  }),
  argon2: Argon2S2K,
});

const V4SymmetricKeyEncryptedSessionKeyPacketBody = /* @__PURE__ */ P.validate(
  /* @__PURE__ */ P.struct({
    enc: EncryptionEnum,
    S2K,
    encryptedSessionKey: /* @__PURE__ */ P.bytes(null),
  }),
  (packet) => {
    // RFC 9580 §5.3.1: when v4 SKESK carries an encrypted session key, the
    // all-zero-IV CFB wrapper requires a salt-bearing S2K: salted, iterated, or Argon2.
    if (packet.encryptedSessionKey.length && packet.S2K.TAG === 'simple')
      throw new Error('PGP.SKESK: encrypted session key requires salted S2K');
    return packet;
  }
);
type V6AEADParamsType = { enc: string; aead: string; S2K: S2KType; iv: Bytes };
const V6AEADParams: P.CoderType<V6AEADParamsType> = /* @__PURE__ */ P.apply(
  /* @__PURE__ */ P.struct({
    enc: EncryptionEnum,
    aead: AeadWithIVLen,
    S2K: /* @__PURE__ */ P.prefix(P.U8, S2K),
    iv: /* @__PURE__ */ P.bytes('aead/ivLen'),
  }),
  {
    encode: (raw) => ({ enc: raw.enc, aead: raw.aead.aead, S2K: raw.S2K, iv: raw.iv }),
    decode: (from) => ({
      enc: from.enc,
      aead: { aead: from.aead, ivLen: aeadNonceLen(from.aead) },
      S2K: from.S2K,
      iv: from.iv,
    }),
  }
);
type V4SymmetricKeyEncryptedSessionKeyPacketType = {
  version?: undefined;
  enc: string;
  S2K: S2KType;
  encryptedSessionKey: Bytes;
};
type V6SymmetricKeyEncryptedSessionKeyPacketType = {
  version: 6;
  enc: string;
  aead: string;
  S2K: S2KType;
  iv: Bytes;
  encryptedSessionKey: Bytes;
  tag: Bytes;
};
type SymmetricKeyEncryptedSessionKeyPacketType =
  | V4SymmetricKeyEncryptedSessionKeyPacketType
  | V6SymmetricKeyEncryptedSessionKeyPacketType;
const V6SymmetricKeyEncryptedSessionKeyPacketBody: P.CoderType<
  Omit<V6SymmetricKeyEncryptedSessionKeyPacketType, 'version'>
> = /* @__PURE__ */ P.apply(
  /* @__PURE__ */ P.struct({
    params: /* @__PURE__ */ P.prefix(P.U8, V6AEADParams),
    keyAndTag: /* @__PURE__ */ P.bytes(null),
  }),
  {
    encode: (raw) => {
      if (raw.keyAndTag.length < AEAD_TAG_LEN) throw new Error('PGP.SKESK: truncated AEAD tag');
      return {
        ...raw.params,
        encryptedSessionKey: raw.keyAndTag.slice(0, -AEAD_TAG_LEN) as Bytes,
        tag: raw.keyAndTag.slice(-AEAD_TAG_LEN) as Bytes,
      };
    },
    decode: (packet) => {
      if (packet.tag.length !== AEAD_TAG_LEN) throw new Error('PGP.SKESK: invalid AEAD tag length');
      return { params: packet, keyAndTag: concatBytes(packet.encryptedSessionKey, packet.tag) };
    },
  }
);
const SKESKVersion = /* @__PURE__ */ P.map(P.U8, { v4: 4, v6: 6 });
const SymmetricKeyEncryptedSessionKeyPacketRaw = /* @__PURE__ */ P.tag(SKESKVersion, {
  v4: V4SymmetricKeyEncryptedSessionKeyPacketBody,
  v6: V6SymmetricKeyEncryptedSessionKeyPacketBody,
});
type SymmetricKeyEncryptedSessionKeyPacketRawType = P.UnwrapCoder<
  typeof SymmetricKeyEncryptedSessionKeyPacketRaw
>;
const SymmetricKeyEncryptedSessionKeyPacket: P.CoderType<SymmetricKeyEncryptedSessionKeyPacketType> =
  /* @__PURE__ */ P.apply<
    SymmetricKeyEncryptedSessionKeyPacketRawType,
    SymmetricKeyEncryptedSessionKeyPacketType
  >(SymmetricKeyEncryptedSessionKeyPacketRaw, {
    encode: (from) =>
      from.TAG === 'v6' ? { version: 6, ...from.data } : { version: undefined, ...from.data },
    decode: (packet) => {
      if (packet.version === 6) {
        const { version: _, ...data } = packet;
        return { TAG: 'v6' as const, data };
      }
      return {
        TAG: 'v4' as const,
        data: {
          enc: packet.enc,
          S2K: packet.S2K,
          encryptedSessionKey: packet.encryptedSessionKey,
        },
      };
    },
  });

// https://datatracker.ietf.org/doc/html/rfc6637#section-9
// Shared legacy public-key body for OID + point-MPI packets; ECDH adds its KDF
// params separately in `ECDHPub`.
type ECDSAPubType = { curve: string; pub: bigint };
const ECDSAPub: P.CoderType<ECDSAPubType> = /* @__PURE__ */ P.struct({
  curve: ECEnum,
  pub: mpi,
});

// Raw RFC 6637 ECDH public-key body; higher-level packet construction chooses
// the curve-specific KDF/KEK pairings such as RFC 9580 Table 30.
type ECDHPubType = {
  curve: string;
  pub: bigint;
  params: { hash: string; encryption: string };
};
const ECDHPub: P.CoderType<ECDHPubType> = /* @__PURE__ */ P.struct({
  curve: ECEnum,
  pub: mpi,
  params: /* @__PURE__ */ P.prefix(
    P.U8,
    /* @__PURE__ */ P.struct({
      magic: /* @__PURE__ */ P.magic(/* @__PURE__ */ P.hex(1), '01'),
      hash: HashEnum,
      encryption: EncryptionEnum,
    })
  ),
});
type NativePubType = { pub: Bytes };
const NativePub32: P.CoderType<NativePubType> = /* @__PURE__ */ P.struct({
  pub: /* @__PURE__ */ P.bytes(32),
});
const NativePub56: P.CoderType<NativePubType> = /* @__PURE__ */ P.struct({
  pub: /* @__PURE__ */ P.bytes(56),
});
const NativePub57: P.CoderType<NativePubType> = /* @__PURE__ */ P.struct({
  pub: /* @__PURE__ */ P.bytes(57),
});
const PublicKeyMaterial = /* @__PURE__ */ P.tag(pubKeyEnum, {
  EdDSA: ECDSAPub,
  ECDSA: ECDSAPub,
  ECDH: ECDHPub,
  // RFC 9580 §5.5.5.7-§5.5.5.10: v6 X25519/X448/Ed25519/Ed448
  // key material is native fixed-width octets, not OID+MPI legacy material.
  X25519: NativePub32,
  X448: NativePub56,
  Ed25519: NativePub32,
  Ed448: NativePub57,
});

/** Supported OpenPGP public-key packet algorithms. */
export type PubKeyPacketAlgo =
  | { TAG: 'EdDSA'; data: ECDSAPubType }
  | { TAG: 'ECDSA'; data: ECDSAPubType }
  | { TAG: 'ECDH'; data: ECDHPubType }
  | { TAG: 'X25519'; data: NativePubType }
  | { TAG: 'X448'; data: NativePubType }
  | { TAG: 'Ed25519'; data: NativePubType }
  | { TAG: 'Ed448'; data: NativePubType };
type PubKeyPacketType = {
  version?: undefined | 6;
  created: number;
  algo: PubKeyPacketAlgo;
};
// RFC 9580 §5.5.2.3 inserts a 4-octet count around v6 public-key material,
// after the public-key algorithm octet.
const V6PublicKeyMaterial: P.CoderType<PubKeyPacketAlgo> = /* @__PURE__ */ P.apply(
  /* @__PURE__ */ P.struct({ algo: pubKeyEnum, material: /* @__PURE__ */ P.bytes(P.U32BE) }),
  {
    // `PublicKeyMaterial` is the shared algorithm-tagged body coder; v6 keeps
    // the algorithm octet outside the counted material, so this is a real
    // packet-layout boundary rather than a field-level string/bytes transform.
    encode: (raw) =>
      PublicKeyMaterial.decode(concatBytes(pubKeyEnum.encode(raw.algo), raw.material)),
    decode: (algo) => {
      const material = PublicKeyMaterial.encode(algo);
      return { algo: algo.TAG, material: material.subarray(1) };
    },
  }
);
const PubKeyVersion = /* @__PURE__ */ P.map(P.U8, { v4: 4, v6: 6 });
const PubKeyPacketRaw = /* @__PURE__ */ P.tag(PubKeyVersion, {
  v4: /* @__PURE__ */ P.struct({ created: P.U32BE, algo: PublicKeyMaterial }),
  v6: /* @__PURE__ */ P.struct({ created: P.U32BE, algo: V6PublicKeyMaterial }),
});

/**
 * OpenPGP public-key packet coder.
 * Current package generation stays on version-4 legacy EdDSA primary-key /
 * ECDH subkey packets; the parser also preserves RFC 9580 version-6 vectors.
 * @example
 * Encode one Ed25519 OpenPGP public-key packet.
 * ```ts
 * import { PubKeyPacket } from 'micro-key-producer/pgp.js';
 * import { ed25519 } from '@noble/curves/ed25519.js';
 * import { bytesToNumberBE } from '@noble/curves/utils.js';
 * import { concatBytes } from '@noble/hashes/utils.js';
 * const secretKey = ed25519.utils.randomSecretKey();
 * PubKeyPacket.encode({
 *   created: 0,
 *   algo: {
 *     TAG: 'EdDSA',
 *     data: {
 *       curve: 'ed25519',
 *       pub: bytesToNumberBE(concatBytes(Uint8Array.of(0x40), ed25519.getPublicKey(secretKey))),
 *     },
 *   },
 * });
 * ```
 */
/** OpenPGP public-key packet coder. */
const PubKeyPacketCoder: P.CoderType<PubKeyPacketType> = /* @__PURE__ */ deepFreeze(
  /* @__PURE__ */ P.apply<P.UnwrapCoder<typeof PubKeyPacketRaw>, PubKeyPacketType>(
    PubKeyPacketRaw,
    {
      encode: (from) =>
        from.TAG === 'v6' ? { version: 6, ...from.data } : { version: undefined, ...from.data },
      decode: (key) => ({
        TAG: key.version === 6 ? ('v6' as const) : ('v4' as const),
        data: { created: key.created, algo: key.algo },
      }),
    }
  )
);
export const PubKeyPacket: TRet<P.CoderType<PubKeyPacketType>> =
  PubKeyPacketCoder as unknown as TRet<P.CoderType<PubKeyPacketType>>;

// Raw unencrypted secret-key payload bytes; checksum verification and
// MPI-vs-opaque-MPI interpretation live in `createPrivKey()` /
// `decodeSecretKey()`, not in this wrapper.
const PlainSecretKey: P.CoderType<{ secret: Bytes }> = /* @__PURE__ */ P.struct({
  secret: /* @__PURE__ */ P.bytes(null),
});

const secretKeyIVLen = /* @__PURE__ */ lengthTable(
  {
    // RFC 4880 §5.5.3 / RFC 9580 §5.5.3: encrypted secret-key CFB IVs use
    // the cipher block size. RFC 4880 §13.9 has 8-octet legacy blocks and
    // 16-octet AES/Twofish blocks; plaintext has no CFB IV and is absent.
    idea: 8,
    tripledes: 8,
    cast5: 8,
    blowfish: 8,
    aes128: 16,
    aes192: 16,
    aes256: 16,
    twofish: 16,
    // RFC 3713 §1.1 defines Camellia as a 128-bit block cipher.
    camellia128: 16,
    camellia192: 16,
    camellia256: 16,
  },
  (enc) => `PGP.secretKey: unknown CFB block size for ${enc}`
);
const EncWithIVLen = /* @__PURE__ */ P.apply(EncryptionEnum, {
  encode: (enc) => ({ enc, ivLen: secretKeyIVLen(enc) }),
  decode: (from) => from.enc,
});

type EncryptedSecretKeyParamsType = { enc: string; S2K: S2KType; iv: Bytes };
const EncryptedSecretKeyParams: P.CoderType<EncryptedSecretKeyParamsType> = /* @__PURE__ */ P.apply(
  /* @__PURE__ */ P.validate(
    /* @__PURE__ */ P.struct({
      enc: EncWithIVLen,
      S2K,
      iv: /* @__PURE__ */ P.bytes('enc/ivLen'),
    }),
    (key) => {
      // RFC 9580 §3.7.2.1: Argon2 S2K is only valid with AEAD secret-key
      // usage 253; this wrapper is the legacy CFB usage 254/255 body.
      if (key.S2K.TAG === 'argon2') throw new Error('PGP.secretKey: Argon2 S2K requires AEAD');
      return key;
    }
  ),
  {
    encode: (from) => ({ enc: from.enc.enc, S2K: from.S2K, iv: from.iv }),
    decode: (to) => ({
      enc: { enc: to.enc, ivLen: secretKeyIVLen(to.enc) },
      S2K: to.S2K,
      iv: to.iv,
    }),
  }
);
const EncryptedSecretKey: P.CoderType<EncryptedSecretKeyParamsType & { secret: Bytes }> =
  /* @__PURE__ */ P.apply(
    /* @__PURE__ */ P.struct({
      params: EncryptedSecretKeyParams,
      secret: /* @__PURE__ */ P.bytes(null),
    }),
    {
      encode: (from) => ({ ...from.params, secret: from.secret }),
      decode: (to) => ({
        params: { enc: to.enc, S2K: to.S2K, iv: to.iv },
        secret: to.secret,
      }),
    }
  );
const V6CFBParams: P.CoderType<EncryptedSecretKeyParamsType> = /* @__PURE__ */ P.apply(
  /* @__PURE__ */ P.validate(
    /* @__PURE__ */ P.struct({
      enc: EncWithIVLen,
      // RFC 9580 §5.5.3: v6 usage 254 includes an S2K-specifier-length
      // octet inside the outer parameter-length field.
      S2K: /* @__PURE__ */ P.prefix(P.U8, S2K),
      iv: /* @__PURE__ */ P.bytes('enc/ivLen'),
    }),
    (key) => {
      // RFC 9580 §3.7.2.1: Argon2 S2K is valid only with AEAD usage 253.
      if (key.S2K.TAG === 'argon2') throw new Error('PGP.secretKey: Argon2 S2K requires AEAD');
      return key;
    }
  ),
  {
    encode: (from) => ({ enc: from.enc.enc, S2K: from.S2K, iv: from.iv }),
    decode: (to) => ({
      enc: { enc: to.enc, ivLen: secretKeyIVLen(to.enc) },
      S2K: to.S2K,
      iv: to.iv,
    }),
  }
);
type SecretKeyProtectionType =
  | { TAG: 'plain'; data: P.UnwrapCoder<typeof PlainSecretKey> }
  | {
      TAG: 'aead';
      data: { enc: string; aead: string; S2K: S2KType; iv: Bytes; secret: Bytes };
    }
  | { TAG: 'encrypted'; data: P.UnwrapCoder<typeof EncryptedSecretKey> }
  | { TAG: 'encrypted2'; data: P.UnwrapCoder<typeof EncryptedSecretKey> }
  | { TAG: 'encryptedDirect'; data: { enc: string; iv: Bytes; secret: Bytes } };
type V4SecretKeyProtectionType = Exclude<SecretKeyProtectionType, { TAG: 'aead' }>;
type V6SecretKeyProtectionType =
  | Extract<SecretKeyProtectionType, { TAG: 'plain' }>
  | Extract<SecretKeyProtectionType, { TAG: 'aead' }>
  | Extract<SecretKeyProtectionType, { TAG: 'encrypted' }>;
const DirectSecretKeyTags = [
  'idea',
  'tripledes',
  'cast5',
  'blowfish',
  'aes128',
  'aes192',
  'aes256',
  'twofish',
  'camellia128',
  'camellia192',
  'camellia256',
] as const;
type DirectSecretKeyTag = (typeof DirectSecretKeyTags)[number];
type DirectSecretKeyBodyType = { iv: Bytes; secret: Bytes };
type SecretKeyProtectionRawType =
  | { TAG: 'plain'; data: P.UnwrapCoder<typeof PlainSecretKey> }
  | { TAG: 'encrypted'; data: P.UnwrapCoder<typeof EncryptedSecretKey> }
  | { TAG: 'encrypted2'; data: P.UnwrapCoder<typeof EncryptedSecretKey> }
  | { TAG: DirectSecretKeyTag; data: DirectSecretKeyBodyType };
const SecretKeyProtection: P.CoderType<V4SecretKeyProtectionType> = /* @__PURE__ */ (() => {
  // Keep the v4 secret-key usage registry local so single-coder treeshake
  // bundles can drop the legacy direct-CFB packet table when SecretKeyPacket is unused.
  const DirectSecretKeyTagSet = /* @__PURE__ */ new Set<string>(DirectSecretKeyTags);
  const DirectSecretKeyBody = (enc: DirectSecretKeyTag) =>
    P.struct({ iv: P.bytes(secretKeyIVLen(enc)), secret: P.bytes(null) });
  return P.apply<SecretKeyProtectionRawType, V4SecretKeyProtectionType>(
    P.tag(
      P.map(P.U8, {
        plain: 0,
        idea: 1,
        tripledes: 2,
        cast5: 3,
        blowfish: 4,
        aes128: 7,
        aes192: 8,
        aes256: 9,
        twofish: 10,
        camellia128: 11,
        camellia192: 12,
        camellia256: 13,
        encrypted: 254,
        encrypted2: 255,
      }),
      {
        plain: PlainSecretKey,
        encrypted: EncryptedSecretKey,
        encrypted2: EncryptedSecretKey,
        idea: DirectSecretKeyBody('idea'),
        tripledes: DirectSecretKeyBody('tripledes'),
        cast5: DirectSecretKeyBody('cast5'),
        blowfish: DirectSecretKeyBody('blowfish'),
        aes128: DirectSecretKeyBody('aes128'),
        aes192: DirectSecretKeyBody('aes192'),
        aes256: DirectSecretKeyBody('aes256'),
        twofish: DirectSecretKeyBody('twofish'),
        camellia128: DirectSecretKeyBody('camellia128'),
        camellia192: DirectSecretKeyBody('camellia192'),
        camellia256: DirectSecretKeyBody('camellia256'),
      }
    ),
    {
      encode: (from) => {
        if (from.TAG === 'plain' || from.TAG === 'encrypted' || from.TAG === 'encrypted2')
          return from;
        // RFC 4880 §5.5.3 and RFC 9580 §3.7.2.1: any other known symmetric
        // cipher id is the legacy direct-CFB form with MD5(passphrase), an IV,
        // and encrypted secrets||2-octet-checksum.
        return { TAG: 'encryptedDirect', data: { enc: from.TAG, ...from.data } };
      },
      decode: (value) => {
        if (value.TAG !== 'encryptedDirect') return value;
        // RFC 9580 §3.7.2.1 marks direct cipher-id usage as LegacyCFB:
        // readable for v4-and-earlier keys, but Generate? No. This encoder only
        // preserves already-parsed packets; createPrivKey() never emits it.
        if (!DirectSecretKeyTagSet.has(value.data.enc))
          throw new Error(`PGP.secretKey: unknown direct cipher=${value.data.enc}`);
        return {
          TAG: value.data.enc as DirectSecretKeyTag,
          data: { iv: value.data.iv, secret: value.data.secret },
        };
      },
    }
  );
})();
type V6SecretKeyProtectionRawType =
  | { TAG: 'plain'; data: P.UnwrapCoder<typeof PlainSecretKey> }
  | { TAG: 'aead'; data: { params: V6AEADParamsType; secret: Bytes } }
  | { TAG: 'encrypted'; data: { params: EncryptedSecretKeyParamsType; secret: Bytes } };
const V6SecretKeyUsage = /* @__PURE__ */ P.map(P.U8, { plain: 0, aead: 253, encrypted: 254 });
const V6SecretKeyProtectionRaw: P.CoderType<V6SecretKeyProtectionRawType> = /* @__PURE__ */ P.tag(
  V6SecretKeyUsage,
  {
    // RFC 9580 §5.5.3: v6 unencrypted secret keys omit the legacy 2-octet
    // checksum used by v3/v4 usage 0 packets.
    plain: PlainSecretKey,
    // RFC 9580 §5.5.3 adds a v6 count over encrypted-secret S2K parameters;
    // usage 253 then carries AEAD-encrypted secret octets plus its tag.
    aead: /* @__PURE__ */ P.struct({
      params: /* @__PURE__ */ P.prefix(P.U8, V6AEADParams),
      secret: /* @__PURE__ */ P.bytes(null),
    }),
    // RFC 9580 §5.5.3 / §3.7.2.1: v6 usage 254 is still CFB with S2K and
    // SHA-1 trailer, but v6 adds a parameter-length octet before cipher,
    // S2K-specifier-length, S2K specifier, and IV. Usage 255 is forbidden
    // for v6 by RFC 9580 §5.5.3 and is intentionally not mapped.
    encrypted: /* @__PURE__ */ P.struct({
      params: /* @__PURE__ */ P.prefix(P.U8, V6CFBParams),
      secret: /* @__PURE__ */ P.bytes(null),
    }),
  }
);
const V6SecretKeyProtection: P.CoderType<V6SecretKeyProtectionType> = /* @__PURE__ */ P.apply<
  V6SecretKeyProtectionRawType,
  V6SecretKeyProtectionType
>(V6SecretKeyProtectionRaw, {
  encode: (from) =>
    from.TAG === 'aead'
      ? { TAG: 'aead', data: { ...from.data.params, secret: from.data.secret } }
      : from.TAG === 'encrypted'
        ? { TAG: 'encrypted', data: { ...from.data.params, secret: from.data.secret } }
        : from,
  decode: (value) => {
    if (value.TAG === 'plain') return value;
    if (value.TAG === 'encrypted') {
      const { enc, S2K, iv, secret } = value.data;
      return { TAG: 'encrypted' as const, data: { params: { enc, S2K, iv }, secret } };
    }
    if (value.TAG === 'aead') {
      const { enc, aead, S2K, iv, secret } = value.data;
      return { TAG: 'aead' as const, data: { params: { enc, aead, S2K, iv }, secret } };
    }
    throw new Error('PGP.secretKey: v6 allows only usage 0, 253, or 254');
  },
});

const SecretKeyPacketRaw = /* @__PURE__ */ P.tag(PubKeyVersion, {
  v4: /* @__PURE__ */ P.struct({
    created: P.U32BE,
    algo: PublicKeyMaterial,
    type: SecretKeyProtection,
  }),
  v6: /* @__PURE__ */ P.struct({
    created: P.U32BE,
    algo: V6PublicKeyMaterial,
    type: V6SecretKeyProtection,
  }),
});
// NOTE: SecretKey is specific packet type as per spec. For user facing API we using 'privateKey'
const SecretKeyPacket: P.CoderType<{ pub: PubKeyPacketType; type: SecretKeyProtectionType }> =
  /* @__PURE__ */ P.apply<
    P.UnwrapCoder<typeof SecretKeyPacketRaw>,
    { pub: PubKeyPacketType; type: SecretKeyProtectionType }
  >(SecretKeyPacketRaw, {
    encode: (from) => ({
      pub: {
        version: from.TAG === 'v6' ? 6 : undefined,
        created: from.data.created,
        algo: from.data.algo,
      },
      type: from.data.type,
    }),
    decode: (key): P.UnwrapCoder<typeof SecretKeyPacketRaw> => {
      const base = { created: key.pub.created, algo: key.pub.algo };
      if (key.pub.version === 6)
        return { TAG: 'v6', data: { ...base, type: key.type as V6SecretKeyProtectionType } };
      return { TAG: 'v4', data: { ...base, type: key.type as V4SecretKeyProtectionType } };
    },
  });
type SecretKeyType = P.UnwrapCoder<typeof SecretKeyPacket>;

// https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.1
// Packet registry is broader than the current signing surface: this module
// emits `binary` detached signatures and `certPositive` / `subkeyBinding` key
// material, but still needs the wider map to parse existing packets.
const SigTypeEnum = /* @__PURE__ */ P.map(P.U8, {
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

const AEADCiphersuite: P.CoderType<{ enc: string; aead: string }> = /* @__PURE__ */ P.struct({
  enc: EncryptionEnum,
  aead: AEADEnum,
});
const FingerprintVersion = /* @__PURE__ */ P.map(P.U8, { v4: 4, v6: 6 });
const FingerprintSubpacketRaw = /* @__PURE__ */ P.tag(FingerprintVersion, {
  v4: /* @__PURE__ */ P.hex(20),
  v6: /* @__PURE__ */ P.hex(32),
});
type FingerprintSubpacketType = { version?: undefined | 6; fingerprint: string };
const FingerprintSubpacket: P.CoderType<{ version?: undefined | 6; fingerprint: string }> =
  /* @__PURE__ */ P.apply<P.UnwrapCoder<typeof FingerprintSubpacketRaw>, FingerprintSubpacketType>(
    FingerprintSubpacketRaw,
    {
      encode: (from) => ({
        version: from.TAG === 'v6' ? 6 : undefined,
        fingerprint: from.data,
      }),
      decode: (value) => {
        // RFC 9580 §5.2.3.35: Issuer/Recipient Fingerprint uses key version
        // plus a v4 20-octet or v6 32-octet fingerprint.
        return {
          TAG: value.version === 6 ? ('v6' as const) : ('v4' as const),
          data: value.fingerprint,
        };
      },
    }
  );
const FeatureBits = /* @__PURE__ */ P.bitset([
  '_r4',
  '_r3',
  '_r2',
  '_r1',
  'v2SEIPD',
  'v5Keys',
  'aead',
  'v1SEIPD',
]);
const Features: P.CoderType<Record<string, boolean>> = /* @__PURE__ */ P.apply<
  P.UnwrapCoder<typeof FeatureBits>,
  Record<string, boolean>
>(FeatureBits, {
  encode: (value) => ({
    modDetect: !!value.v1SEIPD,
    aead: !!value.aead,
    v5Keys: !!value.v5Keys,
    v2SEIPD: !!value.v2SEIPD,
  }),
  decode: (value) => {
    // RFC 9580 §5.2.3.25 uses feature bit 0 for v1 SEIPD and bit 3
    // for v2 SEIPD; older local output names bit 0 `modDetect`.
    return {
      v1SEIPD: !!(value.modDetect || value.v1SEIPD),
      aead: !!value.aead,
      v5Keys: !!value.v5Keys,
      v2SEIPD: !!value.v2SEIPD,
    };
  },
});
type SignatureSubpacketBodyType =
  | { TAG: 'issuerFingerprint'; data: { version?: undefined | 6; fingerprint: string } }
  | { TAG: 'intendedRecipientFingerprint'; data: { version?: undefined | 6; fingerprint: string } }
  | { TAG: 'signatureCreationTime'; data: number }
  | { TAG: 'signatureExpirationTime'; data: number }
  | { TAG: 'exportableCertification'; data: boolean }
  | { TAG: 'revocable'; data: boolean }
  | { TAG: 'keyExpirationTime'; data: number }
  | { TAG: 'revocationKey'; data: { class: number; algo: string; fingerprint: string } }
  | { TAG: 'notationData'; data: { humanReadable: boolean; name: string; value: Uint8Array } }
  | { TAG: 'keyFlags'; data: Record<string, boolean> }
  | { TAG: 'preferredEncryptionAlgorithms'; data: string[] }
  | { TAG: 'preferredHashAlgorithms'; data: string[] }
  | { TAG: 'preferredCompressionAlgorithms'; data: string[] }
  | { TAG: 'preferredAEADAlgorithms'; data: string[] }
  | { TAG: 'preferredAEADCiphersuites'; data: P.UnwrapCoder<typeof AEADCiphersuite>[] }
  | { TAG: 'features'; data: Record<string, boolean> }
  | { TAG: 'keyServerPreferences'; data: Record<string, boolean> }
  | { TAG: 'preferredKeyServer'; data: string }
  | { TAG: 'policyURI'; data: string }
  | { TAG: 'issuer'; data: string }
  | { TAG: 'primaryUserID'; data: boolean }
  | { TAG: 'signersUserID'; data: string }
  | { TAG: 'reasonForRevocation'; data: { code: number; reason: string } }
  | { TAG: 'embeddedSignature'; data: SignaturePacketType };
type SignatureSubpacketType = SignatureSubpacketBodyType & { critical?: boolean };
type SignatureSubpacketRawType = { critical: number; body: SignatureSubpacketBodyType };
const SignatureSubpacket: P.CoderType<SignatureSubpacketType> = /* @__PURE__ */ (() => {
  // https://datatracker.ietf.org/doc/html/rfc4880.html#section-5.2.3.1
  const tags = {
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
    issuerFingerprint: 33,
    // RFC 9580 Table 5 reserves type 34, but existing package self-signatures
    // use this old OpenPGP/GnuPG-compatible AEAD preference tag. Keep it for
    // decoding and unchanged output; new RFC 9580 data uses type 39 below.
    preferredAEADAlgorithms: 34,
    intendedRecipientFingerprint: 35,
    preferredAEADCiphersuites: 39,
  };
  const tag = /* @__PURE__ */ P.map(P.bits(7), tags);
  const notationHuman = 0x80000000;
  const NotationData = /* @__PURE__ */ P.apply<
    { flags: number; nameLen: number; valueLen: number; name: string; value: Uint8Array },
    { humanReadable: boolean; name: string; value: Uint8Array }
  >(
    /* @__PURE__ */ P.struct({
      flags: P.U32BE,
      nameLen: P.U16BE,
      valueLen: P.U16BE,
      name: /* @__PURE__ */ P.apply(/* @__PURE__ */ P.bytes('nameLen'), utf8),
      value: /* @__PURE__ */ P.bytes('valueLen'),
    }),
    {
      encode: (raw) => {
        // RFC 9580 §5.2.3.24 defines only the 0x80000000 human-readable
        // notation flag; all other notation flags MUST be zero.
        if (raw.flags !== 0 && raw.flags !== notationHuman)
          throw new Error('notationData: undefined flags must be zero');
        return {
          humanReadable: raw.flags === notationHuman,
          name: raw.name,
          value: raw.value,
        };
      },
      decode: (from) => ({
        flags: from.humanReadable ? notationHuman : 0,
        // The `name` field codec already handles UTF-8; this is only the
        // RFC 9580 §5.2.3.24 encoded-octet count stored before the field.
        nameLen: utf8.decode(from.name).length,
        valueLen: from.value.length,
        name: from.name,
        value: from.value,
      }),
    }
  );
  const body: P.CoderType<SignatureSubpacketBodyType> = /* @__PURE__ */ P.tag(tag, {
    issuerFingerprint: FingerprintSubpacket,
    intendedRecipientFingerprint: FingerprintSubpacket,
    signatureCreationTime: P.U32BE,
    // RFC 9580 §5.2.3.18 defines Signature Expiration Time as a 4-octet time field.
    signatureExpirationTime: P.U32BE,
    // RFC 9580 §5.2.3.19 defines Exportable Certification as a 1-octet
    // Boolean. GnuPG 2.4.7 emits local certifications as non-critical
    // subpacket 4, despite RFC 9580 requiring critical generation when false.
    exportableCertification: P.bool,
    // RFC 9580 §5.2.3.20 defines Revocable as a 1-octet Boolean.
    revocable: P.bool,
    // RFC 9580 §5.2.3.13 defines Key Expiration Time as a 4-octet time field;
    // GnuPG 2.4.7 emits it on generated keys with an expiration date.
    keyExpirationTime: P.U32BE,
    keyFlags: /* @__PURE__ */ P.bitset([
      '_r',
      'shared',
      'auth',
      'split',
      'encrypt',
      'encryptComm',
      'sign',
      'certify',
    ]),
    preferredEncryptionAlgorithms: /* @__PURE__ */ P.array(null, EncryptionEnum),
    preferredHashAlgorithms: /* @__PURE__ */ P.array(null, HashEnum),
    preferredCompressionAlgorithms: /* @__PURE__ */ P.array(null, CompressionEnum),
    preferredAEADAlgorithms: /* @__PURE__ */ P.array(null, AEADEnum),
    // RFC 9580 §5.2.3.23 deprecates Revocation Key and says applications MUST
    // NOT generate it, but GnuPG 2.4.7 still emits it for `--add-desig-revoker`.
    revocationKey: /* @__PURE__ */ P.struct({
      class: P.U8,
      algo: pubKeyEnum,
      fingerprint: /* @__PURE__ */ P.hex(20),
    }),
    // RFC 9580 §5.2.3.24: Notation Data is flags plus name/value octet strings;
    // GnuPG emits this subpacket for `--sig-notation`.
    notationData: NotationData,
    // RFC 9580 §5.2.3.15: final AEAD preferences are ordered
    // (symmetric-cipher, AEAD-mode) pairs under subpacket type 39.
    preferredAEADCiphersuites: /* @__PURE__ */ P.array(null, AEADCiphersuite),
    features: Features,
    keyServerPreferences: /* @__PURE__ */ P.bitset(['modDetect'], true),
    // RFC 9580 §5.2.3.26 defines Preferred Key Server as a String.
    preferredKeyServer: /* @__PURE__ */ P.string(null),
    // RFC 9580 §5.2.3.28 defines Policy URI as a String.
    policyURI: /* @__PURE__ */ P.string(null),
    issuer: /* @__PURE__ */ P.hex(8),
    primaryUserID: P.bool,
    // RFC 9580 §5.2.3.30 defines Signer's User ID subpacket 28 as String;
    // GnuPG 2.4.7 emits it on detached signatures from generated keys.
    signersUserID: /* @__PURE__ */ P.string(null),
    // RFC 9580 §5.2.3.31 defines Reason for Revocation as one code octet
    // plus a UTF-8 reason string; GnuPG emits it in generated revocation certs.
    reasonForRevocation: /* @__PURE__ */ P.struct({
      code: P.U8,
      reason: /* @__PURE__ */ P.apply(/* @__PURE__ */ P.bytes(null), utf8),
    }),
    // RFC 9580 §5.2.3.34 defines Embedded Signature as one complete Signature
    // packet body; GnuPG emits this back-signature for signing subkeys.
    embeddedSignature: /* @__PURE__ */ P.lazy(() => SignaturePacket),
  });
  return /* @__PURE__ */ P.prefix(
    SignatureSubpacketLen,
    /* @__PURE__ */ P.apply<SignatureSubpacketRawType, SignatureSubpacketType>(
      /* @__PURE__ */ P.struct({
        // RFC 4880 §5.2.3.1 / RFC 9580 §5.2.3.7: bit 7 is the critical flag;
        // bits 6-0 are the real subpacket type id.
        critical: P.bits(1),
        body,
      }),
      {
        encode: (raw) =>
          raw.critical ? ({ ...raw.body, critical: true } as SignatureSubpacketType) : raw.body,
        decode: (value) => {
          const { critical, ...body } = value;
          return { critical: critical ? 1 : 0, body: body as SignatureSubpacketBodyType };
        },
      }
    )
  );
})();
const SignatureSubpacketArray = /* @__PURE__ */ P.array(null, SignatureSubpacket);
// Preserve the raw ordered subpacket list here; RFC 9580 §5.2.3.9 leaves
// duplicate/conflicting-subpacket resolution to higher-level signature
// processing rather than this container coder.
const SignatureSubpackets = /* @__PURE__ */ P.prefix(P.U16BE, SignatureSubpacketArray);
const SignatureSubpacketsV6 = /* @__PURE__ */ P.prefix(P.U32BE, SignatureSubpacketArray);

type SignatureHeadType = {
  version?: undefined | 6;
  type: string;
  algo: string;
  hash: string;
  hashed: SignatureSubpacketType[];
};
const SignatureVersion = /* @__PURE__ */ P.map(P.U8, { v4: 4, v6: 6 });
const SignatureHeadRawInner = /* @__PURE__ */ P.tag(SignatureVersion, {
  v4: /* @__PURE__ */ P.struct({
    type: SigTypeEnum,
    algo: pubKeyEnum,
    hash: HashEnum,
    hashed: SignatureSubpackets,
  }),
  // RFC 9580 §5.2.3 / §5.2.3.7: v4 signatures use 2-octet
  // subpacket-set counts, while v6 uses 4-octet counts.
  v6: /* @__PURE__ */ P.struct({
    type: SigTypeEnum,
    algo: pubKeyEnum,
    hash: HashEnum,
    hashed: SignatureSubpacketsV6,
  }),
});
const SignatureHeadRaw: P.CoderType<SignatureHeadType> = /* @__PURE__ */ P.apply<
  P.UnwrapCoder<typeof SignatureHeadRawInner>,
  SignatureHeadType
>(SignatureHeadRawInner, {
  encode: (from) =>
    from.TAG === 'v6' ? { version: 6, ...from.data } : { version: undefined, ...from.data },
  decode: (head) => ({
    TAG: head.version === 6 ? ('v6' as const) : ('v4' as const),
    data: { type: head.type, algo: head.algo, hash: head.hash, hashed: head.hashed },
  }),
});
const validateFingerprintSubpacketVersions = (
  version: undefined | 6,
  subpackets: TArg<SignatureSubpacketType[]>
) => {
  for (const subpacket of subpackets) {
    if (subpacket.TAG !== 'issuerFingerprint' && subpacket.TAG !== 'intendedRecipientFingerprint')
      continue;
    // RFC 9580 §5.2.3.35 requires issuer-fingerprint version to match the
    // signature version; §5.2.3.36 uses the same versioned fingerprint shape.
    if (subpacket.data.version !== version)
      throw new Error('PGP.Signature: fingerprint subpacket version mismatch');
  }
};
const validateSignatureHead = (head: TArg<SignatureHeadType>) => {
  // RFC 4880 §5.2.3.4 and RFC 9580 §5.2.3.11 require Signature Creation
  // Time in the hashed area. GnuPG 2.4.7 verifies missing-SCT signatures
  // for compatibility but does not generate them, so keep this parser strict.
  if (!head.hashed.some((subpacket) => subpacket.TAG === 'signatureCreationTime'))
    throw new Error('PGP.SignatureHead: missing hashed Signature Creation Time');
  validateFingerprintSubpacketVersions(head.version, head.hashed);
  return head;
};
const SignatureHead: P.CoderType<SignatureHeadType> = /* @__PURE__ */ P.validate(
  SignatureHeadRaw,
  validateSignatureHead
);
const V6SignatureSaltLen: Record<string, number> = {
  sha224: 16,
  sha256: 16,
  sha384: 24,
  sha512: 32,
  sha3_256: 16,
  sha3_512: 32,
};
const v6SignatureSaltLen = (hash: string) => {
  // RFC 9580 §5.2.3 and §9.5 Table 23 fix v6 signature salt length by hash algorithm.
  const len = V6SignatureSaltLen[hash];
  if (len === undefined) throw new Error(`PGP.Signature: hash ${hash} has no v6 salt length`);
  return len;
};
const v6SignatureLen = (algo: string) => {
  // RFC 9580 §5.2.3.4 and §5.2.3.5 store v6 Ed25519/Ed448 signatures
  // as raw native octets, not MPIs.
  if (algo === 'Ed25519') return 64;
  if (algo === 'Ed448') return 114;
  throw new Error(`PGP.Signature: unsupported v6 signature algorithm=${algo}`);
};
type SignaturePacketType = {
  head: SignatureHeadType;
  unhashed: SignatureSubpacketType[];
  hashPrefix: Bytes;
  salt?: Bytes;
  sig: bigint[] | Bytes;
};
const V6SignatureHash = /* @__PURE__ */ P.apply<string, { hash: string; saltLen: number }>(
  HashEnum,
  {
    encode: (hash) => ({ hash, saltLen: v6SignatureSaltLen(hash) }),
    decode: (from) => from.hash,
  }
);
const V6SignatureAlgo = /* @__PURE__ */ P.apply<string, { algo: string; sigLen: number }>(
  pubKeyEnum,
  {
    encode: (algo) => ({ algo, sigLen: v6SignatureLen(algo) }),
    decode: (from) => from.algo,
  }
);
const V6SignaturePacketBodyRaw = /* @__PURE__ */ P.validate(
  /* @__PURE__ */ P.struct({
    type: SigTypeEnum,
    algo: V6SignatureAlgo,
    hash: V6SignatureHash,
    hashed: SignatureSubpacketsV6,
    unhashed: SignatureSubpacketsV6,
    hashPrefix: /* @__PURE__ */ P.bytes(2),
    saltLen: P.U8,
    salt: /* @__PURE__ */ P.bytes('saltLen'),
    sig: /* @__PURE__ */ P.bytes('algo/sigLen'),
  }),
  (packet) => {
    if (packet.saltLen !== packet.hash.saltLen)
      throw new Error('PGP.Signature: wrong v6 salt length');
    return packet;
  }
);
const V6SignaturePacketBody = /* @__PURE__ */ P.apply(V6SignaturePacketBodyRaw, {
  encode: (packet) => ({
    type: packet.type,
    algo: packet.algo.algo,
    hash: packet.hash.hash,
    hashed: packet.hashed,
    unhashed: packet.unhashed,
    hashPrefix: packet.hashPrefix,
    salt: packet.salt,
    sig: packet.sig,
  }),
  decode: (packet) => ({
    type: packet.type,
    algo: { algo: packet.algo, sigLen: v6SignatureLen(packet.algo) },
    hash: { hash: packet.hash, saltLen: v6SignatureSaltLen(packet.hash) },
    hashed: packet.hashed,
    unhashed: packet.unhashed,
    hashPrefix: packet.hashPrefix,
    saltLen: packet.salt.length,
    salt: packet.salt,
    sig: packet.sig,
  }),
});
const SignaturePacketRaw = /* @__PURE__ */ P.tag(SignatureVersion, {
  v4: /* @__PURE__ */ P.struct({
    type: SigTypeEnum,
    algo: pubKeyEnum,
    hash: HashEnum,
    hashed: SignatureSubpackets,
    unhashed: SignatureSubpackets,
    hashPrefix: /* @__PURE__ */ P.bytes(2),
    sig: /* @__PURE__ */ P.array(2, mpi),
  }),
  v6: V6SignaturePacketBody,
});
const SignaturePacket: P.CoderType<SignaturePacketType> = /* @__PURE__ */ P.validate(
  /* @__PURE__ */ P.apply<P.UnwrapCoder<typeof SignaturePacketRaw>, SignaturePacketType>(
    SignaturePacketRaw,
    {
      encode: (from) => ({
        head: {
          version: from.TAG === 'v6' ? 6 : undefined,
          type: from.data.type,
          algo: from.data.algo,
          hash: from.data.hash,
          hashed: from.data.hashed,
        },
        unhashed: from.data.unhashed,
        hashPrefix: from.data.hashPrefix,
        ...(from.TAG === 'v6'
          ? { salt: from.data.salt, sig: from.data.sig }
          : { sig: from.data.sig }),
      }),
      decode: (sig) => {
        const head = sig.head;
        const base = {
          type: head.type,
          algo: head.algo,
          hash: head.hash,
          hashed: head.hashed,
          unhashed: sig.unhashed,
          hashPrefix: sig.hashPrefix,
        };
        if (head.version !== 6)
          return { TAG: 'v4' as const, data: { ...base, sig: sig.sig as bigint[] } };
        const salt = sig.salt;
        if (!salt || !isBytes(sig.sig)) throw new Error('PGP.Signature: invalid v6 signature');
        return { TAG: 'v6' as const, data: { ...base, salt, sig: sig.sig } };
      },
    }
  ),
  (sig) => {
    validateSignatureHead(sig.head);
    validateFingerprintSubpacketVersions(sig.head.version, sig.unhashed);
    return sig;
  }
);

type SignatureType = P.UnwrapCoder<typeof SignaturePacket>;

type OnePassSignaturePacketType =
  | {
      version?: undefined;
      type: string;
      hash: string;
      algo: string;
      keyId: string;
      last: boolean;
    }
  | {
      version: 6;
      type: string;
      hash: string;
      algo: string;
      salt: Bytes;
      fingerprint: string;
      last: boolean;
    };
const OnePassSignatureVersion = /* @__PURE__ */ P.map(P.U8, { v3: 3, v6: 6 });
const OnePassSignaturePacketRaw = /* @__PURE__ */ P.tag(OnePassSignatureVersion, {
  v3: /* @__PURE__ */ P.struct({
    type: SigTypeEnum,
    hash: HashEnum,
    algo: pubKeyEnum,
    keyId: /* @__PURE__ */ P.hex(8),
    last: P.bool,
  }),
  v6: /* @__PURE__ */ P.struct({
    type: SigTypeEnum,
    hash: HashEnum,
    algo: pubKeyEnum,
    // RFC 9580 §5.4: v6 OPS carries salt and a fixed 32-octet fingerprint
    // instead of the v3 8-octet Key ID.
    salt: /* @__PURE__ */ P.bytes(P.U8),
    fingerprint: /* @__PURE__ */ P.hex(32),
    last: P.bool,
  }),
});
const OnePassSignaturePacket: P.CoderType<OnePassSignaturePacketType> = /* @__PURE__ */ P.validate(
  /* @__PURE__ */ P.apply<
    P.UnwrapCoder<typeof OnePassSignaturePacketRaw>,
    OnePassSignaturePacketType
  >(OnePassSignaturePacketRaw, {
    encode: (from) =>
      from.TAG === 'v6' ? { version: 6, ...from.data } : { version: undefined, ...from.data },
    decode: (packet) => {
      if (packet.version === 6) {
        const v6 = packet as Extract<OnePassSignaturePacketType, { version: 6 }>;
        return {
          TAG: 'v6' as const,
          data: {
            type: v6.type,
            hash: v6.hash,
            algo: v6.algo,
            salt: v6.salt,
            fingerprint: v6.fingerprint,
            last: v6.last,
          },
        };
      }
      const v3 = packet as Extract<OnePassSignaturePacketType, { keyId: string }>;
      return {
        TAG: 'v3' as const,
        data: {
          type: v3.type,
          hash: v3.hash,
          algo: v3.algo,
          keyId: v3.keyId,
          last: v3.last,
        },
      };
    },
  }),
  (packet) => {
    if (packet.version === 6 && packet.salt.length !== v6SignatureSaltLen(packet.hash))
      throw new Error('PGP.OnePassSignature: invalid v6 salt length');
    return packet;
  }
);

// RFC 4880 §5.11 / RFC 9580 §5.11 require UTF-8 text here; the shared string
// coder is intentionally used only where malformed UTF-8 already rejects.
const UserPacket = /* @__PURE__ */ P.string(null);
const LiteralFormatEnum = /* @__PURE__ */ P.map(P.U8, {
  binary: 0x62,
  text: 0x74,
  utf8: 0x75,
});
type LiteralDataPacketType = {
  format: string;
  filename: string;
  created: number;
  data: Bytes;
};
const LiteralDataPacket: P.CoderType<LiteralDataPacketType> = /* @__PURE__ */ P.struct({
  // RFC 9580 §5.9: Literal Data is format octet, one-octet filename
  // length/name, timestamp, then literal bytes.
  format: LiteralFormatEnum,
  filename: /* @__PURE__ */ P.string(P.U8),
  created: P.U32BE,
  data: /* @__PURE__ */ P.bytes(null),
});
type PKESKFingerprintType = { version?: undefined | 6; fingerprint: string } | undefined;
const PKESKFingerprintRaw = /* @__PURE__ */ P.mappedTag(P.U8, {
  none: [0, /* @__PURE__ */ P.bytes(0)],
  v4: [21, FingerprintSubpacket],
  v6: [33, FingerprintSubpacket],
});
const PKESKFingerprint: P.CoderType<PKESKFingerprintType> = /* @__PURE__ */ P.apply<
  P.UnwrapCoder<typeof PKESKFingerprintRaw>,
  PKESKFingerprintType
>(PKESKFingerprintRaw, {
  encode: (raw) => (raw.TAG === 'none' ? undefined : raw.data),
  decode: (value) =>
    value
      ? { TAG: value.version === 6 ? ('v6' as const) : ('v4' as const), data: value }
      : { TAG: 'none' as const, data: Uint8Array.of() },
});
type PublicKeyEncryptedSessionKeyPacketType = {
  version: 6;
  fingerprint?: PKESKFingerprintType;
  algo: string;
  ephemeral: Bytes;
  encryptedSessionKey: Bytes;
};
const PublicKeyEncryptedSessionKeyPacket: P.CoderType<PublicKeyEncryptedSessionKeyPacketType> =
  /* @__PURE__ */ P.apply(
    /* @__PURE__ */ P.struct({
      version: /* @__PURE__ */ P.magic(P.U8, 6),
      fingerprint: PKESKFingerprint,
      algo: /* @__PURE__ */ P.magic(pubKeyEnum, 'X25519'),
      // RFC 9580 §5.1.6: X25519 PKESK uses a 32-octet ephemeral key plus a
      // one-octet encrypted-session-key length.
      ephemeral: /* @__PURE__ */ P.bytes(32),
      encryptedSessionKey: /* @__PURE__ */ P.bytes(P.U8),
    }),
    {
      encode: (from) => ({ ...from, version: 6, algo: 'X25519' }),
      decode: (value) => {
        if (value.version !== 6) throw new Error('PGP.PKESK: only v6 packets are supported');
        if (value.algo !== 'X25519')
          throw new Error(`PGP.PKESK: unsupported algorithm=${value.algo}`);
        return {
          version: undefined,
          fingerprint: value.fingerprint,
          algo: undefined,
          ephemeral: value.ephemeral,
          encryptedSessionKey: value.encryptedSessionKey,
        };
      },
    }
  );

// PGP Functions
// RFC 4880 §3.7.1.3 / RFC 9580 §3.7.1.3: decode the 1-octet iterated-S2K
// count into the total octet count hashed.
const EXPBIAS6 = (count: number) => (16 + (count & 15)) << ((count >> 4) + 6);

function deriveKey(
  hash: string,
  len: number,
  password: TArg<Bytes>,
  salt?: TArg<Bytes>,
  count?: number
): TRet<Bytes> {
  // Important: there is difference between zero and empty count
  count = count === undefined ? 0 : EXPBIAS6(count);
  const data = salt ? concatBytes(salt, password) : password;
  let out: Uint8Array = Uint8Array.of();
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
    // RFC 4880 §3.7.1.1 / RFC 9580 §3.7.1.1 require concatenating
    // multiple hash outputs left-to-right when one digest is shorter than the key.
    out = concatBytes(out, h.digest());
  }
  return out.subarray(0, len) as TRet<Bytes>;
}
function deriveS2KKey(S2K: TArg<S2KType>, len: number, password: TArg<Bytes>): TRet<Bytes> {
  const s2kRaw = S2K as S2KType;
  if (s2kRaw.TAG === 'argon2') {
    const { salt, t, p, encodedM } = s2kRaw.data;
    // RFC 9580 §3.7.1.4 invokes Argon2id with passphrase P, salt S,
    // t/p, memory m=2^encoded_m KiB, version 0x13, and output length T.
    return argon2id(password, salt, {
      t,
      p,
      m: 2 ** encodedM,
      version: 0x13,
      dkLen: len,
    }) as TRet<Bytes>;
  }
  const s2k = s2kRaw.data;
  return deriveKey(
    s2k.hash,
    len,
    password,
    'salt' in s2k ? s2k.salt : undefined,
    'count' in s2k ? s2k.count : undefined
  );
}

// Concrete secret-key-packet encryption support is the AES-CFB subset here;
// broader on-wire cipher registries are modeled separately by `EncryptionEnum`
// / `EncryptionKeySize`.
const Encryption: Record<string, ReturnType<typeof createAesCfb>> = {
  aes128: /* @__PURE__ */ createAesCfb(128),
  aes192: /* @__PURE__ */ createAesCfb(192),
  aes256: /* @__PURE__ */ createAesCfb(256),
};

const hashPubKeyRaw = /* @__PURE__ */ P.tag(/* @__PURE__ */ P.map(P.U8, { v4: 0x99, v6: 0x9b }), {
  // RFC 4880 §12.2 / RFC 9580 §5.5.4.2: version-4 fingerprints hash
  // `0x99 || U16BE(len) || Public-Key packet body`.
  v4: /* @__PURE__ */ P.prefix(P.U16BE, PubKeyPacketCoder),
  // RFC 9580 §5.5.4.3: v6 fingerprints and signature key-hash inputs use
  // 0x9B plus a 4-octet packet-body length.
  v6: /* @__PURE__ */ P.prefix(P.U32BE, PubKeyPacketCoder),
});
const hashPubKey: P.CoderType<PubKeyPacketType> = /* @__PURE__ */ P.apply<
  P.UnwrapCoder<typeof hashPubKeyRaw>,
  PubKeyPacketType
>(hashPubKeyRaw, {
  encode: (from) => from.data,
  decode: (pubKey) =>
    ({
      TAG: pubKey.version === 6 ? ('v6' as const) : ('v4' as const),
      data: pubKey,
    }) as P.UnwrapCoder<typeof hashPubKeyRaw>,
});

type HashUserData = { user: string };
const hashUser: P.CoderType<HashUserData> = /* @__PURE__ */ P.struct({
  // RFC 4880 §5.2.4 / RFC 9580 §5.2.4: User ID certifications hash
  // `0xB4 || U32BE(len) || User ID data`.
  magic: /* @__PURE__ */ P.magic(/* @__PURE__ */ P.hex(1), 'b4'),
  user: /* @__PURE__ */ P.prefix(P.U32BE, UserPacket),
});

type SelfCertData = { pubKey: PubKeyPacketType; user: HashUserData };
type SubKeyCertData = { pubKey: PubKeyPacketType; subKey: PubKeyPacketType };
// RFC 4880 §5.2.4 / RFC 9580 §5.2.4: self-certification hash input is the
// primary-key fingerprint wrapper followed by the bound User ID wrapper.
const hashSelfCert: P.CoderType<SelfCertData> = /* @__PURE__ */ P.struct({
  pubKey: hashPubKey,
  user: hashUser,
});
// RFC 4880 §5.2.4 / RFC 9580 §5.2.4: subkey-binding hash input is the
// primary-key fingerprint wrapper followed by the bound subkey wrapper.
const hashSubKeyCert: P.CoderType<SubKeyCertData> = /* @__PURE__ */ P.struct({
  pubKey: hashPubKey,
  subKey: hashPubKey,
});
type SignatureData = SelfCertData | PubKeyPacketType | SubKeyCertData | Bytes | string;

function hashSignature(
  head: TArg<SignatureHeadType>,
  data: TArg<SignatureData>,
  salt?: TArg<Bytes>
): TRet<Bytes> {
  const hashC = Hash[head.hash];
  if (!hashC) throw new Error('PGP.hashSignature: unknown hash');
  const h = hashC.create();
  // RFC 9580 §5.2.4 feeds v6 signature salt into the hash context before any
  // other data; v4 signatures have no salt field.
  if (head.version === 6) {
    if (!salt || salt.length !== v6SignatureSaltLen(head.hash))
      throw new Error('PGP.hashSignature: invalid v6 salt');
    h.update(salt);
  }
  if (['certGeneric', 'certPersona', 'certCasual', 'certPositive'].includes(head.type))
    h.update(hashSelfCert.encode(data as SelfCertData));
  else if (head.type === 'key') h.update(hashPubKey.encode(data as PubKeyPacketType));
  else if (head.type === 'subkeyBinding') h.update(hashSubKeyCert.encode(data as SubKeyCertData));
  else if (head.type === 'binary') {
    if (!isBytes(data)) throw new Error('hashSignature: wrong data for type=binary');
    h.update(data);
  } else if (head.type === 'text') {
    // For text document signatures (type 0x01), the
    // document is canonicalized by converting line endings to <CR><LF>,
    // and the resulting data is hashed
    // RFC 4880 §5.2.4 / RFC 9580 §5.2.4 canonicalize existing line endings
    // only; an unterminated final line must stay unterminated.
    if (typeof data !== 'string') throw new Error('hashSignature: wrong data for type=text');
    const NL = '\r\n';
    let canonical = data.replace(/\r\n|\n|\r/g, NL);
    h.update(utf8.decode(canonical));
  } else throw new Error('Unknown signature type');
  const sigData = SignatureHead.encode(head);
  // RFC 4880 §5.2.4 / RFC 9580 §5.2.4: v4/v6 signature trailers append the
  // signature version and `0xff` before the 4-octet hashed-body length.
  h.update(sigData)
    .update(Uint8Array.from([head.version === 6 ? 6 : 4, 0xff]))
    .update(P.U32BE.encode(sigData.length));
  return h.digest() as TRet<Bytes>;
}

// https://datatracker.ietf.org/doc/html/rfc4880#section-6.1
function crc24(data: TArg<Bytes>) {
  let crc = 0xb704ce;
  for (let i = 0; i < data.length; i++) {
    crc ^= data[i] << 16;
    for (let j = 0; j < 8; j++) {
      crc <<= 1;
      if (crc & 0x1000000) crc ^= 0x1864cfb;
    }
  }
  // RFC 4880 §6.1 / §6.2 armor appends the CRC as raw 24-bit big-endian
  // bytes, not as an integer or base64 text here.
  return new Uint8Array([(crc >> 16) & 0xff, (crc >> 8) & 0xff, crc & 0xff]);
}
// RFC 4880 §6 defines ASCII armor as base64 plus a CRC24 checksum, while
// RFC 9580 §6.1 says recipients MUST NOT reject solely on absent/mismatched
// CRC24. Keep decoding strict anyway: GnuPG 2.4.7 rejects malformed CRC24,
// and a bad armor checksum is a cheap signal that the transported text was
// corrupted before deeper packet/signature checks run.

const PacketTag: Record<string, number> = {
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
  padding: 21,
};
const packetTagId = (tag: string) => {
  const id = PacketTag[tag];
  if (id === undefined) throw new Error(`PGP.PacketHead: unknown tag=${tag}`);
  return id;
};
type PacketHeadType = {
  magic?: undefined;
  version?: undefined;
  tag: string;
  lenType?: number;
  newFormat?: boolean;
};
type PacketHeadRawType = {
  magic?: undefined;
  head:
    | { TAG: 'legacy'; data: { tag: string; lenType: number } }
    | { TAG: 'current'; data: { tag: string } };
};

const PartialDataPacketTags = /* @__PURE__ */ new Set([
  'literalData',
  'compressedData',
  'encryptedData',
  'encryptedProtectedData',
]);
const assertPartialDataPacket = (tag: string) => {
  if (!PartialDataPacketTags.has(tag))
    throw new Error('PGP.Packet: partial body lengths are only allowed for data packets');
};
type PacketData = {
  public_key_encrypted_session_key: PublicKeyEncryptedSessionKeyPacketType;
  symmetric_key_encrypted_session_key: SymmetricKeyEncryptedSessionKeyPacketType;
  userId: string;
  signature: SignaturePacketType;
  onePassSignature: OnePassSignaturePacketType;
  publicKey: PubKeyPacketType;
  publicSubkey: PubKeyPacketType;
  secretKey: SecretKeyType;
  secretSubkey: SecretKeyType;
  literalData: LiteralDataPacketType;
  encryptedProtectedData: Bytes;
  padding: Bytes;
};
type PacketHeader = { newFormat?: true; partialLengths?: number[] };
/** Parsed OpenPGP packet union used by the packet stream and ASCII armor helpers. */
export type Packet = {
  [K in keyof PacketData]: { TAG: K; data: PacketData[K] } & PacketHeader;
}[keyof PacketData];
type PacketCoderMap = { [K in keyof PacketData]: P.CoderType<PacketData[K]> };
const packetHead = (): P.CoderType<PacketHeadType> =>
  P.apply<PacketHeadRawType, PacketHeadType>(
    P.struct({
      magic: P.magic(P.bits(1), 1),
      head: P.mappedTag(P.bits(1), {
        legacy: [
          0,
          P.struct({
            tag: P.map(P.bits(4), PacketTag),
            lenType: P.bits(2),
          }),
        ],
        current: [1, P.struct({ tag: P.map(P.bits(6), PacketTag) })],
      }),
    }),
    {
      encode: (raw): PacketHeadType => {
        if (raw.head.TAG === 'current')
          return {
            magic: undefined,
            version: undefined,
            newFormat: true,
            tag: raw.head.data.tag,
          };
        return {
          magic: undefined,
          version: undefined,
          tag: raw.head.data.tag,
          lenType: raw.head.data.lenType,
        };
      },
      decode: (value) => {
        const tag = packetTagId(value.tag);
        const newFormat = !!value.newFormat || tag >= 16;
        // RFC 9580 §4.2: current OpenPGP headers set bits 7 and 6 and carry
        // a 6-bit Packet Type ID; legacy headers only have 4 tag bits and must
        // not be used for tags >= 16.
        if (newFormat)
          return {
            magic: undefined,
            head: { TAG: 'current', data: { tag: value.tag } },
          };
        const lenType = value.lenType;
        if (
          typeof lenType !== 'number' ||
          !Number.isSafeInteger(lenType) ||
          lenType < 0 ||
          lenType > 3
        )
          throw new Error(`PGP.PacketHead: invalid legacy length type=${lenType}`);
        return {
          magic: undefined,
          head: { TAG: 'legacy', data: { tag: value.tag, lenType } },
        };
      },
    }
  );
const LegacyPacketLen = [P.U8, P.U16BE, P.U32BE] as const;
const PacketCoder: P.CoderType<Packet> = /* @__PURE__ */ (() => {
  // Keep the body-coder registry local to Packet so single-coder exports like
  // PacketLen do not retain every packet coder in treeshake release checks.
  const head = packetHead();
  const PacketTags: PacketCoderMap = {
    public_key_encrypted_session_key: PublicKeyEncryptedSessionKeyPacket,
    symmetric_key_encrypted_session_key: SymmetricKeyEncryptedSessionKeyPacket,
    userId: UserPacket,
    signature: SignaturePacket,
    onePassSignature: OnePassSignaturePacket,
    publicKey: PubKeyPacketCoder,
    publicSubkey: PubKeyPacketCoder,
    secretKey: SecretKeyPacket,
    secretSubkey: SecretKeyPacket,
    literalData: LiteralDataPacket,
    // RFC 9580 §5.13 keeps the SEIPD body encrypted; this packet layer preserves
    // ciphertext bytes and leaves decryption/authentication to a future message API.
    encryptedProtectedData: P.bytes(null),
    // RFC 9580 §5.14 Padding packets contain random bytes and are ignored by
    // message processors; packet round-trip keeps the bytes unchanged.
    padding: P.bytes(null),
  };
  return P.wrap({
    encodeStream: (w: P.Writer, value: TArg<Packet>) => {
      const packet = value as Packet;
      const coder = PacketTags[packet.TAG] as P.CoderType<Packet['data']>;
      if (!coder) throw new Error(`PGP.Packet: unsupported packet tag=${packet.TAG}`);
      const data = coder.encode(packet.data);
      const newFormat =
        !!packet.newFormat || !!packet.partialLengths || packetTagId(packet.TAG) >= 16;
      const lenType = data.length < 2 ** 8 ? 0 : data.length < 2 ** 16 ? 1 : 2;
      head.encodeStream(w, { tag: packet.TAG, lenType, newFormat });
      if (newFormat) {
        if (!packet.partialLengths) {
          PacketLen.encodeStream(w, data.length);
          return w.bytes(data);
        }
        if (!packet.partialLengths.length)
          throw new Error('PGP.Packet: empty partial body length list');
        assertPartialDataPacket(packet.TAG);
        let pos = 0;
        for (let i = 0; i < packet.partialLengths.length; i++) {
          const len = packet.partialLengths[i];
          // RFC 9580 §4.2.1.4 encodes each partial body length as 1 << (octet & 0x1f);
          // preserve decoded chunk boundaries only when they still form that wire shape.
          if (!Number.isSafeInteger(len) || len <= 0 || len > 2 ** 30 || (len & (len - 1)) !== 0)
            throw new Error(`PGP.Packet: invalid partial body length=${len}`);
          if (i === 0 && len < 512)
            throw new Error('PGP.Packet: first partial body length must be at least 512');
          if (pos + len > data.length)
            throw new Error('PGP.Packet: partial body length exceeds data');
          w.byte(0xe0 | Math.log2(len));
          w.bytes(data.subarray(pos, pos + len));
          pos += len;
        }
        PacketLen.encodeStream(w, data.length - pos);
        return w.bytes(data.subarray(pos));
      }
      // Prefer definite legacy lengths; RFC 4880 says indeterminate-length
      // packets SHOULD NOT be generated when the boundary is known.
      LegacyPacketLen[lenType].encodeStream(w, data.length);
      w.bytes(data);
    },
    decodeStream: (r: P.Reader): TRet<Packet> => {
      const { tag, lenType, newFormat } = head.decodeStream(r);
      let body: Bytes;
      let partialLengths: number[] | undefined;
      if (newFormat) {
        const chunks: Bytes[] = [];
        const partial: number[] = [];
        while (true) {
          if (r.isEnd()) {
            if (partial.length)
              throw new Error('PGP.Packet: partial body lengths need a final definite length');
            throw new Error('PGP.Packet: missing packet body length');
          }
          const first = r.byte(true);
          if (first >= 224 && first < 255) {
            assertPartialDataPacket(tag);
            const len = 1 << (first & 0x1f);
            // RFC 9580 §4.2.1.4: partial body lengths are data-packet-only, and
            // the first partial length MUST be at least 512 octets.
            if (!partial.length && len < 512)
              throw new Error('PGP.Packet: first partial body length must be at least 512');
            r.byte();
            partial.push(len);
            chunks.push(r.bytes(len));
            continue;
          }
          const len = PacketLen.decodeStream(r);
          chunks.push(r.bytes(len));
          body = concatBytes(...chunks);
          if (partial.length) partialLengths = partial;
          break;
        }
      } else {
        if (typeof lenType !== 'number') throw new Error('PGP.PacketHead: missing length type');
        const packetLen = lenType !== 3 ? LegacyPacketLen[lenType].decodeStream(r) : r.leftBytes;
        body = r.bytes(packetLen);
      }
      const coder = PacketTags[tag as keyof PacketData] as P.CoderType<Packet['data']>;
      if (!coder) throw new Error(`PGP.Packet: unsupported packet tag=${tag}`);
      const packet = {
        TAG: tag,
        data: coder.decode(body),
      } as Packet;
      // RFC 9580 §4.2 has both legacy and current-format headers. Preserve the
      // decoded header form so RFC packet vectors can re-encode byte-for-byte.
      if (newFormat) packet.newFormat = true;
      if (partialLengths) packet.partialLengths = partialLengths;
      return packet as TRet<Packet>;
    },
  }) as unknown as P.CoderType<Packet>;
})();

const V2SEIPD = /* @__PURE__ */ P.validate(
  /* @__PURE__ */ P.struct({
    version: /* @__PURE__ */ P.magic(P.U8, 2),
    enc: EncryptionEnum,
    aead: AEADEnum,
    chunkSize: P.U8,
    salt: /* @__PURE__ */ P.bytes(32),
    encrypted: /* @__PURE__ */ P.bytes(null),
  }),
  (packet) => {
    // RFC 9580 §5.13.2: implementations MUST accept chunk size octets
    // 0..16 and MUST NOT generate larger chunk-size values.
    if (packet.chunkSize > 16) throw new Error('PGP.SEIPD: invalid v2 chunk size');
    return packet;
  }
);

const u64BE = (n: number) => {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error(`PGP.AEAD: invalid u64 value=${n}`);
  const res = new Uint8Array(8);
  new DataView(res.buffer).setBigUint64(0, BigInt(n), false);
  return res;
};
const packetInfo = (tag: string, version: number, enc: string, aead: string, chunkSize?: number) =>
  concatBytes(
    Uint8Array.of(0xc0 | packetTagId(tag), version),
    EncryptionEnum.encode(enc),
    AEADEnum.encode(aead),
    chunkSize === undefined ? Uint8Array.of() : Uint8Array.of(chunkSize)
  );
const unsupportedAEAD = (aead: string): Error | undefined => {
  if (aead === 'OCB')
    return new Error(
      'PGP.AEAD: OCB not implemented in noble-ciphers, available in awasm/noble. Worth considering backport.'
    );
  if (aead === 'EAX') return new Error('PGP.AEAD: EAX not implemented in noble-ciphers.');
  return;
};
const aeadDecrypt = (
  aead: string,
  key: TArg<Bytes>,
  nonce: TArg<Bytes>,
  aad: TArg<Bytes>,
  data: TArg<Bytes>
): TRet<Bytes> => {
  const unsupported = unsupportedAEAD(aead);
  if (unsupported) throw unsupported;
  if (aead === 'GCM') return gcm(key, nonce, aad).decrypt(data) as TRet<Bytes>;
  throw new Error(`PGP.AEAD: unknown mode=${aead}`);
};
function decryptV6PKESK(
  secretKey: TArg<Bytes>,
  packet: TArg<PublicKeyEncryptedSessionKeyPacketType>
): TRet<Bytes> {
  const pkesk = packet as PublicKeyEncryptedSessionKeyPacketType;
  if (pkesk.version !== 6) throw new Error('PGP.PKESK: expected v6 packet');
  if (pkesk.algo !== 'X25519') throw new Error(`PGP.PKESK: unsupported algorithm=${pkesk.algo}`);
  if (secretKey.length !== 32) throw new Error('PGP.PKESK: expected 32-byte X25519 secret key');
  if (pkesk.encryptedSessionKey.length < 16 || pkesk.encryptedSessionKey.length % 8)
    throw new Error('PGP.PKESK: invalid AES-KW payload length');
  const recipient = x25519.scalarMultBase(secretKey);
  const shared = x25519.scalarMult(secretKey, pkesk.ephemeral);
  // RFC 9580 §5.1.6: X25519 PKESK uses HKDF-SHA256 with no salt, info
  // "OpenPGP X25519", and IKM `ephemeral || recipient public || shared`,
  // then unwraps the session key with RFC 3394 AES-128 key wrap.
  const ikm = concatBytes(pkesk.ephemeral, recipient, shared);
  const kek = hkdf(sha256, ikm, undefined, utf8.decode('OpenPGP X25519'), 16);
  return aeskw(kek).decrypt(pkesk.encryptedSessionKey) as TRet<Bytes>;
}
function decryptV6SKESK(
  password: TArg<Bytes>,
  packet: TArg<V6SymmetricKeyEncryptedSessionKeyPacketType>
): TRet<Bytes> {
  const skesk = packet as V6SymmetricKeyEncryptedSessionKeyPacketType;
  if (skesk.version !== 6) throw new Error('PGP.SKESK: expected v6 packet');
  const keyLen = EncryptionKeySize[skesk.enc];
  if (!keyLen) throw new Error(`PGP.SKESK: unsupported cipher=${skesk.enc}`);
  const unsupported = unsupportedAEAD(skesk.aead);
  if (unsupported) throw unsupported;
  const derived = deriveS2KKey(skesk.S2K, keyLen, password);
  // RFC 9580 §5.3.2: v6 SKESK first HKDFs the S2K output with no salt and
  // info `c3 || 06 || cipher || aead`, then AEAD-decrypts session key || tag
  // using the same four octets as additional authenticated data.
  const info = packetInfo('symmetric_key_encrypted_session_key', 6, skesk.enc, skesk.aead);
  const key = hkdf(sha256, derived, undefined, info, keyLen);
  return aeadDecrypt(
    skesk.aead,
    key,
    skesk.iv,
    info,
    concatBytes(skesk.encryptedSessionKey, skesk.tag)
  );
}
function decryptV2SEIPD(sessionKey: TArg<Bytes>, data: TArg<Bytes>): TRet<Packet[]> {
  const packet = V2SEIPD.decode(data);
  const keyLen = EncryptionKeySize[packet.enc];
  if (!keyLen) throw new Error(`PGP.SEIPD: unsupported cipher=${packet.enc}`);
  if (sessionKey.length !== keyLen) throw new Error('PGP.SEIPD: wrong session key length');
  const nonceLen = aeadNonceLen(packet.aead);
  const info = packetInfo('encryptedProtectedData', 2, packet.enc, packet.aead, packet.chunkSize);
  // RFC 9580 §5.13.2 derives the message key and the nonce prefix from the
  // decrypted session key, v2 SEIPD salt, and `d2 || 02 || cipher || aead || c`.
  const material = hkdf(sha256, sessionKey, packet.salt, info, keyLen + nonceLen - 8);
  const key = material.subarray(0, keyLen);
  const iv = material.subarray(keyLen);
  const encrypted = packet.encrypted;
  if (encrypted.length < AEAD_TAG_LEN) throw new Error('PGP.SEIPD: truncated final tag');
  const chunks = encrypted.subarray(0, -AEAD_TAG_LEN);
  const finalTag = encrypted.subarray(encrypted.length - AEAD_TAG_LEN);
  const chunkSize = 1 << (packet.chunkSize + 6);
  const out = [];
  let pos = 0;
  for (let chunk = 0; pos < chunks.length; chunk++) {
    const dataLen = Math.min(chunkSize, chunks.length - pos - AEAD_TAG_LEN);
    if (dataLen < 0) throw new Error('PGP.SEIPD: truncated chunk tag');
    const nonce = concatBytes(iv, u64BE(chunk));
    out.push(
      aeadDecrypt(packet.aead, key, nonce, info, chunks.subarray(pos, pos + dataLen + AEAD_TAG_LEN))
    );
    pos += dataLen + AEAD_TAG_LEN;
  }
  const clear = concatBytes(...out);
  const final = aeadDecrypt(
    packet.aead,
    key,
    concatBytes(iv, u64BE(out.length)),
    concatBytes(info, u64BE(clear.length)),
    finalTag
  );
  if (final.length) throw new Error('PGP.SEIPD: invalid final tag plaintext');
  return StreamCoder.decode(clear) as TRet<Packet[]>;
}

/**
 * OpenPGP packet-stream coder.
 * @example
 * Encode a short sequence of OpenPGP packets into the binary stream format.
 * ```ts
 * import { Stream } from 'micro-key-producer/pgp.js';
 * Stream.encode([{ TAG: 'userId', data: 'alice@example.com' }]);
 * ```
 */
const StreamCoder: P.CoderType<Packet[]> = /* @__PURE__ */ deepFreeze(
  /* @__PURE__ */ P.array(null, PacketCoder)
);
export const Stream: TRet<P.CoderType<Packet[]>> = StreamCoder as unknown as TRet<
  P.CoderType<Packet[]>
>;
export const __TESTS: {
  PacketHead: P.CoderType<PacketHeadType>;
  SignatureHead: typeof SignatureHead;
  SignatureSubpacket: typeof SignatureSubpacket;
  SignatureSubpacketLen: typeof SignatureSubpacketLen;
  signData: typeof signData;
  verifyData: typeof verifyData;
  decryptV6PKESK: typeof decryptV6PKESK;
  decryptV6SKESK: typeof decryptV6SKESK;
  decryptV2SEIPD: typeof decryptV2SEIPD;
  S2KEnum: typeof S2KEnum;
  S2K: typeof S2K;
} = /* @__PURE__ */ deepFreeze({
  PacketHead: /* @__PURE__ */ packetHead(),
  SignatureHead,
  SignatureSubpacket,
  SignatureSubpacketLen,
  signData,
  verifyData,
  decryptV6PKESK,
  decryptV6SKESK,
  decryptV2SEIPD,
  S2KEnum,
  S2K,
});

// Key generation
// RFC 9580 §5.2.3.3.1 / RFC 8032 §3.3: Ed25519Legacy signatures are exactly
// two 32-octet chunks, R and S, before OpenPGP packet-specific MPI framing.
const EDSIGN = /* @__PURE__ */ P.array(2, P.U256BE);
const ed25519Digest = (hash: TArg<Bytes>): TRet<Bytes> => {
  // RFC 9580 §5.2.3.3 requires Ed25519Legacy digests to be at least
  // fsize=32 octets, and §5.2.3.4 says Ed25519 verifiers MUST reject
  // hashes smaller than 256 bits. GnuPG 2.4.7 accepts explicit SHA-1/
  // SHA-224 downgrades, but normal GPG commit signing uses SHA-512, so
  // keep the RFC boundary here.
  if (hash.length < 32) throw new Error(`PGP.Ed25519: expected digest >= 32 bytes`);
  return hash as TRet<Bytes>;
};
function signData(
  head: TArg<SignatureHeadType>,
  unhashed: TArg<SignatureSubpacketType[]>,
  data: TArg<SignatureData>,
  privateKey: TArg<Bytes>
): SignatureType {
  // RFC 9580 §12.7 feeds the already-hashed packet digest verbatim into PureEdDSA.
  const hash = ed25519Digest(hashSignature(head, data));
  const hashPrefix = hash.subarray(0, 2);
  const sig = EDSIGN.decode(ed25519.sign(hash, privateKey));
  return { head, unhashed, hashPrefix, sig };
}

type VerifyDataResult = {
  head: SignatureHeadType;
  hashPrefix: Bytes;
  hash: Bytes;
  verified: boolean;
};
function verifyData(
  head: TArg<SignatureHeadType>,
  data: TArg<SignatureData>,
  sig: TArg<bigint[] | Bytes>,
  publicKey: TArg<Bytes>,
  salt?: TArg<Bytes>
): TRet<VerifyDataResult> {
  const hash = hashSignature(head, data, salt);
  const hashPrefix = hash.subarray(0, 2);
  if (head.version === 6) {
    if (head.algo !== 'Ed25519')
      throw new Error(`PGP.Signature: unsupported v6 algorithm=${head.algo}`);
    // RFC 9580 §5.2.3.4 stores v6 Ed25519 signatures as 64 raw native octets;
    // EdDSALegacy's two-MPI wrapper is forbidden for v6.
    if (!isBytes(sig) || sig.length !== 64)
      throw new Error('PGP.Signature: invalid v6 Ed25519 signature');
    return {
      head,
      hashPrefix,
      hash,
      verified: ed25519.verify(sig, ed25519Digest(hash), publicKey),
    } as TRet<VerifyDataResult>;
  }
  const checked = ed25519Digest(hash);
  const verified = ed25519.verify(EDSIGN.encode(sig as bigint[]), checked, publicKey);
  return { head, hashPrefix, hash, verified } as TRet<VerifyDataResult>;
}

function secretChecksum(data: TArg<Bytes>) {
  // Wow, third checksum algorithm in single spec!
  // Legacy secret-key packets use the plaintext byte sum mod 65536 for the 2-octet checksum form.
  let checksum = 0;
  for (let i = 0; i < data.length; i++) checksum += data[i];
  checksum %= 65536;
  return checksum;
}
const fixedSecretBytes = (len: number): P.CoderType<bigint> =>
  /* @__PURE__ */ P.apply(/* @__PURE__ */ P.bytes(len), {
    encode: (secret: TArg<Bytes>) => bytesToNumberBE(secret),
    decode: (secret: bigint) => numberToBytesBE(secret, len) as TRet<Bytes>,
  });
const fixedSecretMPI = (len: number): P.CoderType<bigint> =>
  /* @__PURE__ */ P.apply(
    /* @__PURE__ */ P.apply(opaquempi, {
      encode: (payload: TArg<Bytes>): TRet<Bytes> => {
        if (payload.length > len) throw new Error('PGP.secretKey: invalid fixed MPI payload');
        const res = new Uint8Array(len);
        res.set(payload, len - payload.length);
        return res as TRet<Bytes>;
      },
      decode: (secret: TArg<Bytes>): TRet<Bytes> => {
        if (secret.length !== len) throw new Error('PGP.secretKey: invalid fixed MPI length');
        let start = 0;
        while (start < secret.length && secret[start] === 0) start++;
        return secret.slice(start) as TRet<Bytes>;
      },
    }),
    {
      encode: (secret: TArg<Bytes>) => bytesToNumberBE(secret),
      decode: (secret: bigint) => numberToBytesBE(secret, len) as TRet<Bytes>,
    }
  );
const secretPayload = (key: SecretKeyType): P.CoderType<bigint> => {
  const algo = key.pub.algo;
  if (algo.TAG === 'Ed25519' || algo.TAG === 'X25519') {
    // RFC 9580 §5.5.5.7 / §5.5.5.9 store v6 X25519 and Ed25519
    // secret keys as exactly 32 native octets.
    return fixedSecretBytes(32);
  }
  if (algo.TAG === 'Ed448') {
    // RFC 9580 §5.5.5.10 stores v6 Ed448 secret keys as exactly 57 native octets.
    return fixedSecretBytes(57);
  }
  if (algo.TAG === 'EdDSA' && algo.data.curve === 'ed25519') {
    // RFC 9580 §5.5.5.5 stores Ed25519Legacy secrets as MPI-encoded fixed-width
    // native octet strings; §11.3.1 restores those from the MPI payload bytes.
    return fixedSecretMPI(32);
  }
  if (algo.TAG === 'ECDH' && algo.data.curve === 'curve25519') {
    // RFC 9580 §5.5.5.6.1.1 gives Curve25519Legacy a 32-octet scalar boundary;
    // GnuPG-compatible v4 packets may keep the fixed-width 256-bit count here.
    return fixedSecretMPI(32);
  }
  if (!['ECDH', 'ECDSA', 'EdDSA'].includes(algo.TAG))
    throw new Error(`PGP.secretKey unsupported publicKey algorithm: ${algo.TAG}`);
  return mpi;
};
// Plain secret-key packets checksum the canonical MPI bytes, so zero-valued
// secrets here still depend on the shared MPI coder handling `0` correctly.
const secretChecksumCoder = {
  decode(key: SecretKeyType, secret: TArg<Bytes>) {
    const [data, checksum] = [secret.slice(0, -2), P.U16BE.decode(secret.slice(-2))];
    let ourChecksum = secretChecksum(data);
    if (ourChecksum !== checksum)
      throw new Error('PGP.secretKey: wrong checksum for plain encoding');
    return secretPayload(key).decode(data);
  },
  encode(secret: TArg<Bytes>) {
    const encoded = mpi.encode(bytesToNumberBE(secret));
    return concatBytes(encoded, P.U16BE.encode(secretChecksum(encoded)));
  },
};
type SecretKeyPacketTag = 'secretKey' | 'secretSubkey';
const checkV6S2KHash = (key: SecretKeyType, s2k_: TArg<S2KType>) => {
  const s2k = s2k_ as S2KType;
  if (key.pub.version !== 6 || s2k.TAG === 'argon2') return;
  const hash = s2k.data.hash;
  // RFC 9580 §9.5: implementations MUST NOT decrypt v6-or-later secrets
  // with MD5, SHA-1, or RIPEMD-160 as the S2K KDF hash.
  if (hash === 'md5' || hash === 'sha1' || hash === 'ripemd160')
    throw new Error(`PGP.secretKey: weak S2K hash ${hash} is forbidden for v6 keys`);
};

/**
 * Decrypts the secret scalar from a PGP secret-key packet.
 * @param password - Secret-key passphrase.
 * @param key - Parsed secret-key packet.
 * @param packetTag - Optional outer packet tag for v6 AEAD secret keys.
 * @returns Secret scalar as a bigint.
 * @throws If the packet uses unsupported encryption or fails checksum validation. {@link Error}
 * @example
 * Decrypt the secret scalar stored inside an armored private key packet.
 * ```ts
 * import { randomBytes } from '@noble/hashes/utils.js';
 * import { decodeSecretKey, getKeys, privArmor } from 'micro-key-producer/pgp.js';
 * const seed = randomBytes(32);
 * const packet = privArmor
 *   .decode(getKeys(seed, 'alice@example.com', 'password').privateKey)
 *   .find((p) => p.TAG === 'secretKey');
 * if (!packet) throw new Error('missing secret-key packet');
 * decodeSecretKey('password', packet.data);
 * ```
 */
export function decodeSecretKey(
  password: string,
  key: TArg<SecretKeyType>,
  packetTag?: SecretKeyPacketTag
): bigint {
  password = astring(password, 'password');
  // Plain packets do not use packetTag, so validate it before packet-type branching.
  if (packetTag !== undefined) {
    packetTag = astring(packetTag, 'packetTag') as SecretKeyPacketTag;
    if (packetTag !== 'secretKey' && packetTag !== 'secretSubkey')
      throw new Error(`"packetTag" expected "secretKey" or "secretSubkey", got ${packetTag}`);
  }
  if (!P.utils.isPlainObject(key))
    throw new TypeError('"key" expected object, got type=' + typeof key);
  const secret = key as SecretKeyType;
  if (!P.utils.isPlainObject(secret.pub))
    throw new TypeError('"key.pub" expected object, got type=' + typeof secret.pub);
  if (!P.utils.isPlainObject(secret.type))
    throw new TypeError('"key.type" expected object, got type=' + typeof secret.type);
  if (secret.type.TAG === 'plain') {
    if (secret.pub.version === 6) return secretPayload(secret).decode(secret.type.data.secret);
    return secretChecksumCoder.decode(secret, secret.type.data.secret);
  }
  if (secret.type.TAG === 'aead') {
    if (secret.pub.version !== 6) throw new Error('PGP.secretKey: AEAD requires a v6 key packet');
    const data = secret.type.data;
    const keyLen = EncryptionKeySize[data.enc];
    if (keyLen === undefined) throw new Error(`PGP.secretKey: unknown encryption mode=${data.enc}`);
    if (data.secret.length < AEAD_TAG_LEN) throw new Error('PGP.secretKey: truncated AEAD tag');
    const unsupported = unsupportedAEAD(data.aead);
    // RFC 9580 Appendix A.5 uses Argon2 encoded_m=21 before OCB. Since
    // noble-ciphers has no OCB, fail at the real secret-key decrypt API
    // boundary before allocating the unavailable-mode S2K workspace.
    if (unsupported) throw unsupported;
    checkV6S2KHash(secret, data.S2K);
    const derived = deriveS2KKey(data.S2K, keyLen, utf8.decode(password));
    const tags: SecretKeyPacketTag[] = packetTag ? [packetTag] : ['secretKey', 'secretSubkey'];
    let authError: unknown;
    for (const tag of tags) {
      try {
        // RFC 9580 §5.5.3 derives the AEAD KEK with HKDF-SHA256 over
        // `packet type || version || cipher || AEAD`, while AEAD AAD is the
        // packet-prefix octet plus the encoded public-key packet fields.
        const info = packetInfo(tag, 6, data.enc, data.aead);
        const kek = hkdf(sha256, derived, undefined, info, keyLen);
        const aad = concatBytes(
          Uint8Array.of(0xc0 | packetTagId(tag)),
          PubKeyPacketCoder.encode(secret.pub)
        );
        return secretPayload(secret).decode(aeadDecrypt(data.aead, kek, data.iv, aad, data.secret));
      } catch (err) {
        if (
          packetTag ||
          !(err instanceof Error && /invalid .*tag|authentication/i.test(err.message))
        )
          throw err;
        if (!authError) authError = err;
      }
    }
    throw authError;
  }
  if (secret.type.TAG === 'encryptedDirect') {
    const keyData = secret.type.data;
    const keyLen = EncryptionKeySize[keyData.enc];
    if (keyLen === undefined)
      throw new Error(`PGP.secretKey: unknown encryption mode=${keyData.enc}`);
    // RFC 9580 §3.7.2.1 names this v4-and-earlier read-only format
    // LegacyCFB: the S2K usage octet is the cipher id and the KEK is
    // MD5(passphrase), with a trailing 2-octet checksum inside CFB.
    const encKey = Hash.md5(utf8.decode(password));
    const decrypted = Encryption[keyData.enc].decrypt(keyData.secret, encKey, keyData.iv);
    return secretChecksumCoder.decode(secret, decrypted);
  }
  const keyData = secret.type.data;
  // RFC 9580 §3.7.2.1: Argon2 S2K is only valid with AEAD usage 253, not
  // the legacy CFB wrappers handled by this decoder.
  if (keyData.S2K.TAG === 'argon2') throw new Error('PGP.secretKey: Argon2 S2K requires AEAD');
  checkV6S2KHash(secret, keyData.S2K);
  const data = keyData.S2K.data;
  const keyLen = EncryptionKeySize[keyData.enc];
  if (keyLen === undefined)
    throw new Error(`PGP.secretKey: unknown encryption mode=${keyData.enc}`);
  const encKey = deriveKey(
    data.hash,
    keyLen,
    utf8.decode(password),
    'salt' in data ? data.salt : undefined,
    'count' in data ? data.count : undefined
  );
  const decrypted = Encryption[keyData.enc].decrypt(keyData.secret, encKey, keyData.iv);
  // RFC 4880 §5.5.3 / RFC 9580 §5.5.3: usage 255 uses the legacy
  // 2-octet checksum, while usage 254 uses a SHA-1 trailer. RFC 9580
  // §3.7.2.1 forbids generating 255, but keeps it readable for v4 keys.
  if (secret.type.TAG === 'encrypted2') return secretChecksumCoder.decode(secret, decrypted);
  const decryptedKey = decrypted.subarray(0, -20);
  const checksum = Hash.sha1(decryptedKey);
  if (!equalBytes(decrypted.slice(-20), checksum))
    throw new Error('PGP.secretKey: invalid sha1 checksum');
  return secretPayload(secret).decode(decryptedKey);
}

function createPrivKey(
  pub: TArg<PubKeyPacketType>,
  key: TArg<Bytes>,
  password?: string,
  salt?: TArg<Bytes>,
  iv?: TArg<Bytes>,
  // RFC 9580 §9.5 says MUST NOT generate SHA-1 as an S2K KDF, but GnuPG
  // 2.4.7 still does for v4 secret keys; keep it to avoid fingerprinting.
  hash = 'sha1',
  count = 240,
  enc = 'aes128'
): SecretKeyType {
  const pubKey = pub as PubKeyPacketType;
  const keyLen = EncryptionKeySize[enc];
  if (keyLen === undefined) throw new Error(`PGP.secretKey: unknown encryption mode=${enc}`);
  // Export key without password. RFC 9580 §11.3.1 allows fixed-length EC
  // octet strings to strip leading zero bytes in MPI form; GnuPG 2.4.7
  // re-exports these plain Ed25519Legacy secrets in the same canonical form.
  if (password === undefined)
    return {
      pub: pubKey,
      type: { TAG: 'plain', data: { secret: secretChecksumCoder.encode(key) } },
    };
  // RFC 4880 §3.7.1.3 / RFC 9580 §3.7.1.3: iterated-and-salted S2K carries an 8-octet salt.
  if (!isBytes(salt)) throw new Error('PGP.secretKey: no salt');
  if (!isBytes(iv)) throw new Error('PGP.secretKey: no iv');
  const encKey = deriveKey(hash, keyLen, utf8.decode(password), salt, count);
  const keyBytes = opaquempi.encode(key);
  const secretClear = concatBytes(keyBytes, sha1(keyBytes));
  const secret = Encryption[enc].encrypt(secretClear, encKey, iv);
  const S2K = { TAG: 'iterated', data: { hash, salt, count } } as const;
  return { pub: pubKey, type: { TAG: 'encrypted', data: { enc, S2K, iv, secret } } };
}

/**
 * ASCII armor for PGP public key blocks.
 * @example
 * Decode the armored public block that `getKeys()` produces.
 * ```ts
 * import { randomBytes } from '@noble/hashes/utils.js';
 * import { getKeys, pubArmor } from 'micro-key-producer/pgp.js';
 * const seed = randomBytes(32);
 * pubArmor.decode(getKeys(seed, 'alice@example.com').publicKey);
 * ```
 */
// Keep the legacy version-4 public-key armor label and CRC24 footer on this
// surface for byte-for-byte compatibility with the current emitted blocks.
export const pubArmor: TRet<P.Coder<Packet[], string>> = /* @__PURE__ */ deepFreeze(
  /* @__PURE__ */ base64armor('PGP PUBLIC KEY BLOCK', 64, StreamCoder, crc24) as unknown as TRet<
    P.Coder<Packet[], string>
  >
);
/**
 * ASCII armor for PGP private key blocks.
 * @example
 * Decode the armored private block back into OpenPGP packets.
 * ```ts
 * import { randomBytes } from '@noble/hashes/utils.js';
 * import { getKeys, privArmor } from 'micro-key-producer/pgp.js';
 * const seed = randomBytes(32);
 * privArmor.decode(getKeys(seed, 'alice@example.com').privateKey);
 * ```
 */
// Keep the legacy version-4 private-key armor label and CRC24 footer on this
// surface for byte-for-byte compatibility with the current emitted blocks.
export const privArmor: TRet<P.Coder<Packet[], string>> = /* @__PURE__ */ deepFreeze(
  /* @__PURE__ */ base64armor('PGP PRIVATE KEY BLOCK', 64, StreamCoder, crc24) as unknown as TRet<
    P.Coder<Packet[], string>
  >
);
/**
 * ASCII armor for detached PGP signatures.
 * @example
 * Decode an armored detached signature back into its packet list.
 * ```ts
 * import { randomBytes } from '@noble/hashes/utils.js';
 * import { getKeyId, sigArmor, signDetached } from 'micro-key-producer/pgp.js';
 * const seed = randomBytes(32);
 * sigArmor.decode(signDetached(seed, 'hello', getKeyId(seed).fingerprint));
 * ```
 */
// Keep the legacy version-4 detached-signature armor label and CRC24 footer on
// this surface for byte-for-byte compatibility with the current emitted blocks.
export const sigArmor: TRet<P.Coder<Packet[], string>> = /* @__PURE__ */ deepFreeze(
  /* @__PURE__ */ base64armor('PGP SIGNATURE', 64, StreamCoder, crc24) as unknown as TRet<
    P.Coder<Packet[], string>
  >
);

function validateDate(timestamp: number, title = 'timestamp', kind = 'PGP key creation time') {
  if (typeof timestamp !== 'number')
    throw new TypeError(`"${title}" expected number, got type=${typeof timestamp}`);
  // RFC 4880 §3.5 / RFC 9580 §3.5 define time fields as unsigned four-octet
  // seconds, and RFC 9580 §5.5.2.2 uses that field for v4 key creation time.
  if (!Number.isSafeInteger(timestamp) || timestamp < 0 || timestamp > 0xffffffff)
    throw new RangeError(
      `invalid ${kind}: "${title}" expected valid UNIX timestamp, got ${timestamp}`
    );
}

function getPublicPackets(edPriv: TArg<Bytes>, cvPriv: TArg<Bytes>, createdAt: number) {
  validateDate(createdAt, 'createdAt');
  // These legacy v4 packets use prefixed-native `0x40 || point` encodings for
  // Ed25519 / Curve25519, and the Curve25519 ECDH subkey keeps Table 30
  // SHA-256 + AES-128 parameters.
  const edPub = bytesToNumberBE(concatBytes(Uint8Array.of(0x40), ed25519.getPublicKey(edPriv)));
  const edPubPacket = {
    created: createdAt,
    algo: { TAG: 'EdDSA', data: { curve: 'ed25519', pub: edPub } },
  } as const;
  const cvPoint = x25519.scalarMultBase(cvPriv);
  const cvPub = bytesToNumberBE(concatBytes(Uint8Array.of(0x40), cvPoint));
  const cvPubPacket = {
    created: createdAt,
    algo: {
      TAG: 'ECDH',
      data: { curve: 'curve25519', pub: cvPub, params: { hash: 'sha256', encryption: 'aes128' } },
    },
  } as const;
  const fingerprint = hex.encode(sha1(hashPubKey.encode(edPubPacket)));
  const keyId = fingerprint.slice(-16);
  return { edPubPacket, fingerprint, keyId, cvPubPacket };
}

function getCerts(edPriv: TArg<Bytes>, cvPriv: TArg<Bytes>, user: string, createdAt: number) {
  // key settings same as in PGP to avoid fingerprinting since they are part of public key
  const preferredEncryptionAlgorithms = ['aes256', 'aes192', 'aes128', 'tripledes'];
  const preferredHashAlgorithms = ['sha512', 'sha384', 'sha256', 'sha224', 'sha1'];
  const preferredCompressionAlgorithms = ['zlib', 'bzip2', 'zip'];
  // Keep the old OpenPGP/GnuPG-compatible public self-signature surface to
  // avoid fingerprinting changes. RFC 9580 Table 5 reserves subpacket 34 and
  // moves AEAD prefs to type 39 ciphersuite pairs (§5.2.3.15);
  // §5.2.3.32 / §5.2.3.25 also define final feature and key-server flags.
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
    { pubKey: edPubPacket, user: { user } },
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
    { pubKey: edPubPacket, subKey: cvPubPacket },
    edPriv
  );
  return { edPubPacket, fingerprint, keyId, cvPubPacket, cvCert, edCert };
}

/**
 * Formats the armored public half of a deterministic OpenPGP keypair.
 * @param edPriv - Ed25519 signing private key.
 * @param cvPriv - Curve25519 encryption private key.
 * @param user - OpenPGP user ID string.
 * @param createdAt - Key creation time as UNIX timestamp in seconds.
 * @returns ASCII-armored public key block.
 * @throws If the supplied key material or timestamp cannot be encoded as OpenPGP packets. {@link Error}
 * @example
 * Build the public OpenPGP block from the signing key and its Curve25519 subkey.
 * ```ts
 * import { randomBytes } from '@noble/hashes/utils.js';
 * import { formatPublic } from 'micro-key-producer/pgp.js';
 * import { ed25519 } from '@noble/curves/ed25519.js';
 * const seed = randomBytes(32);
 * const cvPriv = ed25519.utils.getExtendedPublicKey(seed).head;
 * formatPublic(seed, cvPriv, 'alice@example.com', 0);
 * ```
 */
export function formatPublic(
  edPriv: TArg<Bytes>,
  cvPriv: TArg<Bytes>,
  user: string,
  createdAt: number
): string {
  edPriv = abytes(edPriv, 32, 'edPriv');
  cvPriv = abytes(cvPriv, 32, 'cvPriv');
  user = astring(user, 'user');
  validateDate(createdAt, 'createdAt');
  const { edPubPacket, cvPubPacket, edCert, cvCert } = getCerts(edPriv, cvPriv, user, createdAt);
  // Keep this wrapper as the fixed v4 transferable-public-key packet sequence;
  // policy changes for the emitted self-signatures belong in `getCerts()`.
  return pubArmor.encode([
    { TAG: 'publicKey', data: edPubPacket },
    { TAG: 'userId', data: user },
    { TAG: 'signature', data: edCert },
    { TAG: 'publicSubkey', data: cvPubPacket },
    { TAG: 'signature', data: cvCert },
  ]);
}

/**
 * Formats the armored private half of a deterministic OpenPGP keypair.
 * @param edPriv - Ed25519 signing private key.
 * @param cvPriv - Curve25519 encryption private key.
 * @param user - OpenPGP user ID string.
 * @param password - Optional secret-key passphrase.
 * @param createdAt - Key creation time as UNIX timestamp in seconds.
 * @param edSalt - Salt for the signing secret-key S2K envelope.
 * @param edIV - IV for the signing secret-key S2K envelope.
 * @param cvSalt - Salt for the encryption subkey S2K envelope.
 * @param cvIV - IV for the encryption subkey S2K envelope.
 * @returns ASCII-armored private key block.
 * @throws If the supplied key material, timestamp, or secret-key envelope parameters are invalid. {@link Error}
 * @example
 * Build the password-protected private key block and matching encryption subkey.
 * ```ts
 * import { randomBytes } from '@noble/hashes/utils.js';
 * import { formatPrivate } from 'micro-key-producer/pgp.js';
 * import { ed25519 } from '@noble/curves/ed25519.js';
 * const seed = randomBytes(32);
 * const cvPriv = ed25519.utils.getExtendedPublicKey(seed).head;
 * formatPrivate(seed, cvPriv, 'alice@example.com', 'password');
 * ```
 */
export function formatPrivate(
  edPriv: TArg<Bytes>,
  cvPriv: TArg<Bytes>,
  user: string,
  password?: string,
  createdAt = 0,
  edSalt: TArg<Uint8Array> = randomBytes(8),
  edIV: TArg<Uint8Array> = randomBytes(16),
  cvSalt: TArg<Uint8Array> = randomBytes(8),
  cvIV: TArg<Uint8Array> = randomBytes(16)
): string {
  edPriv = abytes(edPriv, 32, 'edPriv');
  cvPriv = abytes(cvPriv, 32, 'cvPriv');
  user = astring(user, 'user');
  if (password !== undefined) password = astring(password, 'password');
  validateDate(createdAt, 'createdAt');
  edSalt = abytes(edSalt, 8, 'edSalt');
  edIV = abytes(edIV, 16, 'edIV');
  cvSalt = abytes(cvSalt, 8, 'cvSalt');
  cvIV = abytes(cvIV, 16, 'cvIV');
  const { edPubPacket, cvPubPacket, edCert, cvCert } = getCerts(edPriv, cvPriv, user, createdAt);
  const edSecret = createPrivKey(edPubPacket, edPriv, password, edSalt, edIV);
  // Keep this wrapper as the fixed v4 transferable-secret-key packet sequence;
  // local normalization converts the Curve25519 secret from native little-endian
  // bytes to the fixed-width big-endian MPI input that `createPrivKey()` expects.
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
 * @param edPrivKey - Ed25519 signing private key.
 * @param createdAt - Key creation time as UNIX timestamp in seconds.
 * @returns Public packets plus fingerprint and key ID.
 * @throws If the key material or creation time cannot be encoded as OpenPGP packets. {@link Error}
 * @example
 * Recompute the OpenPGP fingerprint and key ID for an existing signing key.
 * ```ts
 * import { randomBytes } from '@noble/hashes/utils.js';
 * import { getKeyId } from 'micro-key-producer/pgp.js';
 * getKeyId(randomBytes(32)).keyId;
 * ```
 */
export function getKeyId(
  edPrivKey: TArg<Bytes>,
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
  edPrivKey = abytes(edPrivKey, 32, 'edPrivKey');
  validateDate(createdAt, 'createdAt');
  // Reuse the same expanded-head -> Curve25519 sibling derivation as
  // `getKeys()` so standalone fingerprint/key-id queries match emitted bundles.
  const { head: cvPrivate } = ed25519.utils.getExtendedPublicKey(edPrivKey);
  return getPublicPackets(edPrivKey, cvPrivate, createdAt);
}

/**
 * Derives PGP private key, public key and fingerprint.
 * Uses S2K KDF, which means it's slow. Use `getKeyId` if you want to get key id in a fast way.
 * PGP key depends on its date of creation.
 * NOTE: gpg: warning: lower 3 bits of the secret key are not cleared
 * happens even for keys generated with GnuPG 2.3.6, because check looks at item as Opaque MPI, when it is just MPI. See {@link https://dev.gnupg.org/rGdbfb7f809b89cfe05bdacafdb91a2d485b9fe2e0 | the GnuPG bugtracker note}.
 * @param privKey - Ed25519 signing private key.
 * @param user - OpenPGP user ID string.
 * @param password - Optional secret-key passphrase.
 * @param createdAt - Key creation time as UNIX timestamp in seconds.
 * @returns Armored keypair plus fingerprint data.
 * @throws If the key material or creation time cannot be encoded as OpenPGP packets. {@link Error}
 * @example
 * Derive the armored OpenPGP keypair from one Ed25519 private key.
 * ```ts
 * import { randomBytes } from '@noble/hashes/utils.js';
 * import { getKeys } from 'micro-key-producer/pgp.js';
 * const seed = randomBytes(32);
 * getKeys(seed, 'alice@example.com').publicKey;
 * ```
 */
export function getKeys(
  privKey: TArg<Bytes>,
  user: string,
  password?: string,
  createdAt = 0
): {
  keyId: string;
  fingerprint: string; // full fingerprint
  privateKey: string;
  publicKey: string;
} {
  privKey = abytes(privKey, 32, 'privKey');
  user = astring(user, 'user');
  if (password !== undefined) password = astring(password, 'password');
  validateDate(createdAt, 'createdAt');
  // Derive the Curve25519 sibling once and reuse it for the key-id lookup plus
  // both armor writers so exported artifacts stay aligned for one seed/date pair.
  const { head: cvPrivate } = ed25519.utils.getExtendedPublicKey(privKey);
  const { keyId, fingerprint } = getPublicPackets(privKey, cvPrivate, createdAt);
  const publicKey = formatPublic(privKey, cvPrivate, user, createdAt);
  // The slow part
  const privateKey = formatPrivate(privKey, cvPrivate, user, password, createdAt);
  return { keyId, fingerprint, privateKey, publicKey };
}

/**
 * Default export for deterministic OpenPGP key derivation.
 * @param privKey - Ed25519 signing private key.
 * @param user - OpenPGP user ID string.
 * @param password - Optional secret-key passphrase.
 * @param createdAt - Key creation time as UNIX timestamp in seconds.
 * @returns Armored keypair plus fingerprint data.
 * @throws If the key material or creation time cannot be encoded as OpenPGP packets. {@link Error}
 * @example
 * Use the default export when you want the full armored OpenPGP bundle in one call.
 * ```ts
 * import getKeys from 'micro-key-producer/pgp.js';
 * import { randomBytes } from '@noble/hashes/utils.js';
 * const seed = randomBytes(32);
 * getKeys(seed, 'alice@example.com').publicKey;
 * ```
 */
export default getKeys;

// TODO: there should be two versions of this, one throws on duplication, one doesn't. Then we can apply this to all coders
// here and make it easier to use, also per-tag type inference. Probably should be in micro-packed itself (pretty useful!)
// Will be easier to use, but harder to debug. Still need to think about this. But will change exported coders API here.
// const taggedDict = <T>(inner: P.CoderType<{ TAG: string; data: T }[]>) => {
//   return P.apply(inner, {
//     encode: (to) => {
//       if (!Array.isArray(to)) throw new Error('expected array');
//       const res: Record<string, any> = {};
//       for (const i of to) {
//         const { TAG, data } = i;
//         if (res.hasOwnProperty(TAG)) throw new Error('duplicate tag=' + TAG);
//         res[TAG] = data;
//       }
//       return res;
//     },
//     decode: (from) => {
//       return Object.entries(from).map(([k, v]) => ({ TAG: k, data: v }));
//     },
//   });
// };

function detachedType(data: TArg<Bytes | string>) {
  if (!isBytes(data) && typeof data !== 'string')
    throw new TypeError('"data" expected Uint8Array or string, got type=' + typeof data);
  // Keep the API-level boundary simple: JS strings opt into canonical-text
  // signature semantics, while raw byte arrays stay binary.
  return typeof data === 'string' ? 'text' : 'binary';
}

/**
 * Creates an armored detached OpenPGP signature.
 * @param privateKey - Ed25519 signing private key.
 * @param data - Binary or text payload to sign.
 * @param fingerprint - Full OpenPGP fingerprint of the signing key.
 * @param signedAt - Signature creation time as UNIX timestamp in seconds.
 * @returns ASCII-armored detached signature.
 * @throws If the detached payload cannot be encoded or signed as OpenPGP data. {@link Error}
 * @example
 * Create a detached signature you can send alongside the original text payload.
 * ```ts
 * import { randomBytes } from '@noble/hashes/utils.js';
 * import { getKeyId, signDetached } from 'micro-key-producer/pgp.js';
 * const seed = randomBytes(32);
 * const { fingerprint } = getKeyId(seed);
 * signDetached(seed, 'hello', fingerprint);
 * ```
 */
export function signDetached(
  privateKey: TArg<Bytes>,
  data: TArg<Bytes | string>,
  fingerprint: string,
  signedAt: number = 0
): string {
  privateKey = abytes(privateKey, 32, 'privateKey');
  fingerprint = astring(fingerprint, 'fingerprint');
  validateDate(signedAt, 'signedAt', 'PGP signature creation time');
  // RFC 4880 §3.5 and RFC 9580 §3.5 define OpenPGP time fields as unsigned
  // four-octet seconds; RFC 9580 §5.2.3.11 makes Signature Creation Time that field.
  const dataType = detachedType(data);
  const keyId = fingerprint.slice(-16);
  const head: SignatureHeadType = {
    version: undefined,
    type: dataType,
    algo: 'EdDSA',
    hash: 'sha512',
    hashed: [
      { TAG: 'issuerFingerprint', data: { version: undefined, fingerprint } },
      { TAG: 'signatureCreationTime', data: signedAt },
    ],
  };
  const unhashed: SignatureSubpacketType[] = [{ TAG: 'issuer', data: keyId }];
  const sig = signData(head, unhashed, data, privateKey);
  return sigArmor.encode([{ TAG: 'signature', data: sig }]);
}

/**
 * Verifies an armored detached OpenPGP signature with an Ed25519 public key.
 * @param publicKey - Ed25519 public key bytes.
 * @param signature - ASCII-armored detached signature.
 * @param data - Original binary or text payload.
 * @param fingerprint - Optional expected signer fingerprint.
 * @returns Whether the detached signature verifies.
 * @throws If the signature packet, payload type, or signer fingerprint is invalid. {@link Error}
 * @example
 * Verify the detached signature with the signer's Ed25519 public key and fingerprint.
 * ```ts
 * import { randomBytes } from '@noble/hashes/utils.js';
 * import { getKeyId, signDetached, verifyDetached } from 'micro-key-producer/pgp.js';
 * import { ed25519 } from '@noble/curves/ed25519.js';
 * const privateKey = randomBytes(32);
 * const { fingerprint } = getKeyId(privateKey);
 * const signature = signDetached(privateKey, 'hello', fingerprint);
 * verifyDetached(ed25519.getPublicKey(privateKey), signature, 'hello', fingerprint);
 * ```
 */
export function verifyDetached(
  publicKey: TArg<Bytes>,
  signature: string,
  data: TArg<Bytes | string>,
  fingerprint?: string
): boolean {
  publicKey = abytes(publicKey, 32, 'publicKey');
  signature = astring(signature, 'signature');
  if (fingerprint !== undefined) fingerprint = astring(fingerprint, 'fingerprint');
  const sigPacket = sigArmor.decode(signature);
  // NOTE: in theory there can be multiple signatures inside!
  if (sigPacket.length !== 1 || sigPacket[0].TAG !== 'signature')
    throw new Error('wrong signature');
  const sig = sigPacket[0].data;
  const dataType = detachedType(data);
  if (dataType !== sig.head.type)
    throw new Error('verifyDetached: wrong data type: ' + dataType + ', got:' + sig.head.type);
  if (fingerprint) {
    // RFC 9580 §5.2.3.9 leaves duplicate/conflicting subpacket resolution to
    // implementers and says most cases SHOULD use the last hashed subpacket.
    // RFC 9580 §5.2.3.35 Issuer Fingerprint must corroborate a caller-provided
    // full fingerprint; §5.2.3.12 Issuer Key ID is only the low 64 bits.
    let issuerFingerprint: string | undefined;
    for (const subpacket of sig.head.hashed as SignatureSubpacketType[])
      if (subpacket.TAG === 'issuerFingerprint') issuerFingerprint = subpacket.data.fingerprint;
    if (issuerFingerprint !== fingerprint) throw new Error('wrong fingerprint');
  }
  const { verified, hashPrefix } = verifyData(sig.head, data, sig.sig, publicKey, sig.salt);
  if (!equalBytes(hashPrefix, sig.hashPrefix)) return false;
  return verified;
}

/** Parsed primary Ed25519 secret-key material from an armored OpenPGP private key. */
export type ParsedPrivateKey = {
  /** Raw 32-byte Ed25519 private key seed extracted from the primary secret-key packet. */
  privateKey: Bytes;
  /** Primary key creation time as a UNIX timestamp in seconds. */
  created: number;
  /** Recomputed OpenPGP fingerprint for the extracted primary key. */
  fingerprint: string;
  /** Low-64-bit OpenPGP key ID derived from the recomputed fingerprint. */
  keyId: string;
  /** Raw 32-byte Ed25519 public key derived from `privateKey`. */
  publicKey: Bytes;
};

/**
 * This is a basic parsing to extract enough information to signDetached signatures.
 * Supports keys generated by us or PGP (ed25519 only + default opts), doesn't extract ECDH (x25519) keys.
 * @param privateKey - ASCII-armored private key block.
 * @param getPassword - Optional callback used to fetch the secret-key passphrase.
 * @returns Parsed secret key bytes and identifying metadata.
 * @throws If the armored packet layout, password callback, or decoded key material is invalid. {@link Error}
 * @example
 * Parse an armored secret key back into raw key bytes and OpenPGP metadata.
 * ```ts
 * import { randomBytes } from '@noble/hashes/utils.js';
 * import { getKeys, parsePrivateKey } from 'micro-key-producer/pgp.js';
 * const seed = randomBytes(32);
 * const { privateKey } = getKeys(seed, 'alice@example.com');
 * parsePrivateKey(privateKey).then(({ keyId }) => keyId);
 * ```
 */
export async function parsePrivateKey(
  privateKey: string,
  // NOTE: we cannot just provide password as argument since private key can be unprotected
  getPassword?: () => Promise<string>
): Promise<TRet<ParsedPrivateKey>> {
  privateKey = astring(privateKey, 'privateKey');
  if (getPassword !== undefined && typeof getPassword !== 'function')
    throw new TypeError(
      '"getPassword" expected function or undefined, got type=' + typeof getPassword
    );
  // This helper intentionally extracts only the primary Ed25519 secret packet
  // and recomputes fingerprint/keyId locally; it does not validate User IDs,
  // certifications, subkeys, or other transferable-key wrapper packets.
  const parsed = privArmor.decode(privateKey);
  const secretPacket = parsed.filter((i) => i.TAG === 'secretKey');
  if (secretPacket.length !== 1) throw new Error('multiple or zero secret keys');
  const secret = secretPacket[0].data;
  let password = '';
  if (secret.type.TAG !== 'plain') {
    if (!getPassword) throw new Error('no getPassword callback provided');
    // We don't know keyId at this point yet :(
    password = await getPassword(); // Ask user for password via UI?
  }
  const secretScalar = decodeSecretKey(password, secret);
  const secretBytes = numberToBytesBE(secretScalar, 32);
  const publicKey = ed25519.getPublicKey(secretBytes);
  const pubPGP = bytesToNumberBE(concatBytes(Uint8Array.of(0x40), publicKey));
  if (secret.pub.algo.TAG !== 'EdDSA' || secret.pub.algo.data.curve !== 'ed25519')
    throw new Error('unknown key format');
  if (pubPGP !== secret.pub.algo.data.pub) throw new Error('wrong publicKey, decoding failed');
  const created = secret.pub.created;
  const { fingerprint, keyId } = getKeyId(secretBytes, created);
  // TODO: check if there is certPositive with valid fingerprint?
  // const signatures = parsed.filter((i) => i.TAG === 'signature').map((i) => i.data);
  return {
    privateKey: secretBytes,
    created,
    fingerprint,
    keyId,
    publicKey,
  } as TRet<ParsedPrivateKey>;
}

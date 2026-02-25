/**
 * Converts public/secret keys into JWK or DER (PKCS#8 & SPKI).
 *
 * DER support is close to Web Crypto:
 * - No explicit curve definitions.
 * - No other curves like Brainpool or secp.
 * - Various possible encodings with different levels of support (e.g., optional public key),
 *   versions, etc. Attributes inside keys are ignored for now.
 * - We encode keys the same as Web Crypto by default.
 * - All returned keys match Web Crypto exactly.
 * - JWK keys include key usage. For P-256 and related curves, we use an additional
 *   `_jwk_ecdh` coder to encode keys for ECDH usage.
 *
 * ASN.1 is theoretically neat but overly complex:
 * - DER provides canonical encoding, but there are two valid locations for publicKey
 *   inside secretKey.
 * - OID-based encodings are fragmented across multiple RFCs.
 * - Crypto specs evolve inconsistently (e.g., EC, Ed25519, X25519 use different algorithms).
 * - Optional fields (attributes) can vary, leading to fingerprinting risks.
 *
 * We aim for a tree-shaking friendly interface:
 * - It's possible to use only JWK or only DER support.
 * - This mode hasn't been thoroughly tested in isolation.
 *
 * Curves and encoding:
 * - `isCompressed` in `getPublicKey` is fragile. Different curves may mishandle this flag.
 *   If always compressed, it's ignored.
 * - DER supports both compressed and uncompressed formats. We preserve the user-provided
 *   format during encoding.
 * - Secret keys: Ed25519 secrets are raw bytes; `Fn.fromBytes` may fail.
 * - Public keys are always points; X25519 lacks a dedicated `Point` class.
 *
 * TODO:
 * - Add more tests (e.g., Wycheproof SPKI vectors).
 * - Integrate with @noble/curves tests (despite circular deps).
 * - Support additional curves (Brainpool, secp...).
 * - Consider DER signature parsing (ASN.1 parser looks robust).
 * - Add RSA support (existing package available).
 * - Handle encrypted DER keys (unsupported by Web Crypto).
 * - Support explicit curve parameters (a/b, seed) — not common but present in some test vectors.
 * - Implement PEM conversion (Base64 armor).
 *
 * @module
 */
import { bytesToNumberBE } from '@noble/ciphers/utils.js';
import type { CurvePoint, CurvePointCons } from '@noble/curves/abstract/curve.js';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { ed448, x448 } from '@noble/curves/ed448.js';
import { p256, p384, p521 } from '@noble/curves/nist.js';
import { equalBytes, numberToVarBytesBE } from '@noble/curves/utils.js';
import { base64urlnopad, utils as baseUtils } from '@scure/base';
import * as P from 'micro-packed';

/** Utility */
interface JsonWebKey {
  crv?: string | undefined;
  d?: string | undefined;
  dp?: string | undefined;
  dq?: string | undefined;
  e?: string | undefined;
  k?: string | undefined;
  kty?: string | undefined;
  n?: string | undefined;
  p?: string | undefined;
  q?: string | undefined;
  qi?: string | undefined;
  x?: string | undefined;
  y?: string | undefined;
  [key: string]: unknown;
}
type ECConverter<T, Opts = {}> = {
  publicKey: P.Coder<Uint8Array, T>;
  secretKey: {
    encode(from: Uint8Array, opts?: Opts): T;
    decode(to: T): Uint8Array;
  };
};
// JWK
type BrokenCoder<T, A extends any[]> = {
  fromBytes(bytes: Uint8Array): T;
  toBytes(data: T, ...args: A): Uint8Array;
};
const fixCoder = /* @__PURE__ */ <A extends any[], T>(
  c: BrokenCoder<T, A>,
  ...args: A
): P.Coder<T, Uint8Array> => ({
  encode: (data: T) => c.toBytes(data, ...args),
  decode: (data: Uint8Array) => c.fromBytes(data),
});
type JwkBasic = { x: string };
type JwkAffine = { x: string; y: string };
function jwkPointCoder<P extends CurvePoint<any, P>>(
  pc: CurvePointCons<P>
): P.Coder<Uint8Array, JwkAffine> {
  const FpC = baseUtils.chain(fixCoder(pc.Fp), base64urlnopad);
  return {
    encode: (bytes: Uint8Array): JwkAffine => {
      const { x, y } = pc.fromBytes(bytes).toAffine();
      return { x: FpC.encode(x), y: FpC.encode(y) };
    },
    decode: (key: JwkAffine): Uint8Array =>
      pc.fromAffine({ x: FpC.decode(key.x), y: FpC.decode(key.y) }).toBytes(),
  };
}

const jwkBytesCoder: P.Coder<Uint8Array, JwkBasic> = {
  encode: (bytes: Uint8Array): JwkBasic => ({ x: base64urlnopad.encode(bytes) }),
  decode: (key: JwkBasic): Uint8Array => base64urlnopad.decode(key.x),
};

type Curve = typeof p256 | typeof ed25519 | typeof x25519;
type KeyUsage = 'deriveBits' | 'deriveKey' | 'sign' | 'verify';
type JWKConverter = ECConverter<JsonWebKey>;

function jwkConverter(
  curve: Curve,
  pubCoder: P.Coder<Uint8Array, JwkBasic> | P.Coder<Uint8Array, JwkAffine>,
  opts: JsonWebKey = {},
  derive: boolean
): JWKConverter {
  const secUsage: KeyUsage[] = derive ? ['deriveBits'] : ['sign'];
  const pubUsage: KeyUsage[] = derive ? [] : ['verify'];
  Object.freeze(opts);
  Object.freeze(pubUsage);
  Object.freeze(secUsage);
  function checkKey(key: JsonWebKey) {
    if (key.kty !== opts.kty || key.crv !== opts.crv || key.alg !== opts.alg)
      throw new Error('wrong curve');
  }
  const publicKey: P.Coder<Uint8Array, JsonWebKey> = {
    encode: (bytes: Uint8Array) => {
      if ('isValidPublicKey' in curve.utils) {
        if (!curve.utils.isValidPublicKey(bytes)) throw new Error('wrong public key');
      }
      return { ...opts, ext: true, key_ops: pubUsage, ...pubCoder.encode(bytes) };
    },
    decode: (key: JsonWebKey) => {
      checkKey(key);
      return pubCoder.decode(key as JwkAffine);
    },
  };
  const secretKey: P.Coder<Uint8Array, JsonWebKey> = {
    encode: (bytes: Uint8Array) => {
      const pub = curve.getPublicKey(bytes);
      return {
        ...publicKey.encode(pub),
        key_ops: secUsage,
        d: base64urlnopad.encode(bytes),
      };
    },
    decode: (key: JsonWebKey) => {
      const pub = publicKey.decode(key);
      const res = base64urlnopad.decode(key.d!);
      if (!equalBytes(pub, curve.getPublicKey(res))) throw new Error('wrong public key');
      return res;
    },
  };
  return { publicKey, secretKey };
}

/*
 * In @noble/curves we include a minimal, somewhat fragile ASN.1 DER decoder for signatures.
 * That approach works for simple signature structures, but here we face:
 *  - Complex nested ASN.1 structures
 *  - Multiple fields, optional fields, and versioned formats
 *
 * Any zero-dependency implementation would either re-implement large parts of micro-packed
 * or introduce a substantial amount of brittle code. Fortunately, this package already
 * depends on micro-packed.
 *
 * TODO:
 *   - Consider moving the signature coder into this package and removing it from @noble/curves.
 *     Consumers who need it could import it from here.
 *   - We’re partway toward full ASN.1 encoding/decoding for certificates—worth exploring further.
 *   - We can still use this API in @noble/curves tests despite circular dependencies by
 *     reconstructing coders with the actual curve import via this derConvert API.
 */
const ASN1 = /* @__PURE__ */ (() => {
  // All tags are not mandatory. Nevertheless, still included to see if something decoded wrong
  const tagPrimitive = /* @__PURE__ */ P.map(P.bits(5), {
    boolean: 1,
    integer: 2,
    bitString: 3,
    octetString: 4,
    null: 5,
    oid: 6,
    real: 9,
    enum: 10,
    utf8: 12,
    relativeOid: 13,
    sequence: 16,
    set: 17,
    numericString: 18,
    printableString: 19, // A–Z, 0–9, space, limited symbols
    teletexString: 20,
    videotexString: 21,
    IA5String: 22,
    UTCTime: 23,
    generalizedTime: 24,
    visibleString: 26,
    generalString: 27,
    bmpString: 30, // UCS-2 (2 bytes per char)
  });
  const tagNumber = /* @__PURE__ */ P.validate(P.bits(5), (n: number) => {
    if (n === 0b11111) throw new Error('multi-byte tags not supported');
    return n;
  });
  const tag = /* @__PURE__ */ P.validate(
    P.mappedTag(P.bits(2), {
      universal: [0, P.struct({ constructed: P.bits(1), type: tagPrimitive })],
      application: [1, P.struct({ constructed: P.bits(1), number: tagNumber })],
      contextSpecific: [2, P.struct({ constructed: P.bits(1), number: tagNumber })],
      private: [3, P.struct({ constructed: P.bits(1), number: tagNumber })],
    }),
    (val) => {
      if (val.TAG === 'universal') {
        if (['sequence', 'set'].includes(val.data.type)) {
          if (!val.data.constructed) throw new Error('SEQUENCE/SET must be constructed in DER');
        } else if (val.data.constructed)
          throw new Error('Constructed encoding forbidden for this universal tag in DER');
      }
      return val;
    }
  );
  // TODO: add dynamic size support to P.bigint/P.int? seems needed only here.
  // would be P.int(P.bits(7)). Seems easy, but not sure if its worth it.
  const varInt = /* @__PURE__ */ P.apply(P.bytes(P.bits(7)), {
    encode: (from: Uint8Array) => P.int(from.length).decode(from),
    decode: (to: number) => numberToVarBytesBE(to),
  });

  const length = /* @__PURE__ */ P.apply(
    P.mappedTag(P.bits(1), {
      short: [0, P.bits(7)],
      long: [1, varInt],
    }),
    {
      encode: (from) => from.data,
      decode: (to) => ({ TAG: to < 0x80 ? ('short' as const) : ('long' as const), data: to }),
    }
  );
  const tlv = /* @__PURE__ */ P.struct({ tag, data: P.bytes(length) });
  type ASN1Coder<T> = P.CoderType<T> & {
    tagByte: number;
    constructed: number;
    inner: P.CoderType<T>;
  };
  const basic = <T>(typeTag: P.UnwrapCoder<typeof tag>, inner: P.CoderType<T>): ASN1Coder<T> => {
    return {
      tagByte: tag.encode(typeTag)[0],
      constructed: typeTag.data.constructed,
      inner,
      ...P.wrap({
        encodeStream(w, value) {
          tlv.encodeStream(w, {
            tag: typeTag,
            data: inner.encode(value),
          });
        },
        decodeStream(r) {
          return inner.decode(tlv.decodeStream(r).data);
        },
      }),
    };
  };
  // Primitive types
  const Integer = basic(
    { TAG: 'universal', data: { constructed: 0, type: 'integer' } },
    P.wrap({
      encodeStream(w, value) {
        if (value < 0) throw new Error('negative values not allowed');
        const bytes = numberToVarBytesBE(value);
        if (bytes[0] & 0x80) w.byte(0x00); // prepend 0x00 for positive
        w.bytes(bytes);
      },
      decodeStream(r) {
        const bytes = r.bytes(r.leftBytes); // up to known length
        if (bytes[0] & 0x80) throw new Error('negative values not allowed');
        return bytesToNumberBE(bytes);
      },
    }) satisfies P.CoderType<bigint>
  );
  // TODO: merge with PGP? This is more robust (different results). Looks like LEB128 (wasm stuff)
  const OID = basic(
    { TAG: 'universal', data: { constructed: 0, type: 'oid' } },
    P.wrap({
      encodeStream(w, oidStr) {
        const parts = oidStr.split('.').map(Number);
        if (parts.length < 2) throw new Error('OID must have at least two arcs');
        const [first, second, ...rest] = parts;
        if (first < 0 || first > 2) throw new Error('First arc out of range');
        if ((first < 2 && second > 39) || second < 0)
          throw new Error('Second arc out of range for first arc');
        // Combine first two arcs into single value
        let combined = 40 * first + second;
        // P.array({continue: P.bits(1), value: P.bits(7)}), then when !continue push current value to out.
        // But we would need to read number from left side
        const out: number[] = [];
        // Base-128 encode (highest bit signals continuation, not just radix2**7)
        const encodeBase128 = (val: number) => {
          const tmp: number[] = [];
          for (let v = val; v; v >>= 7) tmp.unshift(v & 0x7f);
          if (!val) tmp.push(0);
          for (let i = 0; i < tmp.length - 1; i++) out.push(tmp[i] | 0x80);
          out.push(tmp[tmp.length - 1]);
        };
        encodeBase128(combined);
        for (const val of rest) {
          if (val < 0) throw new Error('Negative OID arc');
          encodeBase128(val);
        }
        w.bytes(Uint8Array.from(out));
      },
      decodeStream(r) {
        const bytes = r.bytes(r.leftBytes); // Must already be scoped to OID length
        if (bytes.length === 0) throw new Error('Empty OID encoding');
        const firstVal = bytes[0];
        const firstArc = Math.floor(firstVal / 40);
        const secondArc = firstVal % 40;
        const out: number[] = [firstArc, secondArc];
        let val = 0;
        for (let i = 1; i < bytes.length; i++) {
          val = (val << 7) | (bytes[i] & 0x7f);
          if ((bytes[i] & 0x80) === 0) {
            out.push(val);
            val = 0;
          }
        }
        if (val !== 0) throw new Error('Truncated OID encoding');
        // Range check
        if ((out[0] < 2 && out[1] > 39) || out[1] < 0) throw new Error('Invalid OID second arc');
        return out.join('.');
      },
    }) satisfies P.CoderType<string>
  );
  const OctetString = basic(
    { TAG: 'universal', data: { constructed: 0, type: 'octetString' } },
    P.bytes(null)
  );
  const BitString = basic(
    { TAG: 'universal', data: { constructed: 0, type: 'bitString' } },
    P.wrap({
      encodeStream(w, value) {
        w.byte(0);
        w.bytes(value);
      },
      decodeStream(r) {
        const leftBits = r.byte();
        if (leftBits !== 0) throw new Error('ASN1.bitString: non-zero amount of leftover bits');
        return r.bytes(r.leftBytes);
      },
    }) satisfies P.CoderType<Uint8Array>
  );
  const sequence = <T extends Record<string, any>>(fields: P.StructRecord<T>) => {
    return basic(
      { TAG: 'universal', data: { constructed: 1, type: 'sequence' } },
      P.struct(fields)
    );
  };
  type ChoiceResult<T extends Record<string, ASN1Coder<any>>> = {
    [K in keyof T]: { TAG: K; data: P.UnwrapCoder<T[K]> };
  }[keyof T];
  const choice = <T extends Record<string, ASN1Coder<any>>>(
    variants: T
  ): P.CoderType<ChoiceResult<T>> =>
    P.wrap({
      encodeStream(w, value: ChoiceResult<T>) {
        if (!value.TAG || !variants[value.TAG])
          throw new Error('ASN1.choice: unknown variant=' + (value.TAG as string));
        variants[value.TAG].encodeStream(w, value.data);
      },
      decodeStream(r): ChoiceResult<T> {
        const tag = r.byte(true);
        for (const k in variants) {
          const v = variants[k];
          if (v.tagByte === tag) return { TAG: k, data: v.decodeStream(r) };
        }
        throw new Error('ASN1.choice: unknown variant=' + tag);
      },
    });

  // Small schema-less parser for debug. Useful to see whats going on inside, but not enough for schema parsing.
  const debug: P.CoderType<any> = P.apply(tlv, {
    encode(from: any) {
      if (from.tag.TAG === 'universal') {
        if (['sequence', 'set'].includes(from.tag.data.type))
          return P.array(null, debug).decode(from.data);
        if (from.tag.data.type === 'integer') return Integer.inner.decode(from.data);
        if (from.tag.data.type === 'oid') return OID.inner.decode(from.data);
        if (from.tag.data.type === 'octetString') return OctetString.inner.decode(from.data);
        if (from.tag.data.type === 'null') return null;
      }
      if (from.tag.TAG === 'contextSpecific' && from.tag.data.constructed)
        return debug.decode(from.data);
      return from;
    },
    decode(_to: any) {
      // Without schema we cannot know how to encode stuff (is Uint8Array is octetString or bitString?)
      throw new Error('not supported');
    },
  });
  return {
    debug,
    Integer,
    OctetString,
    OID,
    BitString,
    UTF8: basic({ TAG: 'universal', data: { constructed: 0, type: 'utf8' } }, P.string(null)),
    null: basic({ TAG: 'universal', data: { constructed: 0, type: 'null' } }, P.constant(null)),
    choice,
    sequence,
    set: <T>(inner: P.CoderType<T>) =>
      basic({ TAG: 'universal', data: { constructed: 1, type: 'set' } }, P.array(null, inner)),
    explicit: <T>(number: number, inner: P.CoderType<T>) =>
      basic({ TAG: 'contextSpecific', data: { constructed: 1, number } }, inner),
    implicit: <T>(number: number, inner: ASN1Coder<T>) =>
      basic(
        { TAG: 'contextSpecific', data: { constructed: inner.constructed, number } },
        inner.inner
      ), // hides actual tag
    optional: <T>(inner: ASN1Coder<T>): ASN1Coder<T | undefined> => {
      return {
        tagByte: inner.tagByte,
        inner: inner.inner as P.CoderType<T | undefined>,
        constructed: inner.constructed,
        ...P.wrap({
          encodeStream(w, value) {
            if (value === undefined) return;
            inner.encodeStream(w, value);
          },
          decodeStream(r) {
            if (r.isEnd()) return undefined;
            const tag = r.byte(true);
            if (tag !== inner.tagByte) return undefined;
            return inner.decodeStream(r);
          },
        }),
      };
    },
  };
})();
// https://www.rfc-editor.org/rfc/rfc5480
// https://www.rfc-editor.org/rfc/rfc5915
// https://www.rfc-editor.org/rfc/rfc5958
// https://www.rfc-editor.org/rfc/rfc8410
const SpecifiedECDomain = /* @__PURE__ */ ASN1.sequence({
  version: ASN1.Integer, // 1 | 2 | 3. 1 -> hash optional, 2|3 -> hash mandatory, 3 -> maybe extra params
  fieldId: ASN1.sequence({
    info: P.mappedTag(ASN1.OID, {
      primeField: ['1.2.840.10045.1.1', ASN1.Integer],
      binaryField: ['1.2.840.10045.1.2', P.bytes(null)], // a lot of stuff, basises, polynominals, too complex
    }),
  }),
  curve: ASN1.sequence({
    a: ASN1.OctetString,
    b: ASN1.OctetString,
    seed: ASN1.optional(ASN1.BitString),
  }),
  base: ASN1.OctetString,
  order: ASN1.Integer,
  cofactor: ASN1.optional(ASN1.Integer),
  hash: ASN1.optional(ASN1.sequence({ algorithm: ASN1.OID, rest: P.bytes(null) })),
  rest: P.bytes(null),
});

const ECParameters = /* @__PURE__ */ ASN1.choice({
  namedCurve: ASN1.OID,
  implicitCurve: ASN1.null,
  specifiedCurve: SpecifiedECDomain,
});
// We can re-use for pub/secret only without RSA. RSA algorithm is different.
const KeyAlgorithm = /* @__PURE__ */ ASN1.sequence({
  info: P.mappedTag(ASN1.OID, {
    // Maps webcrypto stuff, Ed/X attached
    EC: ['1.2.840.10045.2.1', ECParameters],
    X25519: ['1.3.101.110', P.constant(null)], // X25519
    X448: ['1.3.101.111', P.constant(null)], // X448
    Ed25519: ['1.3.101.112', P.constant(null)], // Ed25519
    Ed448: ['1.3.101.113', P.constant(null)], // Ed448
    rsaEncryption: ['1.2.840.113549.1.1.1', ASN1.null],
    // For micro-rsa-dsa-dh support: don't want to add yet, because it's an extra dependency.
    // rsassaPss: ['1.2.840.113549.1.1.10', sequence(hashAlgorithm, maskGenAlgorithm, saltLength, trailerField)]
    // rsaesOaep: ['1.2.840.113549.1.1.7', sequence(hashAlgorithm, maskGenAlgorithm, pSourceAlgorithm)]
    // Easy to parse, works as additional test for parser structure.
    DSA: [
      '1.2.840.10040.4.1',
      ASN1.sequence({ p: ASN1.Integer, q: ASN1.Integer, g: ASN1.Integer }),
    ],
  }),
});
// TODO: this is nice, but we cannot put all OIDS here, so, lets do P.bytes(null)?
// On other hand, if there is some issues with encoding, we will convert key, but other stuff will fail on it
// const DirectoryString = ASN1.choice({
//   utf8: ASN1.UTF8,
// });
// const Attributes = ASN1.set(
//   ASN1.sequence({
//     attribute: P.mappedTag(ASN1.OID, {
//       // 1.2.840.113549.1.9.9.20
//       friendlyName2: ['1.2.840.113549.1.9.9.20', ASN1.set(DirectoryString)],
//       friendlyName: ['1.2.840.113549.1.9.20', ASN1.set(DirectoryString)],
//       localKeyId: ['1.2.840.113549.1.9.21', ASN1.set(ASN1.OctetString)],
//       challengePassword: ['1.2.840.113549.1.9.7', ASN1.set(DirectoryString)],
//     }),
//   })
// );
const Attributes = /* @__PURE__ */ ASN1.set(P.bytes(null));
type RSAKey = {
  version: bigint;
  modulus: bigint;
  publicExponent: bigint;
  privateExponent: bigint;
  prime1: bigint;
  prime2: bigint;
  exponent1: bigint;
  exponent2: bigint;
  coefficient: bigint;
};
type ECParams =
  | { TAG: 'namedCurve'; data: string }
  | { TAG: 'implicitCurve'; data: null }
  | { TAG: 'specifiedCurve'; data: unknown };
type KeyInfo =
  | { TAG: 'EC'; data: ECParams }
  | { TAG: 'X25519'; data: null }
  | { TAG: 'X448'; data: null }
  | { TAG: 'Ed25519'; data: null }
  | { TAG: 'Ed448'; data: null }
  | { TAG: 'rsaEncryption'; data: null }
  | { TAG: 'DSA'; data: unknown };
type Algo = { info: KeyInfo };
type PKCS8Secret =
  | {
      TAG: 'raw';
      data: Uint8Array;
    }
  | {
      TAG: 'struct';
      data: {
        version: bigint;
        privateKey: Uint8Array;
        parameters?: ECParams;
        publicKey?: Uint8Array;
      };
    };
type PKCS8Key = {
  version: bigint;
  algorithm: Algo;
  privateKey: PKCS8Secret;
  attributes?: Uint8Array[];
  publicKey?: Uint8Array;
};
type SPKIKey = { algorithm: Algo; publicKey: Uint8Array };
type ASN1TagCoder<T> = P.CoderType<T> & {
  tagByte: number;
  constructed: number;
  inner: P.CoderType<T>;
};
type ASN1Pub = {
  debug: P.CoderType<any>;
  Integer: ASN1TagCoder<bigint>;
  OctetString: ASN1TagCoder<Uint8Array>;
  OID: ASN1TagCoder<string>;
  BitString: ASN1TagCoder<Uint8Array>;
  UTF8: ASN1TagCoder<string>;
  null: ASN1TagCoder<null>;
  choice: <T extends Record<string, P.CoderType<any>>>(
    variants: T
  ) => P.CoderType<{ [K in keyof T]: { TAG: K; data: P.UnwrapCoder<T[K]> } }[keyof T]>;
  sequence: <T extends Record<string, any>>(fields: P.StructRecord<T>) => ASN1TagCoder<T>;
  set: <T>(inner: P.CoderType<T>) => ASN1TagCoder<T[]>;
  explicit: <T>(number: number, inner: P.CoderType<T>) => ASN1TagCoder<T>;
  implicit: <T>(number: number, inner: ASN1TagCoder<T>) => ASN1TagCoder<T>;
  optional: <T>(inner: ASN1TagCoder<T>) => ASN1TagCoder<T | undefined>;
};
type DERUtilsPub = {
  BER: {
    decode: (
      src: Uint8Array,
      opts?: { allowBER?: boolean }
    ) => { nodes: BerNode[]; der: Uint8Array };
    encode: (nodes: BerNode[], der: Uint8Array) => Uint8Array;
    normalize: (src: Uint8Array, opts?: { allowBER?: boolean }) => Uint8Array;
  };
  ASN1: ASN1Pub;
  RSAPrivateKey: P.CoderType<RSAKey>;
  PKCS8SecretKey: P.CoderType<PKCS8Secret>;
  PKCS8: P.CoderType<PKCS8Key>;
  SPKI: P.CoderType<SPKIKey>;
};
const cat = (parts: Uint8Array[]): Uint8Array => {
  const len = parts.reduce((a, b) => a + b.length, 0);
  const out = new Uint8Array(len);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
};
const lenDer = (len: number): Uint8Array => {
  if (!Number.isSafeInteger(len) || len < 0) throw new Error(`invalid length ${len}`);
  if (len < 0x80) return Uint8Array.from([len]);
  const out: number[] = [];
  for (let n = len; n > 0; n >>= 8) out.unshift(n & 0xff);
  return Uint8Array.from([0x80 | out.length, ...out]);
};
type BerNode = {
  len: number;
  lenBytes: number;
  indefinite: boolean;
  bitUnused?: number;
  children?: BerNode[];
  cls: number;
  tagNum: number;
  cons: boolean;
};
type BerRawNode = {
  tag: Uint8Array;
  len: Uint8Array;
  indefinite: boolean;
  children?: BerRawNode[];
  der: Uint8Array;
  value: Uint8Array;
  pos: number;
  cls: number;
  tagNum: number;
  cons: boolean;
};
const berParseTag = (
  src: Uint8Array,
  pos: number
): { bytes: Uint8Array; pos: number; cls: number; cons: boolean; tagNum: number } => {
  const a = src[pos++];
  if (a === undefined) throw new Error('unexpected end of input');
  const cls = a >>> 6;
  const cons = !!(a & 0x20);
  let tagNum = a & 0x1f;
  const out: number[] = [a];
  if (tagNum !== 0x1f) return { bytes: Uint8Array.from(out), pos, cls, cons, tagNum };
  tagNum = 0;
  while (true) {
    const b = src[pos++];
    if (b === undefined) throw new Error('unexpected end of high-tag-number');
    out.push(b);
    tagNum = (tagNum << 7) | (b & 0x7f);
    if (!(b & 0x80)) break;
  }
  return { bytes: Uint8Array.from(out), pos, cls, cons, tagNum };
};
const berParseLen = (
  src: Uint8Array,
  pos: number
): { pos: number; len?: number; indefinite: boolean } => {
  const a = src[pos++];
  if (a === undefined) throw new Error('unexpected end of length');
  if (a < 0x80) return { pos, len: a, indefinite: false };
  if (a === 0x80) return { pos, indefinite: true };
  const n = a & 0x7f;
  if (!n) throw new Error('invalid length header');
  if (pos + n > src.length) throw new Error('length overrun');
  let len = 0;
  for (let i = 0; i < n; i++) len = (len << 8) | src[pos + i];
  return { pos: pos + n, len, indefinite: false };
};
const berParse = (src: Uint8Array, pos: number, allowBER: boolean): BerRawNode => {
  const tg = berParseTag(src, pos);
  pos = tg.pos;
  const ln = berParseLen(src, pos);
  const lenBytes = src.slice(pos, ln.pos);
  pos = ln.pos;
  const child = (): BerRawNode => berParse(src, pos, allowBER);
  const primitiveTypes = new Set([
    1, 2, 3, 4, 5, 6, 9, 10, 12, 13, 18, 19, 20, 21, 22, 23, 24, 26, 27, 30,
  ]);
  if (ln.indefinite) {
    if (!allowBER) throw new Error('BER indefinite length is not allowed');
    if (!tg.cons) throw new Error('BER indefinite length requires constructed tag');
    const nodes: BerRawNode[] = [];
    while (true) {
      if (src[pos] === 0x00 && src[pos + 1] === 0x00) {
        pos += 2;
        break;
      }
      const n = child();
      nodes.push(n);
      pos = n.pos;
    }
    const constructed = cat(nodes.map((i) => i.der));
    if (tg.cls === 0 && primitiveTypes.has(tg.tagNum) && tg.tagNum !== 16 && tg.tagNum !== 17) {
      if (!allowBER) throw new Error('BER constructed primitive is not allowed');
      const outTag = tg.bytes.slice();
      outTag[0] &= ~0x20;
      if (tg.tagNum === 3) {
        if (!nodes.length)
          return {
            tag: tg.bytes,
            len: lenBytes,
            indefinite: true,
            children: nodes,
            der: cat([outTag, lenDer(1), Uint8Array.from([0])]),
            value: Uint8Array.from([0]),
            pos,
            cls: tg.cls,
            tagNum: tg.tagNum,
            cons: tg.cons,
          };
        const parts: Uint8Array[] = [];
        let unused = 0;
        for (let i = 0; i < nodes.length; i++) {
          const v = nodes[i].value;
          if (!v.length) throw new Error('invalid constructed BIT STRING chunk');
          const u = v[0];
          if (i < nodes.length - 1 && u !== 0)
            throw new Error('invalid constructed BIT STRING intermediate chunk');
          unused = u;
          parts.push(v.slice(1));
        }
        const value = cat([Uint8Array.from([unused]), ...parts]);
        return {
          tag: tg.bytes,
          len: lenBytes,
          indefinite: true,
          children: nodes,
          der: cat([outTag, lenDer(value.length), value]),
          value,
          pos,
          cls: tg.cls,
          tagNum: tg.tagNum,
          cons: tg.cons,
        };
      }
      const value = cat(nodes.map((i) => i.value));
      return {
        tag: tg.bytes,
        len: lenBytes,
        indefinite: true,
        children: nodes,
        der: cat([outTag, lenDer(value.length), value]),
        value,
        pos,
        cls: tg.cls,
        tagNum: tg.tagNum,
        cons: tg.cons,
      };
    }
    return {
      tag: tg.bytes,
      len: lenBytes,
      indefinite: true,
      children: nodes,
      der: cat([tg.bytes, lenDer(constructed.length), constructed]),
      value: constructed,
      pos,
      cls: tg.cls,
      tagNum: tg.tagNum,
      cons: tg.cons,
    };
  }
  if (ln.len === undefined) throw new Error('length missing');
  if (pos + ln.len > src.length) throw new Error('length overrun');
  const valueRaw = src.slice(pos, pos + ln.len);
  pos += ln.len;
  if (!tg.cons)
    return {
      tag: tg.bytes,
      len: lenBytes,
      indefinite: false,
      der: cat([tg.bytes, lenDer(valueRaw.length), valueRaw]),
      value: valueRaw,
      pos,
      cls: tg.cls,
      tagNum: tg.tagNum,
      cons: tg.cons,
    };
  const nodes: BerRawNode[] = [];
  let at = 0;
  while (at < valueRaw.length) {
    const n = berParse(valueRaw, at, allowBER);
    nodes.push(n);
    at = n.pos;
  }
  if (at !== valueRaw.length) throw new Error('constructed value parse mismatch');
  const constructed = cat(nodes.map((i) => i.der));
  if (tg.cls === 0 && primitiveTypes.has(tg.tagNum) && tg.tagNum !== 16 && tg.tagNum !== 17) {
    if (!allowBER) throw new Error('BER constructed primitive is not allowed');
    const outTag = tg.bytes.slice();
    outTag[0] &= ~0x20;
    const value =
      tg.tagNum === 3
        ? (() => {
            if (!nodes.length) return Uint8Array.from([0]);
            const parts: Uint8Array[] = [];
            let unused = 0;
            for (let i = 0; i < nodes.length; i++) {
              const v = nodes[i].value;
              if (!v.length) throw new Error('invalid constructed BIT STRING chunk');
              const u = v[0];
              if (i < nodes.length - 1 && u !== 0)
                throw new Error('invalid constructed BIT STRING intermediate chunk');
              unused = u;
              parts.push(v.slice(1));
            }
            return cat([Uint8Array.from([unused]), ...parts]);
          })()
        : cat(nodes.map((i) => i.value));
    return {
      tag: tg.bytes,
      len: lenBytes,
      indefinite: false,
      children: nodes,
      der: cat([outTag, lenDer(value.length), value]),
      value,
      pos,
      cls: tg.cls,
      tagNum: tg.tagNum,
      cons: tg.cons,
    };
  }
  return {
    tag: tg.bytes,
    len: lenBytes,
    indefinite: false,
    children: nodes,
    der: cat([tg.bytes, lenDer(constructed.length), constructed]),
    value: constructed,
    pos,
    cls: tg.cls,
    tagNum: tg.tagNum,
    cons: tg.cons,
  };
};
const berTag = (cls: number, cons: boolean, tagNum: number): Uint8Array => {
  if (!Number.isInteger(cls) || cls < 0 || cls > 3) throw new Error(`invalid BER class ${cls}`);
  if (!Number.isInteger(tagNum) || tagNum < 0) throw new Error(`invalid BER tag number ${tagNum}`);
  const c = cons ? 0x20 : 0x00;
  if (tagNum < 31) return Uint8Array.from([(cls << 6) | c | tagNum]);
  const out: number[] = [(cls << 6) | c | 0x1f];
  const parts: number[] = [];
  for (let n = tagNum; n > 0; n >>= 7) parts.unshift(n & 0x7f);
  if (!parts.length) parts.push(0);
  for (let i = 0; i < parts.length - 1; i++) out.push(parts[i] | 0x80);
  out.push(parts[parts.length - 1]);
  return Uint8Array.from(out);
};
const berMeta = (n: BerRawNode): BerNode => ({
  len: n.value.length,
  lenBytes: n.indefinite ? 0 : n.len[0] < 0x80 ? 1 : 1 + (n.len[0] & 0x7f),
  indefinite: n.indefinite,
  bitUnused: n.cls === 0 && n.tagNum === 3 && !n.cons && n.value.length ? n.value[0] : undefined,
  children: n.children?.map(berMeta),
  cls: n.cls,
  tagNum: n.tagNum,
  cons: n.cons,
});
const berBuildRaw = (cls: number, tagNum: number, value: Uint8Array): BerRawNode => ({
  tag: berTag(cls, false, tagNum),
  len: lenDer(value.length),
  indefinite: false,
  der: cat([berTag(cls, false, tagNum), lenDer(value.length), value]),
  value,
  pos: 0,
  cls,
  tagNum,
  cons: false,
});
const berSplitPrimitive = (n: BerRawNode, metaChildren: BerNode[]): BerRawNode[] | undefined => {
  if (n.cls !== 0) return undefined;
  if (n.tagNum === 4) {
    let at = 0;
    const out: BerRawNode[] = [];
    for (const m of metaChildren) {
      const len = m.len;
      if (!Number.isInteger(len) || len < 0 || at + len > n.value.length) return undefined;
      const v = n.value.slice(at, at + len);
      out.push(berBuildRaw(n.cls, n.tagNum, v));
      at += len;
    }
    if (at !== n.value.length) return undefined;
    return out;
  }
  if (n.tagNum === 3) {
    if (!n.value.length) return undefined;
    const u = n.value[0];
    const bits = n.value.slice(1);
    let at = 0;
    const out: BerRawNode[] = [];
    for (let i = 0; i < metaChildren.length; i++) {
      const m = metaChildren[i];
      if (!Number.isInteger(m.len) || m.len < 1) return undefined;
      const dlen = m.len - 1;
      if (at + dlen > bits.length) return undefined;
      const cu = i + 1 === metaChildren.length ? u : m.bitUnused || 0;
      const v = cat([Uint8Array.from([cu]), bits.slice(at, at + dlen)]);
      out.push(berBuildRaw(n.cls, n.tagNum, v));
      at += dlen;
    }
    if (at !== bits.length) return undefined;
    return out;
  }
  return undefined;
};
const berLen = (len: number, lenBytes: number): Uint8Array => {
  if (!Number.isSafeInteger(len) || len < 0) throw new Error(`invalid BER length ${len}`);
  if (!Number.isSafeInteger(lenBytes) || lenBytes < 1)
    throw new Error(`invalid BER length-size ${lenBytes}`);
  if (lenBytes === 1) {
    if (len >= 0x80) throw new Error(`short BER length cannot encode ${len}`);
    return Uint8Array.from([len]);
  }
  const width = lenBytes - 1;
  let n = len;
  const out = new Uint8Array(lenBytes);
  out[0] = 0x80 | width;
  for (let i = lenBytes - 1; i >= 1; i--) {
    out[i] = n & 0xff;
    n >>>= 8;
  }
  if (n) throw new Error(`BER length ${len} does not fit ${width} bytes`);
  return out;
};
const berNode = (n: BerRawNode, meta: BerNode): Uint8Array => {
  if (meta.cls !== n.cls || meta.tagNum !== n.tagNum)
    throw new Error(
      `BER tag mismatch expected cls=${meta.cls} tag=${meta.tagNum}, got cls=${n.cls} tag=${n.tagNum}`
    );
  const tag = berTag(meta.cls, meta.cons, meta.tagNum);
  if (!meta.cons) {
    const v = n.value;
    if (meta.indefinite) throw new Error('BER primitive cannot use indefinite length');
    return cat([tag, berLen(v.length, meta.lenBytes), v]);
  }
  const srcChildren = n.cons ? n.children || [] : berSplitPrimitive(n, meta.children || []);
  const mm = meta.children || [];
  if (!srcChildren || srcChildren.length !== mm.length) throw new Error('BER child shape mismatch');
  const body = cat(srcChildren.map((c, i) => berNode(c, mm[i])));
  if (meta.indefinite)
    return cat([tag, Uint8Array.from([0x80]), body, Uint8Array.from([0x00, 0x00])]);
  return cat([tag, berLen(body.length, meta.lenBytes), body]);
};
const BER = {
  decode: (src: Uint8Array, opts: { allowBER?: boolean } = {}) => {
    const allowBER = !!opts.allowBER;
    const nodes: BerNode[] = [];
    const der: Uint8Array[] = [];
    let pos = 0;
    while (pos < src.length) {
      const n = berParse(src, pos, allowBER);
      nodes.push(berMeta(n));
      der.push(n.der);
      pos = n.pos;
    }
    return { nodes, der: cat(der) };
  },
  encode: (nodes: BerNode[], der: Uint8Array) => {
    const rawNodes: BerRawNode[] = [];
    let pos = 0;
    while (pos < der.length) {
      const n = berParse(der, pos, false);
      rawNodes.push(n);
      pos = n.pos;
    }
    if (rawNodes.length !== nodes.length) throw new Error('BER root node count mismatch');
    return cat(rawNodes.map((n, i) => berNode(n, nodes[i])));
  },
  normalize: (src: Uint8Array, opts: { allowBER?: boolean } = {}): Uint8Array => {
    const allowBER = !!opts.allowBER;
    const out: Uint8Array[] = [];
    let pos = 0;
    while (pos < src.length) {
      const n = berParse(src, pos, allowBER);
      out.push(n.der);
      pos = n.pos;
    }
    return cat(out);
  },
} as const;
// RFC 8017 A.1.2: RSAPrivateKey structure (PKCS #1 v2.2).
const RSAPrivateKey = /* @__PURE__ */ ASN1.sequence({
  version: ASN1.Integer,
  modulus: ASN1.Integer,
  publicExponent: ASN1.Integer,
  privateExponent: ASN1.Integer,
  prime1: ASN1.Integer,
  prime2: ASN1.Integer,
  exponent1: ASN1.Integer,
  exponent2: ASN1.Integer,
  coefficient: ASN1.Integer,
});
const PKCS8SecretKey = /* @__PURE__ */ ASN1.choice({
  raw: ASN1.OctetString,
  struct: ASN1.sequence({
    version: ASN1.Integer,
    privateKey: ASN1.OctetString,
    parameters: ASN1.optional(ASN1.explicit(0, ECParameters)),
    publicKey: ASN1.optional(ASN1.explicit(1, ASN1.BitString)),
  }),
});
const PKCS8 = /* @__PURE__ */ ASN1.sequence({
  version: ASN1.Integer,
  algorithm: KeyAlgorithm,
  privateKey: P.apply(ASN1.OctetString, P.coders.reverse(PKCS8SecretKey)),
  attributes: ASN1.optional(ASN1.implicit(0, Attributes)),
  publicKey: ASN1.optional(ASN1.implicit(1, ASN1.BitString)),
});
const SPKI = /* @__PURE__ */ ASN1.sequence({
  algorithm: KeyAlgorithm,
  publicKey: ASN1.BitString,
});

// Could be beautifully typed, but because of isolatedDeclarations, we return garbage.
export const DERUtils: DERUtilsPub = /* @__PURE__ */ {
  BER,
  ASN1: ASN1 as unknown as ASN1Pub,
  RSAPrivateKey: RSAPrivateKey as unknown as P.CoderType<RSAKey>,
  PKCS8SecretKey: PKCS8SecretKey as unknown as P.CoderType<PKCS8Secret>,
  PKCS8: PKCS8 as unknown as P.CoderType<PKCS8Key>,
  SPKI: SPKI as unknown as P.CoderType<SPKIKey>,
};

type DEROpts = {
  noPublicKey?: boolean;
  compressed?: boolean;
};

type DERConverter = ECConverter<Uint8Array, DEROpts>;
export const CurveOID = {
  'P-256': '1.2.840.10045.3.1.7',
  'P-384': '1.3.132.0.34',
  'P-521': '1.3.132.0.35',
} as const;
export const curveOID = (oid: string): keyof typeof CurveOID => {
  for (const c in CurveOID)
    if (CurveOID[c as keyof typeof CurveOID] === oid) return c as keyof typeof CurveOID;
  throw new Error(`unsupported EC namedCurve OID ${oid}`);
};
function derConverter(
  curve: Curve,
  info: P.UnwrapCoder<typeof KeyAlgorithm>['info']
): DERConverter {
  function checkParams(params: P.UnwrapCoder<typeof ECParameters>) {
    if (params.TAG !== 'namedCurve') throw new Error('non-named curves not supported');
  }
  function checkAlgo(keyInfo: P.UnwrapCoder<typeof KeyAlgorithm>['info']) {
    if (keyInfo.TAG !== info.TAG) throw new Error('different curve algorithm');
    if (keyInfo.TAG === 'EC' && info.TAG === 'EC') {
      checkParams(keyInfo.data);
      if (keyInfo.data.data !== info.data.data) throw new Error('different curve');
    }
  }
  if (info.TAG === 'EC') checkParams(info.data);
  const publicKey: P.Coder<Uint8Array, Uint8Array> = {
    encode: (key: Uint8Array) => {
      if ('isValidPublicKey' in curve.utils) {
        if (!curve.utils.isValidPublicKey(key)) throw new Error('wrong public key');
      }
      // we encode what was given always by user (no method to uncompress public key without deps on point)
      return SPKI.encode({ algorithm: { info }, publicKey: key });
    },
    decode: (key: Uint8Array) => {
      const decoded = SPKI.decode(key);
      checkAlgo(decoded.algorithm.info);
      const publicKey = decoded.publicKey;
      if ('isValidPublicKey' in curve.utils) {
        if (!curve.utils.isValidPublicKey(publicKey)) throw new Error('wrong public key');
      }
      return publicKey;
    },
  };
  // There also encrypted version of PKCS8, not supported in webcrypto, not supported by us (yet?)
  const secretKey: P.Coder<Uint8Array, Uint8Array> = {
    encode: (key: Uint8Array, opts: DEROpts = {}): Uint8Array => {
      if ('isValidSecretKey' in curve.utils) {
        if (!curve.utils.isValidSecretKey(key)) throw new Error('wrong secret key');
      }
      // uncompressed by default (compat with webcrypto)
      const publicKey = opts.noPublicKey
        ? undefined
        : info.TAG === 'EC'
          ? curve.getPublicKey(key, !!opts.compressed) // only in weierstrass
          : curve.getPublicKey(key);
      const privateKey =
        info.TAG === 'EC'
          ? ({ TAG: 'struct', data: { version: 1n, privateKey: key, publicKey } } as const)
          : ({ TAG: 'raw', data: key } as const);
      return PKCS8.encode({ version: 0n, algorithm: { info }, privateKey });
    },
    decode: (key: Uint8Array): Uint8Array => {
      const decoded = PKCS8.decode(key);
      checkAlgo(decoded.algorithm.info);
      // EC + struct, other + raw
      // It would be nice to check if publicKey is valid, but that would leak compressed/uncompressed stuff here.
      let secretKey;
      if (decoded.algorithm.info.TAG === 'EC') {
        if (decoded.privateKey.TAG !== 'struct')
          throw new Error('derConverter.secretKey.decode: algorithm secret key type mismatch');
        if (decoded.privateKey.data.parameters) checkParams(decoded.privateKey.data.parameters);
        secretKey = decoded.privateKey.data.privateKey;
      } else {
        if (decoded.privateKey.TAG !== 'raw')
          throw new Error('derConverter.secretKey.decode: algorithm secret key type mismatch');
        secretKey = decoded.privateKey.data;
      }
      // Check publicKey if exists
      const pub = curve.getPublicKey(secretKey, false);
      const pubCompressed = curve.getPublicKey(secretKey, true);
      const checkPub = (p: Uint8Array) => {
        if (!equalBytes(p, pub) && !equalBytes(p, pubCompressed))
          throw new Error('wrong public key');
      };
      if (decoded.publicKey) checkPub(decoded.publicKey);
      if (decoded.privateKey.TAG === 'struct' && decoded.privateKey.data.publicKey)
        checkPub(decoded.privateKey.data.publicKey);
      if ('isValidSecretKey' in curve.utils) {
        if (!curve.utils.isValidSecretKey(secretKey)) throw new Error('wrong secret key');
      }
      return secretKey;
    },
  };
  // const Signature = {}
  return { publicKey, secretKey };
}

// Per-curve definitions
const p256PC = /* @__PURE__ */ jwkPointCoder(p256.Point);
export const p256_jwk: JWKConverter = /* @__PURE__ */ jwkConverter(
  p256,
  p256PC,
  { kty: 'EC', crv: 'P-256' },
  false
);
export const p256_jwk_ecdh: JWKConverter = /* @__PURE__ */ jwkConverter(
  p256,
  p256PC,
  { kty: 'EC', crv: 'P-256' },
  true
);
export const p256_der: DERConverter = /* @__PURE__ */ derConverter(p256, {
  TAG: 'EC',
  data: { TAG: 'namedCurve', data: CurveOID['P-256'] },
});

const p384PC = /* @__PURE__ */ jwkPointCoder(p384.Point);
export const p384_jwk: JWKConverter = /* @__PURE__ */ jwkConverter(
  p384,
  p384PC,
  { kty: 'EC', crv: 'P-384' },
  false
);
export const p384_jwk_ecdh: JWKConverter = /* @__PURE__ */ jwkConverter(
  p384,
  p384PC,
  { kty: 'EC', crv: 'P-384' },
  true
);
export const p384_der: DERConverter = /* @__PURE__ */ derConverter(p384, {
  TAG: 'EC',
  data: { TAG: 'namedCurve', data: CurveOID['P-384'] },
});

const p521PC = /* @__PURE__ */ jwkPointCoder(p521.Point);
export const p521_jwk: JWKConverter = /* @__PURE__ */ jwkConverter(
  p521,
  p521PC,
  { kty: 'EC', crv: 'P-521' },
  false
);
export const p521_jwk_ecdh: JWKConverter = /* @__PURE__ */ jwkConverter(
  p521,
  p521PC,
  { kty: 'EC', crv: 'P-521' },
  true
);
export const p521_der: DERConverter = /* @__PURE__ */ derConverter(p521, {
  TAG: 'EC',
  data: { TAG: 'namedCurve', data: CurveOID['P-521'] },
});

export const ed25519_jwk: JWKConverter = /* @__PURE__ */ jwkConverter(
  ed25519,
  jwkBytesCoder,
  { kty: 'OKP', crv: 'Ed25519', alg: 'Ed25519' },
  false
);
export const ed25519_der: DERConverter = /* @__PURE__ */ derConverter(ed25519, {
  TAG: 'Ed25519',
  data: null,
});

export const ed448_jwk: JWKConverter = /* @__PURE__ */ jwkConverter(
  ed448,
  jwkBytesCoder,
  { kty: 'OKP', crv: 'Ed448', alg: 'Ed448' },
  false
);
export const ed448_der: DERConverter = /* @__PURE__ */ derConverter(ed448, {
  TAG: 'Ed448',
  data: null,
});

export const x25519_jwk: JWKConverter = /* @__PURE__ */ jwkConverter(
  x25519,
  jwkBytesCoder,
  { kty: 'OKP', crv: 'X25519' },
  true
);
export const x25519_der: DERConverter = /* @__PURE__ */ derConverter(x25519, {
  TAG: 'X25519',
  data: null,
});

export const x448_jwk: JWKConverter = /* @__PURE__ */ jwkConverter(
  x448,
  jwkBytesCoder,
  { kty: 'OKP', crv: 'X448' },
  true
);
export const x448_der: DERConverter = /* @__PURE__ */ derConverter(x448, {
  TAG: 'X448',
  data: null,
});

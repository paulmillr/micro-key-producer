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
import type { CurvePoint, CurvePointCons, P_F } from '@noble/curves/abstract/curve.js';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { ed448, x448 } from '@noble/curves/ed448.js';
import { p256, p384, p521 } from '@noble/curves/nist.js';
import { equalBytes, numberToVarBytesBE } from '@noble/curves/utils.js';
import { bytesToHex, concatBytes, hexToBytes, type TArg, type TRet } from '@noble/hashes/utils.js';
import { ascii, base64urlnopad, utils as baseUtils, utf8 } from '@scure/base';
import * as P from 'micro-packed';
import { oidName } from './pgp.ts';
import { deepFreeze } from './utils.ts';

const _0n = /* @__PURE__ */ BigInt(0);
const _1n = /* @__PURE__ */ BigInt(1);
const _2n = /* @__PURE__ */ BigInt(2);
const _3n = /* @__PURE__ */ BigInt(3);

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
type BrokenCoder<T, A extends unknown[]> = {
  fromBytes(bytes: Uint8Array): T;
  toBytes(data: T, ...args: A): Uint8Array;
};
const fixCoder = /* @__PURE__ */ <A extends unknown[], T>(
  c: TArg<BrokenCoder<T, A>>,
  ...args: A
): TRet<P.Coder<T, Uint8Array>> => {
  const cc = c as BrokenCoder<T, A>;
  return {
    encode: (data: T) => cc.toBytes(data, ...args),
    decode: (data: TArg<Uint8Array>) => cc.fromBytes(data as Uint8Array),
  } as unknown as TRet<P.Coder<T, Uint8Array>>;
};
type JwkBasic = { x: string };
type JwkAffine = { x: string; y: string };
function jwkPointCoder<P extends CurvePoint<any, P>>(
  pc: CurvePointCons<P>
): TRet<P.Coder<Uint8Array, JwkAffine>> {
  // RFC 7518 EC JWK fields encode full-width SEC 1 affine coordinates with
  // base64url, so preserve fixed field-element widths here.
  const FpC = baseUtils.chain(fixCoder(pc.Fp), base64urlnopad);
  return {
    encode: (bytes: TArg<Uint8Array>): JwkAffine => {
      const { x, y } = pc.fromBytes(bytes as Uint8Array).toAffine();
      return { x: FpC.encode(x), y: FpC.encode(y) };
    },
    decode: (key: JwkAffine): TRet<Uint8Array> =>
      pc
        .fromAffine({
          x: FpC.decode(key.x) as P_F<P>,
          y: FpC.decode(key.y) as P_F<P>,
        })
        .toBytes() as TRet<Uint8Array>,
  } as unknown as TRet<P.Coder<Uint8Array, JwkAffine>>;
}

const jwkBytesCoder: P.Coder<Uint8Array, JwkBasic> = {
  // RFC 8037 OKP JWK keys store the public key octet string directly in the
  // base64url-encoded `x` field.
  encode: (bytes: TArg<Uint8Array>): JwkBasic => ({ x: base64urlnopad.encode(bytes) }),
  decode: (key: JwkBasic): TRet<Uint8Array> => base64urlnopad.decode(key.x) as TRet<Uint8Array>,
};

type Curve = typeof p256 | typeof ed25519 | typeof x25519;
type KeyUsage = 'deriveBits' | 'deriveKey' | 'sign' | 'verify';
type JWKConverter = ECConverter<JsonWebKey>;

// RFC 7518 §4.6 defines the ECDH-ES JOSE algorithm labels; RFC 8037 reuses
// the same family for X25519/X448 OKP keys.
const ECDH_ES_ALGS = [undefined, 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW'];

function jwkConverter(
  curve: Curve,
  pubCoder: TArg<P.Coder<Uint8Array, JwkBasic> | P.Coder<Uint8Array, JwkAffine>>,
  opts: JsonWebKey = {},
  derive: boolean,
  decodeAlgs: (string | undefined)[] = [opts.alg as string | undefined]
): TRet<JWKConverter> {
  const coder = pubCoder as P.Coder<Uint8Array, JwkBasic> | P.Coder<Uint8Array, JwkAffine>;
  // Match WebCrypto ECDH JWK exports: private keys use `deriveBits`, while
  // public keys keep an empty `key_ops` array.
  const secUsage: KeyUsage[] = derive ? ['deriveBits'] : ['sign'];
  const pubUsage: KeyUsage[] = derive ? [] : ['verify'];
  const algs = Object.freeze([...decodeAlgs]);
  Object.freeze(opts);
  Object.freeze(pubUsage);
  Object.freeze(secUsage);
  // Decode only binds JWK identity (`kty` / `crv` / optional `alg`); WebCrypto
  // export metadata like `ext` and optional RFC 7517 `key_ops` are not part of
  // the raw key material.
  function checkKey(key: JsonWebKey) {
    if (key.kty !== opts.kty || key.crv !== opts.crv) throw new Error('wrong curve');
    // RFC 7517 §4.4 makes JWK `alg` optional, while RFC 8037 §3.1 uses
    // `EdDSA` for Ed25519/Ed448 JOSE signatures; accept only the configured
    // compatible metadata values so decode stays tied to this curve family.
    if (!algs.includes(key.alg as string | undefined)) throw new Error('wrong curve');
  }
  const publicKey: P.Coder<Uint8Array, JsonWebKey> = deepFreeze({
    encode: (bytes: TArg<Uint8Array>) => {
      const raw = bytes as Uint8Array;
      if ('isValidPublicKey' in curve.utils) {
        if (!curve.utils.isValidPublicKey(raw)) throw new Error('wrong public key');
      }
      return { ...opts, ext: true, key_ops: pubUsage, ...coder.encode(raw) };
    },
    decode: (key: JsonWebKey): TRet<Uint8Array> => {
      checkKey(key);
      return coder.decode(key as JwkAffine) as TRet<Uint8Array>;
    },
  });
  const secretKey: JWKConverter['secretKey'] = deepFreeze({
    encode: (bytes: TArg<Uint8Array>) => {
      const sec = bytes as Uint8Array;
      const pub = curve.getPublicKey(sec);
      return {
        ...publicKey.encode(pub),
        key_ops: secUsage,
        d: base64urlnopad.encode(sec),
      };
    },
    decode: (key: JsonWebKey): TRet<Uint8Array> => {
      const pub = publicKey.decode(key);
      const res = base64urlnopad.decode(key.d!);
      if (!equalBytes(pub, curve.getPublicKey(res))) throw new Error('wrong public key');
      return res as TRet<Uint8Array>;
    },
  });
  return deepFreeze({ publicKey, secretKey }) as TRet<JWKConverter>;
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
// Typed PKCS#8 / SPKI / ECPrivateKey schemas below use the DER subset they
// need: mostly low-tag-number, definite-length TLVs plus byte-aligned BIT
// STRINGs and nonnegative INTEGERs. Raw ANY/TLV helpers preserve open ASN.1
// values, including high-tag-number identifiers, without schema interpretation.
let RawTLV!: P.CoderType<Uint8Array>;
const lenBody = (len: number, width?: number, minimal = true): number[] => {
  const out: number[] = [];
  for (let n = len; n > 0; n = Math.floor(n / 256)) out.unshift(n & 0xff);
  if (minimal) return out;
  if (width === undefined) throw new Error('fixed length width expected');
  if (out.length > width) throw new Error(`length ${len} does not fit ${width} bytes`);
  while (out.length < width) out.unshift(0);
  return out;
};
const lenValue = (bytes: TArg<Uint8Array>): number => {
  let len = 0;
  for (const b of bytes) {
    if (len > (Number.MAX_SAFE_INTEGER - b) / 256) throw new Error('length exceeds safe integer');
    len = len * 256 + b;
  }
  return len;
};
const BER_TAG_MAX = 0xffffffff;
const highTagNumber = (tag: number[]): number => {
  let num = 0;
  for (let i = 1; i < tag.length; i++) {
    const b = tag[i];
    // RFC 9090 §2.1 restates X.690 base-128 shortest-form for OID
    // subidentifiers; high-tag-number identifiers use the same base-128
    // form, and RFC 7468 Appendix B requires DER canonicality.
    if (i === 1 && b === 0x80) throw new Error('BER high-tag-number non-minimal');
    if (num > (BER_TAG_MAX - (b & 0x7f)) / 128) throw new Error('BER tag number exceeds uint32');
    num = num * 128 + (b & 0x7f);
  }
  if (num < 0x1f) throw new Error('BER high-tag-number non-minimal');
  return num;
};
const DERLen: P.CoderType<number> = /* @__PURE__ */ (() => {
  return /* @__PURE__ */ P.apply(
    /* @__PURE__ */ P.mappedTag(P.bits(1), {
      short: [0, P.bits(7)],
      long: [1, P.bytes(P.bits(7))],
    }),
    {
      encode(raw): number {
        if (raw.TAG === 'short') return raw.data;
        if (!raw.data.length) throw new Error('DER indefinite length is not supported');
        const len = lenValue(raw.data);
        // RFC 7468 Appendix B describes DER as the single canonical BER encoding
        // used for signatures/hashes, so BER-only non-minimal length encodings
        // are rejected instead of silently canonicalized.
        if (len < 0x80 || raw.data[0] === 0) throw new Error('DER non-minimal length encoding');
        return len;
      },
      decode(len: number) {
        if (!Number.isSafeInteger(len) || len < 0) throw new Error(`invalid length ${len}`);
        if (len < 0x80) return { TAG: 'short' as const, data: len };
        // RFC 5280 §4.1 says X.509 DER is tag/length/value, and RFC 7468
        // Appendix B notes DER always uses definite-length encoding; keep the
        // length body as arithmetic base-256 bytes, not JS signed-32-bit shifts.
        return { TAG: 'long' as const, data: Uint8Array.from(lenBody(len)) };
      },
    }
  );
})();
type ASN1DebugTag =
  | { TAG: 'universal'; data: { constructed: number; type: string } }
  | { TAG: 'application'; data: { constructed: number; number: number } }
  | { TAG: 'contextSpecific'; data: { constructed: number; number: number } }
  | { TAG: 'private'; data: { constructed: number; number: number } };
type ASN1DebugTLV = { tag: ASN1DebugTag; data: Uint8Array };
type ASN1Debug = null | bigint | string | Uint8Array | ASN1DebugTLV | ASN1Debug[];
const asDebug = (v: TArg<ASN1Debug>): TRet<ASN1Debug> => v as TRet<ASN1Debug>;
type ASN1StructRecord<T extends Record<string, unknown>> = { [K in keyof T]: P.CoderType<T[K]> };
/** Generic ASN.1 tree node used for lossless unsupported DER TLV payloads. */
export type TLVNode = {
  /** First ASN.1 identifier octet. */
  tag: number;
  /** Full ASN.1 identifier octets when the tag uses high-tag-number form. */
  tagHex?: string;
  /** Nested child nodes for constructed values. */
  children?: TLVNode[];
  /** Hex-encoded payload for primitive values. */
  valueHex?: string;
};
/** Generic ASN.1 AlgorithmIdentifier shell with optional raw parameters. */
export type ASN1AlgorithmIdentifier = {
  /** Algorithm object identifier. */
  algorithm: string;
  /** Optional raw AlgorithmIdentifier parameters TLV. */
  params?: TLVNode;
};
/** Generic ASN.1 Attribute shell with raw SET OF values. */
export type ASN1Attribute = {
  /** Attribute object identifier. */
  oid: string;
  /** Raw ASN.1 attribute values. */
  values: Uint8Array[];
};
/** Generic ASN.1 Time choice. */
export type ASN1Time = { TAG: 'utc'; data: string } | { TAG: 'generalized'; data: string };
/** Generic ASN.1 string value choice used by schema-less TLV helpers. */
export type ASN1StringValue =
  | { TAG: 'utf8'; data: string }
  | { TAG: 'printable'; data: string }
  | { TAG: 'teletex'; data: string }
  | { TAG: 'ia5'; data: string }
  | { TAG: 'bmp'; data: string }
  | { TAG: 'universal'; data: string }
  | { TAG: 'visible'; data: string }
  | { TAG: 'numeric'; data: string };
/** Generic parsed ASN.1 string-or-raw value. */
export type ASN1StringOrRaw = ASN1StringValue | { TAG: 'raw'; data: TLVNode };
/** Generic best-effort parsed ASN.1 ANY value. */
export type ASN1AnyValue =
  | { TAG: 'text'; data: ASN1StringValue }
  | { TAG: 'oid'; data: string }
  | { TAG: 'int'; data: bigint }
  | { TAG: 'bool'; data: boolean }
  | { TAG: 'time'; data: ASN1Time }
  | { TAG: 'octet'; data: Uint8Array }
  | { TAG: 'raw'; data: TLVNode };
type ASN1SetOpts = { ber?: boolean };
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
  const tlv = /* @__PURE__ */ P.struct({ tag, data: P.bytes(DERLen) });
  type ASN1Coder<T> = P.CoderType<T> & {
    tagByte: number;
    tagBytes: number[];
    constructed: number;
    inner: P.CoderType<T>;
  };
  type ASN1MaybeCoder<T> = P.CoderType<T> &
    Partial<Pick<ASN1Coder<T>, 'tagByte' | 'tagBytes' | 'constructed' | 'inner'>>;
  const tagsOf = <T>(v: ASN1MaybeCoder<T>): number[] => {
    if (v.tagBytes && v.tagBytes.length) return v.tagBytes;
    return v.tagByte === undefined ? [] : [v.tagByte];
  };
  const expectTagByte = (tagByte: number, expected: number): void => {
    if (tagByte !== expected)
      throw new Error(`expected tag 0x${expected.toString(16)}, got 0x${tagByte.toString(16)}`);
  };
  const basic = <T>(typeTag: P.UnwrapCoder<typeof tag>, inner: P.CoderType<T>): ASN1Coder<T> => {
    const tagByte = tag.encode(typeTag)[0];
    const coder = /* @__PURE__ */ P.apply<P.UnwrapCoder<typeof tlv>, T>(tlv, {
      encode(from): T {
        // RFC 5280 §4.1/Appendix B rely on DER identifier octets selecting the
        // field type; a typed ASN.1 coder must not reinterpret a different tag's body.
        expectTagByte(tag.encode(from.tag)[0], tagByte);
        return inner.decode(from.data);
      },
      decode(value): P.UnwrapCoder<typeof tlv> {
        return {
          tag: typeTag,
          data: inner.encode(value),
        };
      },
    });
    return {
      tagByte,
      tagBytes: [tagByte],
      constructed: typeTag.data.constructed,
      inner,
      ...coder,
    };
  };
  const tagged = <T>(tagByte: number, inner: P.CoderType<T>): ASN1Coder<T> => {
    if (!Number.isInteger(tagByte) || tagByte < 0 || tagByte > 0xff)
      throw new Error(`ASN1.tagged: invalid one-octet tag ${tagByte}`);
    if ((tagByte & 0x1f) === 0x1f)
      throw new Error('ASN1.tagged: high-tag-number form needs ASN1.any or BER');
    const rawTlv = /* @__PURE__ */ P.struct({ tag: P.U8, value: P.bytes(DERLen) });
    const coder = /* @__PURE__ */ P.apply<P.UnwrapCoder<typeof rawTlv>, T>(rawTlv, {
      encode(from): T {
        expectTagByte(from.tag, tagByte);
        return inner.decode(from.value);
      },
      decode(value): P.UnwrapCoder<typeof rawTlv> {
        return { tag: tagByte, value: inner.encode(value) };
      },
    });
    return {
      tagByte,
      tagBytes: [tagByte],
      constructed: tagByte & 0x20 ? 1 : 0,
      inner,
      ...coder,
    };
  };
  const ASCII = /* @__PURE__ */ P.apply(/* @__PURE__ */ P.bytes(null), ascii);
  // Primitive types
  const Integer = basic(
    { TAG: 'universal', data: { constructed: 0, type: 'integer' } },
    /* @__PURE__ */ P.apply(/* @__PURE__ */ P.bytes(null), {
      encode(bytes) {
        // RFC 5280 Appendix B notes leading 00 is only for clearing the
        // INTEGER sign bit; RFC 7468 Appendix B's DER canonicality means empty
        // or redundant leading-zero encodings are rejected.
        if (!bytes.length) throw new Error('DER INTEGER empty');
        if (bytes[0] & 0x80) throw new Error('negative values not allowed');
        if (bytes.length > 1 && bytes[0] === 0x00 && !(bytes[1] & 0x80))
          throw new Error('DER INTEGER non-minimal');
        return bytesToNumberBE(bytes);
      },
      decode(value) {
        if (value < 0) throw new Error('negative values not allowed');
        const bytes = numberToVarBytesBE(value);
        return (
          bytes[0] & 0x80 ? concatBytes(Uint8Array.of(0x00), bytes) : bytes
        ) as TRet<Uint8Array>;
      },
    }) satisfies P.CoderType<bigint>
  );
  const OID = basic(
    { TAG: 'universal', data: { constructed: 0, type: 'oid' } },
    // RFC 5280 Appendix B mandates X.509 support for OID arc elements
    // through 268,435,455; this shared JS string coder rejects non-integer or
    // unsafe-number arcs instead of silently rounding/coercing them.
    oidName
  );
  const OIDMap = basic({ TAG: 'universal', data: { constructed: 0, type: 'oid' } }, oidName);
  const OctetString = basic(
    { TAG: 'universal', data: { constructed: 0, type: 'octetString' } },
    P.bytes(null)
  );
  const BitStringInner = /* @__PURE__ */ P.struct({
    unused: P.U8,
    bytes: /* @__PURE__ */ P.bytes(null),
  });
  const BitStringRaw = tagged(
    0x03,
    /* @__PURE__ */ P.validate(BitStringInner, (d) => {
      const bs = d as { unused: number; bytes: Uint8Array };
      // X.690 §8.6.2.2 limits the initial octet to 0..7, §8.6.2.3 makes empty
      // BIT STRINGs use 0, and §11.2.1 requires DER/CER unused tail bits be zero.
      if (bs.unused > 7) throw new Error(`BIT STRING invalid unused bits: ${bs.unused}`);
      if (!bs.bytes.length && bs.unused) throw new Error('BIT STRING empty with unused bits');
      if (bs.unused && bs.bytes[bs.bytes.length - 1] & ((1 << bs.unused) - 1))
        throw new Error('BIT STRING nonzero unused tail bits');
      return d;
    })
  );
  const BitString = tagged(
    BitStringRaw.tagByte,
    /* @__PURE__ */ P.apply(BitStringRaw.inner, {
      encode: (d: TArg<{ unused: number; bytes: Uint8Array }>): TRet<Uint8Array> => {
        const bs = d as { unused: number; bytes: Uint8Array };
        if (bs.unused !== 0) throw new Error('ASN1.bitString: non-zero amount of leftover bits');
        return bs.bytes as TRet<Uint8Array>;
      },
      decode: (bytes: TArg<Uint8Array>): TRet<{ unused: number; bytes: Uint8Array }> =>
        ({ unused: 0, bytes: bytes as Uint8Array }) as TRet<{
          unused: number;
          bytes: Uint8Array;
        }>,
    })
  );
  const Boolean = tagged(
    0x01,
    /* @__PURE__ */ P.apply(
      /* @__PURE__ */ P.validate(P.U8, (b) => {
        // DER is stricter than BER 8.2.2: X.690 §11.1 narrows TRUE to the
        // single canonical contents octet 0xff for CER/DER encodings.
        if (b !== 0x00 && b !== 0xff) throw new Error('DER BOOLEAN TRUE must be 0xff');
        return b;
      }),
      {
        encode: (b: number): boolean => b !== 0,
        decode: (v: boolean): number => (v ? 0xff : 0x00),
      }
    )
  );
  const UTF8String = tagged(
    0x0c,
    // RFC 5280 Appendix A.1 makes UTF8String conform to RFC 3629; RFC 3629
    // §3 forbids UTF-16 surrogate code points in UTF-8.
    /* @__PURE__ */ P.apply(/* @__PURE__ */ P.bytes(null), utf8) satisfies P.CoderType<string>
  );
  const IA5String = tagged(0x16, ASCII);
  const PrintableString = tagged(
    0x13,
    /* @__PURE__ */ P.validate(ASCII, (s: string) => {
      if (!/^[A-Za-z0-9 '()+,./:=?-]*$/.test(s))
        throw new Error(`invalid PrintableString: ${JSON.stringify(s)}`);
      return s;
    })
  );
  const TeletexString = tagged(
    0x14,
    /* @__PURE__ */ P.apply(/* @__PURE__ */ P.bytes(null), {
      encode: (b: TArg<Uint8Array>): string => {
        let out = '';
        for (let i = 0; i < b.length; i++) out += String.fromCharCode(b[i]);
        return out;
      },
      decode: (s: string): TRet<Uint8Array> => {
        const out = new Uint8Array(s.length);
        for (let i = 0; i < s.length; i++) {
          const c = s.charCodeAt(i);
          if (c > 0xff)
            throw new Error(`expected latin1 character, got U+${c.toString(16).toUpperCase()}`);
          out[i] = c;
        }
        return out as TRet<Uint8Array>;
      },
    }) satisfies P.CoderType<string>
  );
  const VisibleString = tagged(0x1a, ASCII);
  const NumericString = tagged(
    0x12,
    /* @__PURE__ */ P.validate(ASCII, (s: string) => {
      if (!/^[0-9 ]*$/.test(s)) throw new Error(`invalid NumericString: ${JSON.stringify(s)}`);
      return s;
    })
  );
  const checkBMPStringUnit = (c: number): void => {
    if (c >= 0xd800 && c <= 0xdfff)
      throw new Error(
        `BMPString: expected Basic Multilingual Plane scalar, got surrogate U+${c
          .toString(16)
          .toUpperCase()}`
      );
  };
  const BMPString = tagged(
    0x1e,
    /* @__PURE__ */ P.apply(/* @__PURE__ */ P.bytes(null), {
      encode: (b: TArg<Uint8Array>): string => {
        if (b.length % 2) throw new Error('BMPString length must be even');
        let out = '';
        for (let i = 0; i < b.length; i += 2) {
          const c = (b[i] << 8) | b[i + 1];
          checkBMPStringUnit(c);
          out += String.fromCharCode(c);
        }
        return out;
      },
      decode: (s: string): TRet<Uint8Array> => {
        const out = new Uint8Array(s.length * 2);
        for (let i = 0; i < s.length; i++) {
          const c = s.charCodeAt(i);
          checkBMPStringUnit(c);
          out[i * 2] = c >>> 8;
          out[i * 2 + 1] = c & 0xff;
        }
        return out as TRet<Uint8Array>;
      },
    }) satisfies P.CoderType<string>
  );
  const checkUniversalStringScalar = (c: number): void => {
    if (c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff))
      throw new Error(
        `UniversalString: expected Unicode scalar, got U+${c.toString(16).toUpperCase()}`
      );
  };
  const UniversalString = tagged(
    0x1c,
    /* @__PURE__ */ P.apply(/* @__PURE__ */ P.bytes(null), {
      encode: (b: TArg<Uint8Array>): string => {
        if (b.length % 4) throw new Error('UniversalString length must be multiple of 4');
        let out = '';
        for (let i = 0; i < b.length; i += 4) {
          const c = b[i] * 0x1000000 + (b[i + 1] << 16) + (b[i + 2] << 8) + b[i + 3];
          checkUniversalStringScalar(c);
          out += String.fromCodePoint(c);
        }
        return out;
      },
      decode: (s: string): TRet<Uint8Array> => {
        const chars = [...s];
        const out = new Uint8Array(chars.length * 4);
        for (let i = 0; i < chars.length; i++) {
          const c = chars[i].codePointAt(0)!;
          checkUniversalStringScalar(c);
          out[i * 4] = c >>> 24;
          out[i * 4 + 1] = (c >>> 16) & 0xff;
          out[i * 4 + 2] = (c >>> 8) & 0xff;
          out[i * 4 + 3] = c & 0xff;
        }
        return out as TRet<Uint8Array>;
      },
    }) satisfies P.CoderType<string>
  );
  const UTCTime = tagged(0x17, ASCII);
  const GeneralizedTime = tagged(0x18, ASCII);
  // RFC 5280 §4.2 and RFC 5958 §2 carry OID-defined fields as encoded
  // ASN.1 values; preserve exactly one DER TLV here without schema-parsing
  // constructed children or rejecting high-tag-number identifiers.
  const Any = /* @__PURE__ */ P.wrap({
    encodeStream(w, value: TArg<Uint8Array>) {
      w.bytes(Any.decode(value));
    },
    decodeStream(r): TRet<Uint8Array> {
      const tag: number[] = [r.byte()];
      if ((tag[0] & 0x1f) === 0x1f) {
        while (true) {
          const b = r.byte();
          tag.push(b);
          if (!(b & 0x80)) break;
        }
        highTagNumber(tag);
      }
      const a = r.byte();
      let len = a;
      let lenBytes = [a];
      if (a >= 0x80) {
        const n = a & 0x7f;
        if (!n) throw new Error('DER indefinite length is not supported');
        const lb = r.bytes(n);
        len = lenValue(lb);
        if (len < 0x80 || lb[0] === 0) throw new Error('DER non-minimal length encoding');
        lenBytes = [a, ...lb];
      }
      return concatBytes(
        Uint8Array.from(tag),
        Uint8Array.from(lenBytes),
        r.bytes(len)
      ) as TRet<Uint8Array>;
    },
  }) satisfies P.CoderType<Uint8Array>;
  const sequence = <T extends Record<string, unknown>>(fields: ASN1StructRecord<T>) => {
    return basic(
      { TAG: 'universal', data: { constructed: 1, type: 'sequence' } },
      P.struct(fields)
    );
  };
  const set = <T>(inner: P.CoderType<T>, opts: ASN1SetOpts = {}) => {
    // BER SET members are unordered; DER callers keep sorted-order validation,
    // while BER-facing CMS containers opt out per RFC 5652 sections 1 and 1.1.1.
    const ber = !!opts.ber;
    const cmp = (a: TArg<Uint8Array>, b: TArg<Uint8Array>): number => {
      const n = Math.min(a.length, b.length);
      for (let i = 0; i < n; i++) {
        const d = a[i] - b[i];
        if (d) return d;
      }
      return a.length - b.length;
    };
    type SetItem = { raw: Uint8Array; value: T };
    const item = /* @__PURE__ */ P.apply<Uint8Array, SetItem>(Any, {
      encode(raw) {
        return { raw, value: inner.decode(raw) };
      },
      decode(value): TRet<Uint8Array> {
        return value.raw as TRet<Uint8Array>;
      },
    });
    return basic(
      { TAG: 'universal', data: { constructed: 1, type: 'set' } },
      /* @__PURE__ */ P.apply<SetItem[], T[]>(/* @__PURE__ */ P.array(null, item), {
        encode(items): T[] {
          const out: T[] = [];
          let prev: Uint8Array | undefined;
          for (const item of items) {
            if (!ber) {
              // RFC 5280 Appendix B: DER SET OF values require ordering by their
              // encoded values, so strict DER decode rejects unsorted members.
              if (prev && cmp(prev, item.raw) > 0)
                throw new Error('DER SET OF values must be sorted');
            }
            prev = item.raw;
            out.push(item.value);
          }
          return out;
        },
        decode(values) {
          // RFC 7468 Figure 20 requires PRIVATE KEY DER; DER/X.690 sorts SET OF
          // members by complete encoded value.
          return values
            .map((value) => ({ raw: inner.encode(value), value }))
            .sort((a, b) => cmp(a.raw, b.raw));
        },
      })
    );
  };
  type ChoiceCoder<T> = P.CoderType<T> &
    Partial<Pick<ASN1Coder<T>, 'tagByte' | 'tagBytes' | 'constructed' | 'inner'>>;
  type ChoiceInput<T extends Record<string, unknown>> = { [K in keyof T]: ChoiceCoder<T[K]> };
  type ChoiceResult<T extends Record<string, unknown>> = {
    [K in keyof T]: { TAG: K; data: T[K] };
  }[keyof T];
  const choice = <T extends Record<string, unknown>>(
    variants: ChoiceInput<T>
  ): ASN1Coder<ChoiceResult<T>> => {
    const keys = Object.keys(variants) as (keyof T)[];
    if (!keys.length) throw new Error('ASN1.choice: empty variants');
    const choiceTags = keys.map((k) => tagsOf(variants[k]));
    const tagBytes = choiceTags.some((i) => !i.length) ? [] : choiceTags.flat();
    const coder = /* @__PURE__ */ P.apply<Uint8Array, ChoiceResult<T>>(Any, {
      encode(raw): ChoiceResult<T> {
        const tag = raw[0];
        for (const k in variants) {
          const v = variants[k] as ASN1MaybeCoder<unknown>;
          const tags = tagsOf(v);
          if (tags.length && !tags.includes(tag)) continue;
          return { TAG: k, data: v.decode(raw) } as ChoiceResult<T>;
        }
        throw new Error('ASN1.choice: unknown variant=' + tag);
      },
      decode(value): TRet<Uint8Array> {
        if (!value.TAG || !variants[value.TAG])
          throw new Error('ASN1.choice: unknown variant=' + (value.TAG as string));
        const variant = variants[value.TAG] as unknown as P.CoderType<ChoiceResult<T>['data']>;
        return variant.encode(value.data) as TRet<Uint8Array>;
      },
    });
    return {
      tagByte: tagBytes[0],
      tagBytes,
      constructed: variants[keys[0]].constructed || 0,
      inner: P.bytes(null) as unknown as P.CoderType<ChoiceResult<T>>,
      ...coder,
    };
  };
  const StringValue = /* @__PURE__ */ choice({
    utf8: UTF8String,
    printable: PrintableString,
    teletex: TeletexString,
    ia5: IA5String,
    bmp: BMPString,
    universal: UniversalString,
    visible: VisibleString,
    numeric: NumericString,
  }) satisfies P.CoderType<ASN1StringValue>;
  const stringTags = tagsOf(StringValue);
  const Time = /* @__PURE__ */ choice({ utc: UTCTime, generalized: GeneralizedTime });
  const timeTags = tagsOf(Time);

  // Small schema-less parser for debug. Useful to see whats going on inside, but not enough for schema parsing.
  const debug: P.CoderType<ASN1Debug> = P.apply<P.UnwrapCoder<typeof tlv>, ASN1Debug>(tlv, {
    encode(from: P.UnwrapCoder<typeof tlv>): TRet<ASN1Debug> {
      if (from.tag.TAG === 'universal') {
        if (['sequence', 'set'].includes(from.tag.data.type))
          return asDebug(P.array(null, debug).decode(from.data));
        if (from.tag.data.type === 'integer') return asDebug(Integer.inner.decode(from.data));
        if (from.tag.data.type === 'oid') return asDebug(OIDMap.inner.decode(from.data));
        if (from.tag.data.type === 'octetString')
          return asDebug(OctetString.inner.decode(from.data));
        if (from.tag.data.type === 'null') return null;
      }
      if (from.tag.TAG === 'contextSpecific' && from.tag.data.constructed)
        return asDebug(debug.decode(from.data));
      return from as TRet<ASN1Debug>;
    },
    decode(_to: TArg<ASN1Debug>): P.UnwrapCoder<typeof tlv> {
      // Without schema we cannot know how to encode stuff (is Uint8Array is octetString or bitString?)
      throw new Error('not supported');
    },
  });
  const TLVNode = /* @__PURE__ */ P.apply(Any, {
    encode(raw): TLVNode {
      const tag = raw[0];
      let pos = 1;
      let tagHex: string | undefined;
      if ((tag & 0x1f) === 0x1f) {
        while (true) {
          if (pos >= raw.length) throw new Error('TLVNode high-tag-number truncated');
          const b = raw[pos++];
          if (!(b & 0x80)) break;
        }
        tagHex = bytesToHex(raw.subarray(0, pos));
      }
      const len = DERLen.decode(raw.subarray(pos), { allowUnreadBytes: true });
      const valueAt = pos + DERLen.encode(len).length;
      if (valueAt + len !== raw.length) throw new Error('TLVNode raw length mismatch');
      const value = raw.subarray(valueAt);
      const base: Pick<TLVNode, 'tag' | 'tagHex'> = tagHex ? { tag, tagHex } : { tag };
      if (tag & 0x20) {
        const items: TLVNode[] = [];
        let at = 0;
        while (at < value.length) {
          // RFC 5280 §4.1 defines X.509 DER as tag/length/value. Reuse the
          // generic one-TLV reader here so constructed raw nodes preserve
          // high-tag-number identifier octets instead of treating them as length bytes.
          const child = Any.decode(value.subarray(at), { allowUnreadBytes: true });
          items.push(TLVNode.decode(child));
          at += child.length;
        }
        return { ...base, children: items };
      }
      return { ...base, valueHex: bytesToHex(value) };
    },
    decode(n: TArg<TLVNode>): TRet<Uint8Array> {
      const value = n.children
        ? concatBytes(...n.children.map((i) => TLVNode.encode(i)))
        : hexToBytes(n.valueHex || '');
      const tag = n.tagHex ? hexToBytes(n.tagHex) : Uint8Array.of(n.tag);
      if (tag[0] !== n.tag) throw new Error('TLVNode tagHex/tag mismatch');
      return concatBytes(tag, DERLen.encode(value.length), value) as TRet<Uint8Array>;
    },
  }) satisfies P.CoderType<TLVNode>;
  const toTLV = <T>(coder: P.CoderType<T>, value: T): TLVNode =>
    TLVNode.decode(coder.encode(value));
  const StringOrRaw = /* @__PURE__ */ P.apply(TLVNode, {
    encode: (n: TArg<TLVNode>): TRet<ASN1StringOrRaw> => {
      const node = n as TLVNode;
      if (stringTags.includes(node.tag))
        return StringValue.decode(TLVNode.encode(node)) as TRet<ASN1StringOrRaw>;
      return { TAG: 'raw', data: node } as TRet<ASN1StringOrRaw>;
    },
    decode: (v: TArg<ASN1StringOrRaw>): TLVNode => {
      const value = v as ASN1StringOrRaw;
      return value.TAG === 'raw' ? value.data : toTLV(StringValue, value);
    },
  }) satisfies P.CoderType<ASN1StringOrRaw>;
  const AnyValue = /* @__PURE__ */ P.apply(TLVNode, {
    encode: (n: TArg<TLVNode>): TRet<ASN1AnyValue> => {
      const node = n as TLVNode;
      const der = TLVNode.encode(node);
      if (node.tag === Boolean.tagByte)
        return { TAG: 'bool', data: Boolean.decode(der) } as TRet<ASN1AnyValue>;
      if (node.tag === Integer.tagByte)
        return { TAG: 'int', data: Integer.decode(der) } as TRet<ASN1AnyValue>;
      if (node.tag === OID.tagByte)
        return { TAG: 'oid', data: OIDMap.decode(der) } as TRet<ASN1AnyValue>;
      if (node.tag === OctetString.tagByte)
        return { TAG: 'octet', data: OctetString.decode(der) } as TRet<ASN1AnyValue>;
      if (timeTags.includes(node.tag))
        return { TAG: 'time', data: Time.decode(der) } as TRet<ASN1AnyValue>;
      if (stringTags.includes(node.tag))
        return { TAG: 'text', data: StringValue.decode(der) } as TRet<ASN1AnyValue>;
      return { TAG: 'raw', data: node } as TRet<ASN1AnyValue>;
    },
    decode: (x: TArg<ASN1AnyValue>): TLVNode => {
      const v = x as ASN1AnyValue;
      if (v.TAG === 'raw') return v.data;
      if (v.TAG === 'text') return toTLV(StringValue, v.data);
      if (v.TAG === 'oid') return toTLV(OIDMap, v.data);
      if (v.TAG === 'int') return toTLV(Integer, v.data);
      if (v.TAG === 'bool') return toTLV(Boolean, v.data);
      if (v.TAG === 'time') return toTLV(Time, v.data);
      return toTLV(OctetString, v.data);
    },
  }) satisfies P.CoderType<ASN1AnyValue>;
  const optional = <T>(inner: ASN1MaybeCoder<T>): ASN1MaybeCoder<T | undefined> => {
    const tagBytes = tagsOf(inner);
    return {
      tagByte: inner.tagByte,
      tagBytes,
      inner: (inner.inner || inner) as P.CoderType<T | undefined>,
      constructed: inner.constructed || 0,
      ...P.wrap({
        encodeStream(w, value) {
          if (value === undefined) return;
          inner.encodeStream(w, value);
        },
        decodeStream(r) {
          if (r.isEnd()) return undefined;
          // Unknown-tag OPTIONAL fields are only safe as trailing fields: with
          // no tag set to peek, presence means the parent stream still has one
          // value left. Middle open optionals must be modeled explicitly.
          if (!tagBytes.length) return inner.decodeStream(r);
          const tag = r.byte(true);
          if (!tagBytes.includes(tag)) return undefined;
          return inner.decodeStream(r);
        },
      }),
    };
  };
  type ASN1Value<C> = C extends ASN1MaybeCoder<infer T> ? T : never;
  const validate = <C extends object>(inner: C, fn: (value: ASN1Value<C>) => ASN1Value<C>): C => ({
    ...inner,
    ...P.validate(inner as unknown as P.CoderType<ASN1Value<C>>, fn),
  });
  // RFC 5280 §4.1.1.2 and RFC 5652 §§10.1.1/10.1.2 use the common
  // AlgorithmIdentifier shape. OID-specific parameter rules stay with callers.
  const AlgorithmIdentifier = /* @__PURE__ */ sequence({
    algorithm: OIDMap,
    params: /* @__PURE__ */ optional(TLVNode),
  }) satisfies ASN1Coder<ASN1AlgorithmIdentifier>;
  const Attribute = /* @__PURE__ */ sequence({ oid: OID, values: set(Any) });
  const ECDSASig = /* @__PURE__ */ sequence({ r: Integer, s: Integer });
  RawTLV = Any;
  return {
    debug,
    tagged,
    ASCII,
    Integer,
    Boolean,
    OctetString,
    OID,
    OIDMap,
    BitString,
    BitStringRaw,
    UTF8: UTF8String,
    UTF8String,
    IA5String,
    PrintableString,
    TeletexString,
    VisibleString,
    NumericString,
    BMPString,
    UniversalString,
    String: StringValue,
    UTCTime,
    GeneralizedTime,
    Time,
    null: basic({ TAG: 'universal', data: { constructed: 0, type: 'null' } }, P.constant(null)),
    any: Any,
    TLVNode,
    StringOrRaw,
    AnyValue,
    AlgorithmIdentifier,
    Attribute,
    ECDSASig,
    choice,
    sequence,
    set,
    explicit: <T>(number: number, inner: P.CoderType<T>) =>
      basic({ TAG: 'contextSpecific', data: { constructed: 1, number } }, inner),
    implicit: <T>(number: number, inner: ASN1Coder<T>) =>
      basic(
        { TAG: 'contextSpecific', data: { constructed: inner.constructed, number } },
        inner.inner
      ), // hides actual tag
    optional,
    validate,
  };
})();
// RFC 5480 https://www.rfc-editor.org/rfc/rfc5480
// RFC 5915 https://www.rfc-editor.org/rfc/rfc5915
// RFC 5958 https://www.rfc-editor.org/rfc/rfc5958
// RFC 8410 https://www.rfc-editor.org/rfc/rfc8410
// Keep explicit-domain support in DERUtils for low-level interop/vector coverage;
// the higher-level PKIX-facing converters later reject non-named curves.
const SpecifiedECDomain = /* @__PURE__ */ (() =>
  ASN1.validate(
    ASN1.sequence({
      version: ASN1.Integer,
      fieldId: ASN1.sequence({
        info: P.mappedTag(ASN1.OID, {
          primeField: ['primeField', ASN1.Integer],
          binaryField: ['binaryField', P.bytes(null)], // a lot of stuff, basises, polynominals, too complex
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
    }),
    (domain) => {
      // SEC 1 v2 Appendix C.2 defines SpecifiedECDomainVersion as ecdpVer1(1),
      // ecdpVer2(2), or ecdpVer3(3), and requires curve.seed for v2/v3.
      if (domain.version !== _1n && domain.version !== _2n && domain.version !== _3n)
        throw new Error(`SpecifiedECDomain: expected version 1, 2, or 3, got ${domain.version}`);
      if ((domain.version === _2n || domain.version === _3n) && domain.curve.seed === undefined)
        throw new Error(`SpecifiedECDomain: expected curve.seed for version ${domain.version}`);
      return domain;
    }
  ))();

// DERUtils preserves the full ECParameters choice for low-level parsing/roundtrips,
// while derConverter.checkParams later narrows public curve converters to namedCurve only.
const ECParameters = /* @__PURE__ */ (() =>
  ASN1.choice({
    namedCurve: ASN1.OID,
    implicitCurve: ASN1.null,
    specifiedCurve: SpecifiedECDomain,
  }))();
const DSAParameters = /* @__PURE__ */ (() =>
  ASN1.sequence({ p: ASN1.Integer, q: ASN1.Integer, g: ASN1.Integer }))();
// We can re-use for pub/secret only without RSA. RSA algorithm is different.
// AlgorithmIdentifier parameter rules vary by OID: EC MUST carry ECParameters,
// Ed/X MUST omit parameters, rsaEncryption uses ASN.1 NULL, and DSA may carry
// explicit Dss-Parms or inherit/obtain domain parameters outside this SPKI.
const KeyAlgorithm = /* @__PURE__ */ (() =>
  ASN1.sequence({
    info: P.mappedTag(ASN1.OID, {
      // Maps webcrypto stuff, Ed/X attached
      EC: ['ecPublicKey', ECParameters],
      X25519: ['X25519', P.constant(null)], // X25519
      X448: ['X448', P.constant(null)], // X448
      Ed25519: ['Ed25519', P.constant(null)], // Ed25519
      Ed448: ['Ed448', P.constant(null)], // Ed448
      rsaEncryption: ['rsaEncryption', ASN1.null],
      // Today we don't want to support RSA keys. In the future it can be done using `micro-rsa-dsa-dh` package
      // Code:
      // rsassaPss: ['1.2.840.113549.1.1.10', sequence(hashAlgorithm, maskGenAlgorithm, saltLength, trailerField)]
      // rsaesOaep: ['1.2.840.113549.1.1.7', sequence(hashAlgorithm, maskGenAlgorithm, pSourceAlgorithm)]
      // Easy to parse, works as additional test for parser structure.
      DSA: [
        'DSA',
        // RFC 3279 §2.3.2: if id-dsa domain parameters are omitted, the
        // AlgorithmIdentifier parameters component MUST be omitted entirely.
        ASN1.optional(DSAParameters),
      ],
    }),
  }))();
// TODO: this is nice, but we cannot put all OID rows here, so, lets do P.bytes(null)?
// On the other hand, if there is some issues with encoding, we will convert key, but other stuff will fail on it
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
// Keep each SET member as one DER-encoded Attribute blob; the allowed
// attribute OIDs are open-ended, so DERUtils preserves opaque per-attribute
// bytes instead of hardcoding a closed PKCS#9 schema here.
// RFC 5208 §6 and RFC 5958 §2 define PKCS#8 attributes as SET OF Attribute,
// so each decoded member must be one Attribute TLV rather than a greedy byte tail.
const Attributes = /* @__PURE__ */ (() => ASN1.set(RawTLV))();
type RSAOtherPrimeInfo = {
  prime: bigint;
  exponent: bigint;
  coefficient: bigint;
};
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
  otherPrimeInfos?: RSAOtherPrimeInfo[];
};
/** Elliptic-curve parameter encoding used by DER key structures. */
export type ECParams =
  | { TAG: 'namedCurve'; data: string }
  | { TAG: 'implicitCurve'; data: null }
  | { TAG: 'specifiedCurve'; data: unknown };
/** Algorithm identifier payload for DER key structures. */
export type KeyInfo =
  | { TAG: 'EC'; data: ECParams }
  | { TAG: 'X25519'; data: null }
  | { TAG: 'X448'; data: null }
  | { TAG: 'Ed25519'; data: null }
  | { TAG: 'Ed448'; data: null }
  | { TAG: 'rsaEncryption'; data: null }
  | { TAG: 'DSA'; data: unknown };
/** Top-level algorithm wrapper for DER key structures. */
export type Algo = {
  /** Algorithm identifier and its associated parameters. */
  info: KeyInfo;
};
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
/** Decoded PKCS#8 private-key structure. */
export type PKCS8Key = {
  /** PKCS#8 version field. */
  version: bigint;
  /** Algorithm identifier describing the wrapped private key. */
  algorithm: Algo;
  /** Raw or structured private-key payload. */
  privateKey: PKCS8Secret;
  /** Optional PKCS#8 attributes carried alongside the key. */
  attributes?: Uint8Array[];
  /** Optional public key attached to the private-key structure. */
  publicKey?: Uint8Array;
};
type PKCS8Raw = Omit<PKCS8Key, 'privateKey'> & { privateKey: Uint8Array };
/** Decoded SubjectPublicKeyInfo structure. */
export type SPKIKey = {
  /** Algorithm identifier describing the public key. */
  algorithm: Algo;
  /** Encoded public-key bytes. */
  publicKey: Uint8Array;
};
type ASN1TagCoder<T> = P.CoderType<T> & {
  tagByte: number;
  tagBytes: number[];
  constructed: number;
  inner: P.CoderType<T>;
};
type ASN1ChoiceRecord<T extends Record<string, unknown>> = {
  [K in keyof T]: P.CoderType<T[K]> &
    Partial<Pick<ASN1TagCoder<T[K]>, 'tagByte' | 'tagBytes' | 'constructed' | 'inner'>>;
};
type ASN1ChoiceResult<T extends Record<string, unknown>> = {
  [K in keyof T]: { TAG: K; data: T[K] };
}[keyof T];
type ASN1Pub = {
  debug: P.CoderType<ASN1Debug>;
  tagged: <T>(tag: number, inner: P.CoderType<T>) => ASN1TagCoder<T>;
  ASCII: P.CoderType<string>;
  Integer: ASN1TagCoder<bigint>;
  Boolean: ASN1TagCoder<boolean>;
  OctetString: ASN1TagCoder<Uint8Array>;
  OID: ASN1TagCoder<string>;
  OIDMap: ASN1TagCoder<string>;
  BitString: ASN1TagCoder<Uint8Array>;
  BitStringRaw: ASN1TagCoder<{ unused: number; bytes: Uint8Array }>;
  UTF8: ASN1TagCoder<string>;
  UTF8String: ASN1TagCoder<string>;
  IA5String: ASN1TagCoder<string>;
  PrintableString: ASN1TagCoder<string>;
  TeletexString: ASN1TagCoder<string>;
  VisibleString: ASN1TagCoder<string>;
  NumericString: ASN1TagCoder<string>;
  BMPString: ASN1TagCoder<string>;
  UniversalString: ASN1TagCoder<string>;
  String: P.CoderType<ASN1StringValue>;
  UTCTime: ASN1TagCoder<string>;
  GeneralizedTime: ASN1TagCoder<string>;
  Time: P.CoderType<ASN1Time>;
  null: ASN1TagCoder<null>;
  any: P.CoderType<Uint8Array>;
  TLVNode: P.CoderType<TLVNode>;
  StringOrRaw: P.CoderType<ASN1StringOrRaw>;
  AnyValue: P.CoderType<ASN1AnyValue>;
  AlgorithmIdentifier: ASN1TagCoder<ASN1AlgorithmIdentifier>;
  Attribute: ASN1TagCoder<ASN1Attribute>;
  ECDSASig: ASN1TagCoder<{ r: bigint; s: bigint }>;
  choice: <T extends Record<string, unknown>>(
    variants: ASN1ChoiceRecord<T>
  ) => P.CoderType<ASN1ChoiceResult<T>>;
  sequence: <T extends Record<string, unknown>>(fields: ASN1StructRecord<T>) => ASN1TagCoder<T>;
  set: <T>(inner: P.CoderType<T>, opts?: { ber?: boolean }) => ASN1TagCoder<T[]>;
  explicit: <T>(number: number, inner: P.CoderType<T>) => ASN1TagCoder<T>;
  implicit: <T>(number: number, inner: ASN1TagCoder<T>) => ASN1TagCoder<T>;
  optional: {
    <T>(inner: ASN1TagCoder<T>): ASN1TagCoder<T | undefined>;
    <T>(inner: P.CoderType<T>): P.CoderType<T | undefined>;
  };
};
/** Low-level DER/ASN.1 coders and BER normalization helpers. */
export type DERUtilsPub = {
  /** BER decoder/encoder used to normalize supported BER input to DER. */
  BER: {
    decode: (
      src: TArg<Uint8Array>,
      opts?: { allowBER?: boolean }
    ) => TRet<{ nodes: BerNode[]; der: Uint8Array }>;
    encode: (nodes: BerNode[], der: TArg<Uint8Array>) => TRet<Uint8Array>;
    normalize: (src: TArg<Uint8Array>, opts?: { allowBER?: boolean }) => TRet<Uint8Array>;
  };
  /** DER length coder with minimal-length validation. */
  DERLen: P.CoderType<number>;
  /** Generic ASN.1 building blocks used by the DER converters. */
  ASN1: ASN1Pub;
  /** PKCS#1 RSA private-key decoder for compatibility parsing. */
  RSAPrivateKey: P.CoderType<RSAKey>;
  /** Inner PKCS#8 private-key OCTET STRING body coder. */
  PKCS8SecretKey: P.CoderType<PKCS8Secret>;
  /** PKCS#8 PrivateKeyInfo coder. */
  PKCS8: P.CoderType<PKCS8Key>;
  /** X.509 SubjectPublicKeyInfo coder. */
  SPKI: P.CoderType<SPKIKey>;
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
type BERDoc = { nodes: BerNode[]; der: Uint8Array };
const berRaw = (n: unknown): TRet<BerRawNode> => n as TRet<BerRawNode>;
// RFC 5958 receivers must accept BER input, so this helper keeps enough
// BER metadata to re-emit indefinite/constructed forms while also exposing
// a DER-normalized byte view for the higher-level converters.
const BER = {
  parse: (src: TArg<Uint8Array>, pos: number, allowBER: boolean): TRet<BerRawNode> => {
    const aTag = src[pos++];
    if (aTag === undefined) throw new Error('unexpected end of input');
    const cls = aTag >>> 6;
    const cons = !!(aTag & 0x20);
    let tagNum = aTag & 0x1f;
    const tagBytes: number[] = [aTag];
    if (tagNum === 0x1f) {
      while (true) {
        const b = src[pos++];
        if (b === undefined) throw new Error('unexpected end of high-tag-number');
        tagBytes.push(b);
        if (!(b & 0x80)) break;
      }
      // RFC 5958 §2 requires BER receiver support and references X.690 for BER;
      // the uint32 cap is this public `number` metadata boundary, not an X.690 requirement.
      tagNum = highTagNumber(tagBytes);
    }
    const tg = { bytes: Uint8Array.from(tagBytes), cls, cons, tagNum };
    const lenAt = pos;
    const aLen = src[pos++];
    if (aLen === undefined) throw new Error('unexpected end of length');
    let ln: { len?: number; indefinite: boolean };
    if (aLen < 0x80) ln = { len: aLen, indefinite: false };
    else if (aLen === 0x80) ln = { indefinite: true };
    else {
      const n = aLen & 0x7f;
      if (!n) throw new Error('invalid length header');
      if (pos + n > src.length) throw new Error('length overrun');
      const lenBytes = src.subarray(pos, pos + n);
      const len = lenValue(lenBytes);
      // BER definite-long length may be non-minimal; DER must reject it here
      // so strict callers do not silently canonicalize malformed DER.
      if (!allowBER && (len < 0x80 || lenBytes[0] === 0))
        throw new Error('DER non-minimal length encoding');
      pos += n;
      ln = { len, indefinite: false };
    }
    const lenBytes = src.slice(lenAt, pos);
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
        const n = BER.parse(src, pos, allowBER);
        nodes.push(n);
        pos = n.pos;
      }
      const constructed = concatBytes(...nodes.map((i) => i.der));
      if (tg.cls === 0 && primitiveTypes.has(tg.tagNum) && tg.tagNum !== 16 && tg.tagNum !== 17) {
        if (!allowBER) throw new Error('BER constructed primitive is not allowed');
        const outTag = tg.bytes.slice();
        outTag[0] &= ~0x20;
        if (tg.tagNum === 3) {
          if (!nodes.length)
            return berRaw({
              tag: tg.bytes,
              len: lenBytes,
              indefinite: true,
              children: nodes,
              der: concatBytes(...[outTag, DERLen.encode(1), Uint8Array.from([0])]),
              value: Uint8Array.from([0]),
              pos,
              cls: tg.cls,
              tagNum: tg.tagNum,
              cons: tg.cons,
            });
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
          const value = concatBytes(...[Uint8Array.from([unused]), ...parts]);
          return berRaw({
            tag: tg.bytes,
            len: lenBytes,
            indefinite: true,
            children: nodes,
            der: concatBytes(...[outTag, DERLen.encode(value.length), value]),
            value,
            pos,
            cls: tg.cls,
            tagNum: tg.tagNum,
            cons: tg.cons,
          });
        }
        const value = concatBytes(...nodes.map((i) => i.value));
        return berRaw({
          tag: tg.bytes,
          len: lenBytes,
          indefinite: true,
          children: nodes,
          der: concatBytes(...[outTag, DERLen.encode(value.length), value]),
          value,
          pos,
          cls: tg.cls,
          tagNum: tg.tagNum,
          cons: tg.cons,
        });
      }
      return berRaw({
        tag: tg.bytes,
        len: lenBytes,
        indefinite: true,
        children: nodes,
        der: concatBytes(...[tg.bytes, DERLen.encode(constructed.length), constructed]),
        value: constructed,
        pos,
        cls: tg.cls,
        tagNum: tg.tagNum,
        cons: tg.cons,
      });
    }
    if (ln.len === undefined) throw new Error('length missing');
    if (pos + ln.len > src.length) throw new Error('length overrun');
    const valueRaw = src.slice(pos, pos + ln.len);
    pos += ln.len;
    if (!tg.cons)
      return berRaw({
        tag: tg.bytes,
        len: lenBytes,
        indefinite: false,
        der: concatBytes(...[tg.bytes, DERLen.encode(valueRaw.length), valueRaw]),
        value: valueRaw,
        pos,
        cls: tg.cls,
        tagNum: tg.tagNum,
        cons: tg.cons,
      });
    const nodes: BerRawNode[] = [];
    let at = 0;
    while (at < valueRaw.length) {
      const n = BER.parse(valueRaw, at, allowBER);
      nodes.push(n);
      at = n.pos;
    }
    if (at !== valueRaw.length) throw new Error('constructed value parse mismatch');
    const constructed = concatBytes(...nodes.map((i) => i.der));
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
              return concatBytes(...[Uint8Array.from([unused]), ...parts]);
            })()
          : concatBytes(...nodes.map((i) => i.value));
      return berRaw({
        tag: tg.bytes,
        len: lenBytes,
        indefinite: false,
        children: nodes,
        der: concatBytes(...[outTag, DERLen.encode(value.length), value]),
        value,
        pos,
        cls: tg.cls,
        tagNum: tg.tagNum,
        cons: tg.cons,
      });
    }
    return berRaw({
      tag: tg.bytes,
      len: lenBytes,
      indefinite: false,
      children: nodes,
      der: concatBytes(...[tg.bytes, DERLen.encode(constructed.length), constructed]),
      value: constructed,
      pos,
      cls: tg.cls,
      tagNum: tg.tagNum,
      cons: tg.cons,
    });
  },
  tag: (cls: number, cons: boolean, tagNum: number): TRet<Uint8Array> => {
    if (!Number.isInteger(cls) || cls < 0 || cls > 3) throw new Error(`invalid BER class ${cls}`);
    if (!Number.isInteger(tagNum) || tagNum < 0 || tagNum > BER_TAG_MAX)
      throw new Error(`invalid BER tag number ${tagNum}`);
    const c = cons ? 0x20 : 0x00;
    if (tagNum < 31) return Uint8Array.from([(cls << 6) | c | tagNum]) as TRet<Uint8Array>;
    const out: number[] = [(cls << 6) | c | 0x1f];
    const parts: number[] = [];
    for (let n = tagNum; n > 0; n = Math.floor(n / 128)) parts.unshift(n % 128);
    if (!parts.length) parts.push(0);
    for (let i = 0; i < parts.length - 1; i++) out.push(parts[i] | 0x80);
    out.push(parts[parts.length - 1]);
    return Uint8Array.from(out) as TRet<Uint8Array>;
  },
  meta: (n: TArg<BerRawNode>): BerNode => ({
    len: n.value.length,
    lenBytes: n.indefinite ? 0 : n.len[0] < 0x80 ? 1 : 1 + (n.len[0] & 0x7f),
    indefinite: n.indefinite,
    bitUnused: n.cls === 0 && n.tagNum === 3 && !n.cons && n.value.length ? n.value[0] : undefined,
    children: n.children?.map(BER.meta),
    cls: n.cls,
    tagNum: n.tagNum,
    cons: n.cons,
  }),
  buildRaw: (cls: number, tagNum: number, value: TArg<Uint8Array>): TRet<BerRawNode> =>
    berRaw({
      tag: BER.tag(cls, false, tagNum),
      len: DERLen.encode(value.length),
      indefinite: false,
      der: concatBytes(...[BER.tag(cls, false, tagNum), DERLen.encode(value.length), value]),
      value,
      pos: 0,
      cls,
      tagNum,
      cons: false,
    }),
  len: (len: number, lenBytes: number): TRet<Uint8Array> => {
    if (!Number.isSafeInteger(len) || len < 0) throw new Error(`invalid BER length ${len}`);
    if (!Number.isSafeInteger(lenBytes) || lenBytes < 1)
      throw new Error(`invalid BER length-size ${lenBytes}`);
    if (lenBytes === 1) {
      if (len >= 0x80) throw new Error(`short BER length cannot encode ${len}`);
      return Uint8Array.from([len]) as TRet<Uint8Array>;
    }
    const width = lenBytes - 1;
    return Uint8Array.from([0x80 | width, ...lenBody(len, width, false)]) as TRet<Uint8Array>;
  },
  node: (n: TArg<BerRawNode>, meta: BerNode): TRet<Uint8Array> => {
    if (meta.cls !== n.cls || meta.tagNum !== n.tagNum)
      throw new Error(
        `BER tag mismatch expected cls=${meta.cls} tag=${meta.tagNum}, got cls=${n.cls} tag=${n.tagNum}`
      );
    const tag = BER.tag(meta.cls, meta.cons, meta.tagNum);
    if (!meta.cons) {
      const v = n.value;
      if (meta.indefinite) throw new Error('BER primitive cannot use indefinite length');
      return concatBytes(...[tag, BER.len(v.length, meta.lenBytes), v]) as TRet<Uint8Array>;
    }
    const mm = meta.children || [];
    let srcChildren: BerRawNode[] | undefined;
    if (n.cons) srcChildren = n.children || [];
    else if (n.cls === 0 && n.tagNum === 4) {
      let at = 0;
      const out: BerRawNode[] = [];
      for (const m of mm) {
        const len = m.len;
        if (!Number.isInteger(len) || len < 0 || at + len > n.value.length)
          throw new Error('BER child shape mismatch');
        const v = n.value.slice(at, at + len);
        out.push(BER.buildRaw(n.cls, n.tagNum, v));
        at += len;
      }
      if (at !== n.value.length) throw new Error('BER child shape mismatch');
      srcChildren = out;
    } else if (n.cls === 0 && n.tagNum === 3) {
      if (!n.value.length) throw new Error('BER child shape mismatch');
      const u = n.value[0];
      const bits = n.value.slice(1);
      let at = 0;
      const out: BerRawNode[] = [];
      for (let i = 0; i < mm.length; i++) {
        const m = mm[i];
        if (!Number.isInteger(m.len) || m.len < 1) throw new Error('BER child shape mismatch');
        const dlen = m.len - 1;
        if (at + dlen > bits.length) throw new Error('BER child shape mismatch');
        const cu = i + 1 === mm.length ? u : m.bitUnused || 0;
        const v = concatBytes(...[Uint8Array.from([cu]), bits.slice(at, at + dlen)]);
        out.push(BER.buildRaw(n.cls, n.tagNum, v));
        at += dlen;
      }
      if (at !== bits.length) throw new Error('BER child shape mismatch');
      srcChildren = out;
    }
    if (!srcChildren || srcChildren.length !== mm.length)
      throw new Error('BER child shape mismatch');
    const body = concatBytes(...srcChildren.map((c, i) => BER.node(c, mm[i])));
    if (meta.indefinite)
      return concatBytes(
        ...[tag, Uint8Array.from([0x80]), body, Uint8Array.from([0x00, 0x00])]
      ) as TRet<Uint8Array>;
    return concatBytes(...[tag, BER.len(body.length, meta.lenBytes), body]) as TRet<Uint8Array>;
  },
  decode: (src: TArg<Uint8Array>, opts: { allowBER?: boolean } = {}): TRet<BERDoc> => {
    const allowBER = !!opts.allowBER;
    const nodes: BerNode[] = [];
    const der: Uint8Array[] = [];
    let pos = 0;
    while (pos < src.length) {
      const n = BER.parse(src, pos, allowBER);
      nodes.push(BER.meta(n));
      der.push(n.der);
      pos = n.pos;
    }
    return { nodes, der: concatBytes(...der) } as TRet<BERDoc>;
  },
  encode: (nodes: BerNode[], der: TArg<Uint8Array>): TRet<Uint8Array> => {
    const rawNodes: BerRawNode[] = [];
    let pos = 0;
    while (pos < der.length) {
      const n = BER.parse(der, pos, false);
      rawNodes.push(n);
      pos = n.pos;
    }
    if (rawNodes.length !== nodes.length) throw new Error('BER root node count mismatch');
    return concatBytes(...rawNodes.map((n, i) => BER.node(n, nodes[i]))) as TRet<Uint8Array>;
  },
  normalize: (src: TArg<Uint8Array>, opts: { allowBER?: boolean } = {}): TRet<Uint8Array> => {
    const allowBER = !!opts.allowBER;
    const out: Uint8Array[] = [];
    let pos = 0;
    while (pos < src.length) {
      const n = BER.parse(src, pos, allowBER);
      out.push(n.der);
      pos = n.pos;
    }
    return concatBytes(...out) as TRet<Uint8Array>;
  },
} as const;
// The outer PKCS#8 / OneAsymmetricKey privateKey field is always an OCTET
// STRING, but the wrapped payload is algorithm-specific: RFC 8410 uses an
// inner CurvePrivateKey OCTET STRING, while RFC 5915 EC keys use ECPrivateKey.
const ECPrivateKey = /* @__PURE__ */ (() =>
  ASN1.validate(
    ASN1.sequence({
      version: ASN1.Integer,
      privateKey: ASN1.OctetString,
      parameters: ASN1.optional(ASN1.explicit(0, ECParameters)),
      publicKey: ASN1.optional(ASN1.explicit(1, ASN1.BitString)),
    }),
    (key) => {
      // RFC 5915 §3 defines ECPrivateKey.version as ecPrivkeyVer1(1) and says
      // this document's version SHALL be set to that value.
      if (key.version !== _1n)
        throw new Error(`ECPrivateKey: expected version 1, got ${key.version}`);
      return key;
    }
  ))();
const PKCS8SecretKey = /* @__PURE__ */ (() =>
  ASN1.choice({
    raw: ASN1.OctetString,
    struct: ECPrivateKey,
  }))() as unknown as P.CoderType<PKCS8Secret>;
const PKCS8Raw = /* @__PURE__ */ (() =>
  ASN1.sequence({
    version: ASN1.Integer,
    algorithm: KeyAlgorithm,
    privateKey: ASN1.OctetString,
    attributes: /* @__PURE__ */ ASN1.optional(/* @__PURE__ */ ASN1.implicit(0, Attributes)),
    publicKey: /* @__PURE__ */ ASN1.optional(/* @__PURE__ */ ASN1.implicit(1, ASN1.BitString)),
  }))() as unknown as P.CoderType<PKCS8Raw>;
// treeshake: these schema objects still stay alive through member reads unless
// the whole declaration is pure.
// RFC 5208-compatible PrivateKeyInfo stays at version 0 without a top-level
// publicKey, while RFC 5958 requires version 1 once the outer publicKey field
// is present.
const pkcs8Version = (version: bigint, publicKey?: TArg<Uint8Array>) => {
  // RFC 5958 §2 defines Version as v1(0), v2(1): if publicKey is present,
  // version is set to v2; otherwise it is set to v1.
  if (version !== _0n && version !== _1n) throw new Error('PKCS8: expected version 0 or 1');
  if (publicKey !== undefined && version !== _1n)
    throw new Error('PKCS8: expected version 1 when publicKey is present');
  if (publicKey === undefined && version !== _0n)
    throw new Error('PKCS8: expected version 0 when publicKey is absent');
};
const PKCS8: P.CoderType<PKCS8Key> = /* @__PURE__ */ (() =>
  P.apply(PKCS8Raw, {
    encode(to: TArg<PKCS8Raw>): TRet<PKCS8Key> {
      const raw = to as PKCS8Raw;
      pkcs8Version(raw.version, raw.publicKey);
      // RFC 5208 §5 / RFC 5958 §2 make privateKey algorithm-defined:
      // rsaEncryption carries raw RFC 8017 Appendix A.1.2 RSAPrivateKey bytes,
      // not the RFC 8410 inner CurvePrivateKey OCTET STRING used by Ed/X keys.
      if (raw.algorithm.info.TAG === 'rsaEncryption')
        return {
          ...raw,
          privateKey: { TAG: 'raw' as const, data: raw.privateKey },
        } as TRet<PKCS8Key>;
      return { ...raw, privateKey: PKCS8SecretKey.decode(raw.privateKey) } as TRet<PKCS8Key>;
    },
    decode(from: TArg<PKCS8Key>): TRet<PKCS8Raw> {
      const key = from as PKCS8Key;
      pkcs8Version(key.version, key.publicKey);
      if (key.algorithm.info.TAG === 'rsaEncryption') {
        if (key.privateKey.TAG !== 'raw')
          throw new Error('PKCS8 RSA: expected raw RSAPrivateKey payload');
        return { ...key, privateKey: key.privateKey.data } as TRet<PKCS8Raw>;
      }
      return { ...key, privateKey: PKCS8SecretKey.encode(key.privateKey) } as TRet<PKCS8Raw>;
    },
  }))();
// Keep subjectPublicKey as the raw BIT STRING payload here; RFC 3279 / RFC 5480 /
// RFC 8410 define the algorithm-specific bytes, and derConverter validates the
// curve/key shape later at the public converter boundary.
const SPKI = /* @__PURE__ */ (() =>
  ASN1.sequence({
    algorithm: KeyAlgorithm,
    publicKey: ASN1.BitString,
  }))();

// Could be beautifully typed, but because of isolatedDeclarations, we return garbage.
/**
 * Low-level DER, BER, ASN.1, PKCS#8, and SPKI helpers.
 * @example
 * Reach for the raw ASN.1 coders when you need to inspect key structures by hand.
 * ```ts
 * import { DERUtils } from 'micro-key-producer/convert.js';
 * DERUtils.ASN1.OID.encode('1.2.840.10045.3.1.7');
 * ```
 */
export const DERUtils: TRet<DERUtilsPub> = /* @__PURE__ */ deepFreeze(
  /* @__PURE__ */ (() => {
    // treeshake: keep RSA PKCS#1 structure inside DERUtils so converter-only
    // bundles can drop DERUtils as a whole.
    const OtherPrimeInfo = ASN1.sequence({
      prime: ASN1.Integer,
      exponent: ASN1.Integer,
      coefficient: ASN1.Integer,
    });
    const OtherPrimeInfos = ASN1.sequence({
      values: P.array(null, OtherPrimeInfo),
    });
    const RSAPrivateKeyInner = ASN1.sequence({
      version: ASN1.Integer,
      modulus: ASN1.Integer,
      publicExponent: ASN1.Integer,
      privateExponent: ASN1.Integer,
      prime1: ASN1.Integer,
      prime2: ASN1.Integer,
      exponent1: ASN1.Integer,
      exponent2: ASN1.Integer,
      coefficient: ASN1.Integer,
      otherPrimeInfos: ASN1.optional(OtherPrimeInfos),
    });
    const rsaOtherPrimes = (version: bigint, other?: RSAOtherPrimeInfo[]) => {
      // RFC 8017 Appendix A.1.2 defines Version as two-prime(0) or multi(1):
      // otherPrimeInfos SHALL be omitted for version 0 and present with at
      // least one OtherPrimeInfo for version 1.
      if (version !== _0n && version !== _1n)
        throw new Error('RSAPrivateKey: expected version 0 or 1');
      if (version === _0n && other !== undefined)
        throw new Error('RSAPrivateKey: unexpected otherPrimeInfos for version 0');
      if (version === _1n && (!other || !other.length))
        throw new Error('RSAPrivateKey: expected otherPrimeInfos for version 1');
    };
    const RSAPrivateKey = P.apply(RSAPrivateKeyInner, {
      encode(to): RSAKey {
        const other = to.otherPrimeInfos?.values;
        rsaOtherPrimes(to.version, other);
        return { ...to, otherPrimeInfos: other };
      },
      decode(from: RSAKey) {
        rsaOtherPrimes(from.version, from.otherPrimeInfos);
        return {
          ...from,
          otherPrimeInfos:
            from.otherPrimeInfos === undefined ? undefined : { values: from.otherPrimeInfos },
        };
      },
    });
    return {
      BER,
      DERLen: DERLen,
      ASN1: ASN1 as unknown as ASN1Pub,
      RSAPrivateKey: RSAPrivateKey as unknown as P.CoderType<RSAKey>,
      PKCS8SecretKey: PKCS8SecretKey as unknown as P.CoderType<PKCS8Secret>,
      PKCS8: PKCS8 as unknown as P.CoderType<PKCS8Key>,
      SPKI: SPKI as unknown as P.CoderType<SPKIKey>,
    };
  })()
) as TRet<DERUtilsPub>;

type DEROpts = {
  noPublicKey?: boolean;
  compressed?: boolean;
};

type DERConverter = ECConverter<Uint8Array, DEROpts>;
function derConverter(
  curve: Curve,
  info: P.UnwrapCoder<typeof KeyAlgorithm>['info']
): TRet<DERConverter> {
  function checkParams(params: ECParams, expected?: string): string {
    if (params.TAG !== 'namedCurve') throw new Error('non-named curves not supported');
    if (expected === undefined) return params.data;
    // RFC 5915 §1 puts the PKCS#8 EC namedCurve in privateKeyAlgorithm; §3 says
    // ECPrivateKey.parameters are the domain parameters for that same private key,
    // and RFC 5480 §2.1.1 says namedCurve fully identifies those parameters.
    if (params.data !== expected) throw new Error('different curve');
    return params.data;
  }
  const expectedCurve = info.TAG === 'EC' ? checkParams(info.data) : undefined;
  function checkAlgo(keyInfo: KeyInfo) {
    // Each exported converter is fixed to one algorithm family, and EC
    // converters also pin one namedCurve OID for both SPKI and PKCS#8.
    if (keyInfo.TAG !== info.TAG) throw new Error('different curve algorithm');
    if (keyInfo.TAG === 'EC' && info.TAG === 'EC') {
      checkParams(keyInfo.data, expectedCurve);
    }
  }
  const publicKey: P.Coder<Uint8Array, Uint8Array> = {
    encode: (key: TArg<Uint8Array>): TRet<Uint8Array> => {
      const raw = key as Uint8Array;
      if ('isValidPublicKey' in curve.utils) {
        if (!curve.utils.isValidPublicKey(raw)) throw new Error('wrong public key');
      }
      // we encode what was given always by user (no method to uncompress public key without deps on point)
      return SPKI.encode({ algorithm: { info }, publicKey: raw }) as TRet<Uint8Array>;
    },
    decode: (key: TArg<Uint8Array>): TRet<Uint8Array> => {
      const decoded = SPKI.decode(key);
      checkAlgo(decoded.algorithm.info);
      const publicKey = decoded.publicKey;
      if ('isValidPublicKey' in curve.utils) {
        if (!curve.utils.isValidPublicKey(publicKey)) throw new Error('wrong public key');
      }
      return publicKey as TRet<Uint8Array>;
    },
  };
  // There also encrypted version of PKCS8, not supported in webcrypto, not supported by us (yet?)
  const secretKey: P.Coder<Uint8Array, Uint8Array> = {
    encode: (key: TArg<Uint8Array>, opts: DEROpts = {}): TRet<Uint8Array> => {
      const raw = key as Uint8Array;
      if ('isValidSecretKey' in curve.utils) {
        if (!curve.utils.isValidSecretKey(raw)) throw new Error('wrong secret key');
      }
      // uncompressed by default (compat with webcrypto)
      const publicKey = opts.noPublicKey
        ? undefined
        : info.TAG === 'EC'
          ? curve.getPublicKey(raw, !!opts.compressed) // only in weierstrass
          : curve.getPublicKey(raw);
      // RFC 5915 §3 makes ECPrivateKey.parameters ASN.1 OPTIONAL; keep
      // omitting it here so generated EC PKCS#8 stays byte-compatible with
      // WebCrypto, while the outer RFC 5915 §1 namedCurve still names the curve.
      const privateKey =
        info.TAG === 'EC'
          ? ({ TAG: 'struct', data: { version: _1n, privateKey: raw, publicKey } } as const)
          : ({ TAG: 'raw', data: raw } as const);
      // RFC 8410 allows a top-level publicKey for Ed/X PKCS#8, but current
      // WebCrypto exports omit it; keep the shorter form for byte-for-byte compatibility.
      return PKCS8.encode({ version: _0n, algorithm: { info }, privateKey }) as TRet<Uint8Array>;
    },
    decode: (key: TArg<Uint8Array>): TRet<Uint8Array> => {
      const decoded = PKCS8.decode(key);
      checkAlgo(decoded.algorithm.info);
      // EC + struct, other + raw
      // It would be nice to check if publicKey is valid, but that would leak compressed/uncompressed stuff here.
      let secretKey;
      if (decoded.algorithm.info.TAG === 'EC') {
        if (decoded.privateKey.TAG !== 'struct')
          throw new Error('derConverter.secretKey.decode: algorithm secret key type mismatch');
        // RFC 5915 §3 says conforming ECPrivateKey includes parameters, but
        // WebCrypto EC PKCS#8 omits this inner field; when it is absent, the
        // outer RFC 5915 §1 / RFC 5480 §2.1.1 namedCurve checked above is used.
        if (decoded.privateKey.data.parameters)
          checkParams(decoded.privateKey.data.parameters, expectedCurve);
        secretKey = decoded.privateKey.data.privateKey;
      } else {
        if (decoded.privateKey.TAG !== 'raw')
          throw new Error('derConverter.secretKey.decode: algorithm secret key type mismatch');
        secretKey = decoded.privateKey.data;
      }
      // Check publicKey if exists
      const pub = curve.getPublicKey(secretKey, false);
      const pubCompressed = curve.getPublicKey(secretKey, true);
      const checkPub = (p: TArg<Uint8Array>) => {
        if (!equalBytes(p, pub) && !equalBytes(p, pubCompressed))
          throw new Error('wrong public key');
      };
      if (decoded.publicKey) checkPub(decoded.publicKey);
      if (decoded.privateKey.TAG === 'struct' && decoded.privateKey.data.publicKey)
        checkPub(decoded.privateKey.data.publicKey);
      if ('isValidSecretKey' in curve.utils) {
        if (!curve.utils.isValidSecretKey(secretKey)) throw new Error('wrong secret key');
      }
      return secretKey as TRet<Uint8Array>;
    },
  };
  // const Signature = {}
  return deepFreeze({ publicKey, secretKey }) as TRet<DERConverter>;
}

// Per-curve definitions
/**
 * JWK converter for P-256 signing keys.
 * @example
 * Encode a freshly generated P-256 signing key as JWK.
 * ```ts
 * import { p256 } from '@noble/curves/nist.js';
 * import { p256_jwk } from 'micro-key-producer/convert.js';
 * p256_jwk.secretKey.encode(p256.utils.randomSecretKey());
 * ```
 */
export const p256_jwk: TRet<JWKConverter> = /* @__PURE__ */ (() =>
  // RFC 7518 §3.4 registers `ES256` for ECDSA over P-256; WebCrypto exports
  // omit `alg`, so accept both metadata forms on decode.
  jwkConverter(p256, jwkPointCoder(p256.Point), { kty: 'EC', crv: 'P-256' }, false, [
    undefined,
    'ES256',
  ]))();
/**
 * JWK converter for P-256 ECDH keys.
 * @example
 * Encode a P-256 private key for ECDH-oriented JWK consumers.
 * ```ts
 * import { p256 } from '@noble/curves/nist.js';
 * import { p256_jwk_ecdh } from 'micro-key-producer/convert.js';
 * p256_jwk_ecdh.secretKey.encode(p256.utils.randomSecretKey());
 * ```
 */
export const p256_jwk_ecdh: TRet<JWKConverter> = /* @__PURE__ */ (() =>
  jwkConverter(p256, jwkPointCoder(p256.Point), { kty: 'EC', crv: 'P-256' }, true, ECDH_ES_ALGS))();
/**
 * DER converter for P-256 keys.
 * @example
 * Encode the same P-256 secret key into DER/PKCS#8 form.
 * ```ts
 * import { p256 } from '@noble/curves/nist.js';
 * import { p256_der } from 'micro-key-producer/convert.js';
 * p256_der.secretKey.encode(p256.utils.randomSecretKey());
 * ```
 */
export const p256_der: TRet<DERConverter> = /* @__PURE__ */ (() =>
  derConverter(p256, {
    TAG: 'EC',
    data: { TAG: 'namedCurve', data: 'P-256' },
  }))();

/**
 * JWK converter for P-384 signing keys.
 * @example
 * Encode a freshly generated P-384 signing key as JWK.
 * ```ts
 * import { p384 } from '@noble/curves/nist.js';
 * import { p384_jwk } from 'micro-key-producer/convert.js';
 * p384_jwk.secretKey.encode(p384.utils.randomSecretKey());
 * ```
 */
export const p384_jwk: TRet<JWKConverter> = /* @__PURE__ */ (() =>
  // RFC 7518 §3.4 registers `ES384` for ECDSA over P-384; WebCrypto exports
  // omit `alg`, so accept both metadata forms on decode.
  jwkConverter(p384, jwkPointCoder(p384.Point), { kty: 'EC', crv: 'P-384' }, false, [
    undefined,
    'ES384',
  ]))();
/**
 * JWK converter for P-384 ECDH keys.
 * @example
 * Encode a P-384 private key for ECDH-oriented JWK consumers.
 * ```ts
 * import { p384 } from '@noble/curves/nist.js';
 * import { p384_jwk_ecdh } from 'micro-key-producer/convert.js';
 * p384_jwk_ecdh.secretKey.encode(p384.utils.randomSecretKey());
 * ```
 */
export const p384_jwk_ecdh: TRet<JWKConverter> = /* @__PURE__ */ (() =>
  jwkConverter(p384, jwkPointCoder(p384.Point), { kty: 'EC', crv: 'P-384' }, true, ECDH_ES_ALGS))();
/**
 * DER converter for P-384 keys.
 * @example
 * Encode the same P-384 secret key into DER/PKCS#8 form.
 * ```ts
 * import { p384 } from '@noble/curves/nist.js';
 * import { p384_der } from 'micro-key-producer/convert.js';
 * p384_der.secretKey.encode(p384.utils.randomSecretKey());
 * ```
 */
export const p384_der: TRet<DERConverter> = /* @__PURE__ */ (() =>
  derConverter(p384, {
    TAG: 'EC',
    data: { TAG: 'namedCurve', data: 'P-384' },
  }))();

/**
 * JWK converter for P-521 signing keys.
 * @example
 * Encode a freshly generated P-521 signing key as JWK.
 * ```ts
 * import { p521 } from '@noble/curves/nist.js';
 * import { p521_jwk } from 'micro-key-producer/convert.js';
 * p521_jwk.secretKey.encode(p521.utils.randomSecretKey());
 * ```
 */
export const p521_jwk: TRet<JWKConverter> = /* @__PURE__ */ (() =>
  // RFC 7518 §3.4 registers `ES512` for ECDSA over P-521; WebCrypto exports
  // omit `alg`, so accept both metadata forms on decode.
  jwkConverter(p521, jwkPointCoder(p521.Point), { kty: 'EC', crv: 'P-521' }, false, [
    undefined,
    'ES512',
  ]))();
/**
 * JWK converter for P-521 ECDH keys.
 * @example
 * Encode a P-521 private key for ECDH-oriented JWK consumers.
 * ```ts
 * import { p521 } from '@noble/curves/nist.js';
 * import { p521_jwk_ecdh } from 'micro-key-producer/convert.js';
 * p521_jwk_ecdh.secretKey.encode(p521.utils.randomSecretKey());
 * ```
 */
export const p521_jwk_ecdh: TRet<JWKConverter> = /* @__PURE__ */ (() =>
  jwkConverter(p521, jwkPointCoder(p521.Point), { kty: 'EC', crv: 'P-521' }, true, ECDH_ES_ALGS))();
/**
 * DER converter for P-521 keys.
 * @example
 * Encode the same P-521 secret key into DER/PKCS#8 form.
 * ```ts
 * import { p521 } from '@noble/curves/nist.js';
 * import { p521_der } from 'micro-key-producer/convert.js';
 * p521_der.secretKey.encode(p521.utils.randomSecretKey());
 * ```
 */
export const p521_der: TRet<DERConverter> = /* @__PURE__ */ (() =>
  derConverter(p521, {
    TAG: 'EC',
    data: { TAG: 'namedCurve', data: 'P-521' },
  }))();

/**
 * JWK converter for Ed25519 keys.
 * @example
 * Encode an Ed25519 secret key into JWK form.
 * ```ts
 * import { ed25519 } from '@noble/curves/ed25519.js';
 * import { ed25519_jwk } from 'micro-key-producer/convert.js';
 * ed25519_jwk.secretKey.encode(ed25519.utils.randomSecretKey());
 * ```
 */
export const ed25519_jwk: TRet<JWKConverter> = /* @__PURE__ */ jwkConverter(
  ed25519,
  jwkBytesCoder,
  // RFC 8037 §3.1 uses `alg="EdDSA"` for Ed25519 JOSE signatures, but
  // WebCrypto exports `alg="Ed25519"`; keep the WebCrypto form for byte-for-byte round-trips.
  { kty: 'OKP', crv: 'Ed25519', alg: 'Ed25519' },
  false,
  [undefined, 'EdDSA', 'Ed25519']
);
/**
 * DER converter for Ed25519 keys.
 * @example
 * Encode the same Ed25519 secret key into DER/PKCS#8 form.
 * ```ts
 * import { ed25519 } from '@noble/curves/ed25519.js';
 * import { ed25519_der } from 'micro-key-producer/convert.js';
 * ed25519_der.secretKey.encode(ed25519.utils.randomSecretKey());
 * ```
 */
export const ed25519_der: TRet<DERConverter> = /* @__PURE__ */ derConverter(ed25519, {
  TAG: 'Ed25519',
  data: null,
});

/**
 * JWK converter for Ed448 keys.
 * @example
 * Encode an Ed448 secret key into JWK form.
 * ```ts
 * import { ed448 } from '@noble/curves/ed448.js';
 * import { ed448_jwk } from 'micro-key-producer/convert.js';
 * ed448_jwk.secretKey.encode(ed448.utils.randomSecretKey());
 * ```
 */
export const ed448_jwk: TRet<JWKConverter> = /* @__PURE__ */ jwkConverter(
  ed448,
  jwkBytesCoder,
  // RFC 8037 §3.1 uses `alg="EdDSA"` for Ed448 JOSE signatures, but
  // WebCrypto exports `alg="Ed448"`; keep the WebCrypto form for byte-for-byte round-trips.
  { kty: 'OKP', crv: 'Ed448', alg: 'Ed448' },
  false,
  [undefined, 'EdDSA', 'Ed448']
);
/**
 * DER converter for Ed448 keys.
 * @example
 * Encode the same Ed448 secret key into DER/PKCS#8 form.
 * ```ts
 * import { ed448 } from '@noble/curves/ed448.js';
 * import { ed448_der } from 'micro-key-producer/convert.js';
 * ed448_der.secretKey.encode(ed448.utils.randomSecretKey());
 * ```
 */
export const ed448_der: TRet<DERConverter> = /* @__PURE__ */ derConverter(ed448, {
  TAG: 'Ed448',
  data: null,
});

/**
 * JWK converter for X25519 keys.
 * @example
 * Encode an X25519 private key into JWK form.
 * ```ts
 * import { x25519 } from '@noble/curves/ed25519.js';
 * import { x25519_jwk } from 'micro-key-producer/convert.js';
 * x25519_jwk.secretKey.encode(x25519.utils.randomSecretKey());
 * ```
 */
export const x25519_jwk: TRet<JWKConverter> = /* @__PURE__ */ jwkConverter(
  x25519,
  jwkBytesCoder,
  // RFC 8037 uses X25519 with the ECDH-ES algorithm family, while WebCrypto
  // exports omit `alg`; keep it unset for byte-for-byte round-trips.
  { kty: 'OKP', crv: 'X25519' },
  true,
  ECDH_ES_ALGS
);
/**
 * DER converter for X25519 keys.
 * @example
 * Encode the same X25519 secret key into DER/PKCS#8 form.
 * ```ts
 * import { x25519 } from '@noble/curves/ed25519.js';
 * import { x25519_der } from 'micro-key-producer/convert.js';
 * x25519_der.secretKey.encode(x25519.utils.randomSecretKey());
 * ```
 */
export const x25519_der: TRet<DERConverter> = /* @__PURE__ */ derConverter(x25519, {
  TAG: 'X25519',
  data: null,
});

/**
 * JWK converter for X448 keys.
 * @example
 * Encode an X448 private key into JWK form.
 * ```ts
 * import { x448 } from '@noble/curves/ed448.js';
 * import { x448_jwk } from 'micro-key-producer/convert.js';
 * x448_jwk.secretKey.encode(x448.utils.randomSecretKey());
 * ```
 */
export const x448_jwk: TRet<JWKConverter> = /* @__PURE__ */ jwkConverter(
  x448,
  jwkBytesCoder,
  // RFC 8037 uses X448 with the ECDH-ES algorithm family, while WebCrypto
  // exports omit `alg`; keep it unset for byte-for-byte round-trips.
  { kty: 'OKP', crv: 'X448' },
  true,
  ECDH_ES_ALGS
);
/**
 * DER converter for X448 keys.
 * @example
 * Encode the same X448 secret key into DER/PKCS#8 form.
 * ```ts
 * import { x448 } from '@noble/curves/ed448.js';
 * import { x448_der } from 'micro-key-producer/convert.js';
 * x448_der.secretKey.encode(x448.utils.randomSecretKey());
 * ```
 */
export const x448_der: TRet<DERConverter> = /* @__PURE__ */ derConverter(x448, {
  TAG: 'X448',
  data: null,
});

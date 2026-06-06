/*! micro-key-producer - MIT License (c) 2024 Paul Miller (paulmillr.com) */
/**
 * ASN.1 OID, DER, and BER helpers.
 * @module
 */
import { bytesToNumberBE } from '@noble/ciphers/utils.js';
import { numberToVarBytesBE } from '@noble/curves/utils.js';
import { bytesToHex, concatBytes, hexToBytes, type TArg, type TRet } from '@noble/hashes/utils.js';
import { ascii, utf8 } from '@scure/base';
import * as P from 'micro-packed';
import { deepFreeze } from './utils.ts';

// ASN.1 OID (object identifier) without tag & length.
// First two elements: [i0 * 40 + i1].
// Others are base-128 subidentifiers: 7-bit chunks with 0x80 on each non-final byte.
/**
 * ASN.1 OID coder without DER tag/length wrappers.
 * @example
 * Encode one ASN.1 object identifier without DER tag and length bytes.
 * ```ts
 * import { oid } from 'micro-key-producer/asn1.js';
 * oid.encode('1.3.6.1.4.1.11591.15.1');
 * ```
 */
export const oid: P.CoderType<string> = /* @__PURE__ */ deepFreeze(
  /* @__PURE__ */ P.wrap({
    encodeStream: (w: P.Writer, value: string) => {
      const items = value.split('.').map((arc) => {
        if (!/^[0-9]+$/.test(arc)) throw new Error(`invalid oid arc ${arc}`);
        const n = Number(arc);
        if (!Number.isSafeInteger(n)) throw new Error(`oid arc exceeds safe integer ${arc}`);
        return n;
      });
      if (items.length < 2) throw new Error('oid must have at least two arcs');
      const first = items[0];
      if (first > 2) throw new Error('oid first arc out of range');
      if (first < 2 && items[1] > 39) throw new Error('oid second arc out of range');
      const firstSubid = first * 40 + items[1];
      if (!Number.isSafeInteger(firstSubid))
        throw new Error('oid first subidentifier exceeds safe integer');
      for (let i = 1; i < items.length; i++) {
        const val = i === 1 ? firstSubid : items[i];
        if (!Number.isSafeInteger(val) || val < 0) throw new Error(`invalid oid arc ${val}`);
        const tmp: number[] = [];
        for (let n = val; n; n = Math.floor(n / 128)) tmp.unshift(n & 0x7f);
        if (!val) tmp.push(0);
        for (let j = 0; j < tmp.length - 1; j++) w.byte(tmp[j] | 0x80);
        w.byte(tmp[tmp.length - 1]);
      }
    },
    decodeStream: (r: P.Reader): string => {
      if (r.isEnd()) throw new Error('empty oid');
      const body: number[] = [];
      while (!r.isEnd()) {
        let val = 0;
        let first = true;
        while (true) {
          const byte = r.byte();
          // RFC 9090 section 2.1 restates X.690 BER OID contents: each base-128
          // subidentifier is shortest-form, so it cannot start with 0x80.
          if (first && byte === 0x80) throw new Error('oid non-minimal arc');
          if (val > (Number.MAX_SAFE_INTEGER - (byte & 0x7f)) / 128)
            throw new Error('oid arc exceeds safe integer');
          val = val * 128 + (byte & 0x7f);
          if (!(byte & 0x80)) break;
          first = false;
        }
        body.push(val);
      }
      const firstArc = body[0] < 80 ? Math.floor(body[0] / 40) : 2;
      const res = [firstArc, body[0] - 40 * firstArc, ...body.slice(1)];
      if (res[0] < 2 && res[1] > 39) throw new Error('oid second arc out of range');
      return res.join('.');
    },
  })
);
// Shared ASN.1 object identifiers used by DER, PGP, X.509, and CMS helpers.
// Keep this table private; public code should use the `oidName` coder so OID
// names and dotted values stay centralized in this cluster.
const OIDS = /* @__PURE__ */ deepFreeze({
  ecPublicKey: '1.2.840.10045.2.1',
  X25519: '1.3.101.110',
  X448: '1.3.101.111',
  Ed25519: '1.3.101.112',
  Ed448: '1.3.101.113',
  'P-256': '1.2.840.10045.3.1.7',
  'P-384': '1.3.132.0.34',
  'P-521': '1.3.132.0.35',
  secp256k1: '1.3.132.0.10',
  brainpoolP256r1: '1.3.36.3.3.2.8.1.1.7',
  brainpoolP384r1: '1.3.36.3.3.2.8.1.1.11',
  brainpoolP512r1: '1.3.36.3.3.2.8.1.1.13',
  curve25519Legacy: '1.3.6.1.4.1.3029.1.5.1',
  ed25519Legacy: '1.3.6.1.4.1.11591.15.1',
  primeField: '1.2.840.10045.1.1',
  binaryField: '1.2.840.10045.1.2',
  sha224: '2.16.840.1.101.3.4.2.4',
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',
  shake256: '2.16.840.1.101.3.4.2.12',
  shake256_512: '2.16.840.1.101.3.4.2.18',
  'ecdsa-with-SHA224': '1.2.840.10045.4.3.1',
  'ecdsa-with-SHA256': '1.2.840.10045.4.3.2',
  'ecdsa-with-SHA384': '1.2.840.10045.4.3.3',
  'ecdsa-with-SHA512': '1.2.840.10045.4.3.4',
  rsaEncryption: '1.2.840.113549.1.1.1',
  DSA: '1.2.840.10040.4.1',
  commonName: '2.5.4.3',
  localityName: '2.5.4.7',
  owner: '2.5.4.32',
  givenName: '2.5.4.42',
  objectIdentifier: '2.5.4.106',
  etsiQcCompliance: '0.4.0.1862.1.1',
  data: '1.2.840.113549.1.7.1',
  signedData: '1.2.840.113549.1.7.2',
  envelopedData: '1.2.840.113549.1.7.3',
  digestedData: '1.2.840.113549.1.7.5',
  encryptedData: '1.2.840.113549.1.7.6',
  authenticatedData: '1.2.840.113549.1.9.16.1.2',
  anyExtendedKeyUsage: '2.5.29.37.0',
  serverAuth: '1.3.6.1.5.5.7.3.1',
  clientAuth: '1.3.6.1.5.5.7.3.2',
  codeSigning: '1.3.6.1.5.5.7.3.3',
  emailProtection: '1.3.6.1.5.5.7.3.4',
  timeStamping: '1.3.6.1.5.5.7.3.8',
  OCSPSigning: '1.3.6.1.5.5.7.3.9',
  subjectKeyIdentifier: '2.5.29.14',
  keyUsage: '2.5.29.15',
  privateKeyUsagePeriod: '2.5.29.16',
  subjectAltName: '2.5.29.17',
  issuerAltName: '2.5.29.18',
  basicConstraints: '2.5.29.19',
  subjectDirectoryAttributes: '2.5.29.9',
  nameConstraints: '2.5.29.30',
  crlDistributionPoints: '2.5.29.31',
  certificatePolicies: '2.5.29.32',
  anyPolicy: '2.5.29.32.0',
  policyMappings: '2.5.29.33',
  authorityKeyIdentifier: '2.5.29.35',
  policyConstraints: '2.5.29.36',
  freshestCRL: '2.5.29.46',
  inhibitAnyPolicy: '2.5.29.54',
  extendedKeyUsage: '2.5.29.37',
  certificateIssuer: '2.5.29.29',
  issuingDistributionPoint: '2.5.29.28',
  authorityInfoAccess: '1.3.6.1.5.5.7.1.1',
  qcStatements: '1.3.6.1.5.5.7.1.3',
  subjectInfoAccess: '1.3.6.1.5.5.7.1.11',
  proxyCertInfo: '1.3.6.1.5.5.7.1.14',
  tlsFeature: '1.3.6.1.5.5.7.1.24',
  sctList: '1.3.6.1.4.1.11129.2.4.2',
  msCertType: '1.3.6.1.4.1.311.21.1',
  idQtCps: '1.3.6.1.5.5.7.2.1',
  idQtUnotice: '1.3.6.1.5.5.7.2.2',
  proxyPolicyInheritAll: '1.3.6.1.5.5.7.21.1',
  proxyPolicyIndependent: '1.3.6.1.5.5.7.21.2',
  attrContentType: '1.2.840.113549.1.9.3',
  attrMessageDigest: '1.2.840.113549.1.9.4',
  attrSigningTime: '1.2.840.113549.1.9.5',
  attrCountersignature: '1.2.840.113549.1.9.6',
  attrSMIMECapabilities: '1.2.840.113549.1.9.15',
  'aes256-cbc': '2.16.840.1.101.3.4.1.42',
  'aes192-cbc': '2.16.840.1.101.3.4.1.22',
  'aes128-cbc': '2.16.840.1.101.3.4.1.2',
  'aes256-gcm': '2.16.840.1.101.3.4.1.46',
  'aes192-gcm': '2.16.840.1.101.3.4.1.26',
  'aes128-gcm': '2.16.840.1.101.3.4.1.6',
  'aes256-cfb': '2.16.840.1.101.3.4.1.44',
  'aes192-cfb': '2.16.840.1.101.3.4.1.24',
  'aes128-cfb': '2.16.840.1.101.3.4.1.4',
  'aes256-kw': '2.16.840.1.101.3.4.1.45',
  'aes192-kw': '2.16.840.1.101.3.4.1.25',
  'aes128-kw': '2.16.840.1.101.3.4.1.5',
  'des-ede3-cbc': '1.2.840.113549.3.7',
  'rc2-cbc': '1.2.840.113549.3.2',
  'des-cbc': '1.3.14.3.2.7',
  dhSinglePass_stdDH_sha1kdf_scheme: '1.3.133.16.840.63.0.2',
  dhSinglePass_cofactorDH_sha1kdf_scheme: '1.3.133.16.840.63.0.3',
  mqvSinglePass_sha1kdf_scheme: '1.3.133.16.840.63.0.16',
  rsaKem: '1.2.840.113549.1.9.16.3.14',
} as const);
const OIDS_INVERT = /* @__PURE__ */ (() =>
  deepFreeze(Object.fromEntries(Object.entries(OIDS).map(([k, v]) => [v, k]))))();
/**
 * ASN.1 OID coder that decodes known OIDs to names and preserves unknown OIDs as raw dotted text.
 * @example
 * Encode a named OID and decode the same bytes back to its known name.
 * ```ts
 * import { oidName } from 'micro-key-producer/asn1.js';
 * oidName.decode(oidName.encode('signedData'));
 * ```
 */
export const oidName: P.CoderType<string> = /* @__PURE__ */ deepFreeze(
  /* @__PURE__ */ P.apply(oid, {
    encode: (v: TArg<string>): string => OIDS_INVERT[v as string] || (v as string),
    decode: (v: TArg<string>): string => {
      const s = v as string;
      const id = OIDS[s as keyof typeof OIDS];
      if (id) return id;
      if (/^[0-9]+(?:\.[0-9]+)+$/.test(s)) return s;
      throw new Error(`unknown oid ${v}`);
    },
  })
);


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
const DERLength: P.CoderType<number> = /* @__PURE__ */ (() => {
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
type TLVNode = {
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
type ASN1AlgorithmIdentifier = {
  /** Algorithm object identifier. */
  algorithm: string;
  /** Optional raw AlgorithmIdentifier parameters TLV. */
  params?: TLVNode;
};
/** Generic ASN.1 Attribute shell with raw SET OF values. */
type ASN1Attribute = {
  /** Attribute object identifier. */
  oid: string;
  /** Raw ASN.1 attribute values. */
  values: Uint8Array[];
};
/** Generic ASN.1 Time choice. */
type ASN1Time = { TAG: 'utc'; data: string } | { TAG: 'generalized'; data: string };
/** Generic ASN.1 string value choice used by schema-less TLV helpers. */
type ASN1StringValue =
  | { TAG: 'utf8'; data: string }
  | { TAG: 'printable'; data: string }
  | { TAG: 'teletex'; data: string }
  | { TAG: 'ia5'; data: string }
  | { TAG: 'bmp'; data: string }
  | { TAG: 'universal'; data: string }
  | { TAG: 'visible'; data: string }
  | { TAG: 'numeric'; data: string };
/** Generic parsed ASN.1 string-or-raw value. */
type ASN1StringOrRaw = ASN1StringValue | { TAG: 'raw'; data: TLVNode };
/** Generic best-effort parsed ASN.1 ANY value. */
type ASN1AnyValue =
  | { TAG: 'text'; data: ASN1StringValue }
  | { TAG: 'oid'; data: string }
  | { TAG: 'int'; data: bigint }
  | { TAG: 'bool'; data: boolean }
  | { TAG: 'time'; data: ASN1Time }
  | { TAG: 'octet'; data: Uint8Array }
  | { TAG: 'raw'; data: TLVNode };
type ASN1SetOpts = { ber?: boolean };
const _ASN1 = /* @__PURE__ */ (() => {
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
  const tlv = /* @__PURE__ */ P.struct({ tag, data: P.bytes(DERLength) });
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
    const rawTlv = /* @__PURE__ */ P.struct({ tag: P.U8, value: P.bytes(DERLength) });
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
      const len = DERLength.decode(raw.subarray(pos), { allowUnreadBytes: true });
      const valueAt = pos + DERLength.encode(len).length;
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
      return concatBytes(tag, DERLength.encode(value.length), value) as TRet<Uint8Array>;
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
type ASN1TagCoder<T> = P.CoderType<T> & {
  tagByte: number;
  tagBytes: number[];
  constructed: number;
  inner: P.CoderType<T>;
};
type ASN1MaybeCoder<T> = P.CoderType<T> &
  Partial<Pick<ASN1TagCoder<T>, 'tagByte' | 'tagBytes' | 'constructed' | 'inner'>>;
type ASN1ChoiceRecord<T extends Record<string, unknown>> = {
  [K in keyof T]: ASN1MaybeCoder<T[K]>;
};
type ASN1ChoiceResult<T extends Record<string, unknown>> = {
  [K in keyof T]: { TAG: K; data: T[K] };
}[keyof T];
type ASN1Value<C> = C extends ASN1MaybeCoder<infer T> ? T : never;
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
  validate: <C extends object>(inner: C, fn: (value: ASN1Value<C>) => ASN1Value<C>) => C;
};
/** Generic ASN.1 building blocks. */
export const ASN1: TRet<ASN1Pub> = /* @__PURE__ */ deepFreeze(
  _ASN1 as unknown as ASN1Pub
) as unknown as TRet<ASN1Pub>;
type BERPub = {
  view: (src: TArg<Uint8Array>, opts?: BEROpts) => TRet<BERDoc>;
  decode: (
    src: TArg<Uint8Array>,
    opts?: { allowBER?: boolean }
  ) => TRet<{ nodes: BerNode[]; der: Uint8Array }>;
  encode: (nodes: BerNode[], der: TArg<Uint8Array>) => TRet<Uint8Array>;
  normalize: (src: TArg<Uint8Array>, opts?: { allowBER?: boolean }) => TRet<Uint8Array>;
};
type DERPub = {
  /** DER length coder with minimal-length validation. */
  length: P.CoderType<number>;
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
type BEROpts = { allowBER?: boolean };
const berRaw = (n: unknown): TRet<BerRawNode> => n as TRet<BerRawNode>;
// RFC 5958 receivers must accept BER input, so this helper keeps enough
// BER metadata to re-emit indefinite/constructed forms while also exposing
// a DER-normalized byte view for the higher-level converters.
const _BER = {
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
        const n = _BER.parse(src, pos, allowBER);
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
              der: concatBytes(...[outTag, DERLength.encode(1), Uint8Array.from([0])]),
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
            der: concatBytes(...[outTag, DERLength.encode(value.length), value]),
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
          der: concatBytes(...[outTag, DERLength.encode(value.length), value]),
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
        der: concatBytes(...[tg.bytes, DERLength.encode(constructed.length), constructed]),
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
        der: concatBytes(...[tg.bytes, DERLength.encode(valueRaw.length), valueRaw]),
        value: valueRaw,
        pos,
        cls: tg.cls,
        tagNum: tg.tagNum,
        cons: tg.cons,
      });
    const nodes: BerRawNode[] = [];
    let at = 0;
    while (at < valueRaw.length) {
      const n = _BER.parse(valueRaw, at, allowBER);
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
        der: concatBytes(...[outTag, DERLength.encode(value.length), value]),
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
      der: concatBytes(...[tg.bytes, DERLength.encode(constructed.length), constructed]),
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
    children: n.children?.map(_BER.meta),
    cls: n.cls,
    tagNum: n.tagNum,
    cons: n.cons,
  }),
  buildRaw: (cls: number, tagNum: number, value: TArg<Uint8Array>): TRet<BerRawNode> =>
    berRaw({
      tag: _BER.tag(cls, false, tagNum),
      len: DERLength.encode(value.length),
      indefinite: false,
      der: concatBytes(...[_BER.tag(cls, false, tagNum), DERLength.encode(value.length), value]),
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
    const tag = _BER.tag(meta.cls, meta.cons, meta.tagNum);
    if (!meta.cons) {
      const v = n.value;
      if (meta.indefinite) throw new Error('BER primitive cannot use indefinite length');
      return concatBytes(...[tag, _BER.len(v.length, meta.lenBytes), v]) as TRet<Uint8Array>;
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
        out.push(_BER.buildRaw(n.cls, n.tagNum, v));
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
        out.push(_BER.buildRaw(n.cls, n.tagNum, v));
        at += dlen;
      }
      if (at !== bits.length) throw new Error('BER child shape mismatch');
      srcChildren = out;
    }
    if (!srcChildren || srcChildren.length !== mm.length)
      throw new Error('BER child shape mismatch');
    const body = concatBytes(...srcChildren.map((c, i) => _BER.node(c, mm[i])));
    if (meta.indefinite)
      return concatBytes(
        ...[tag, Uint8Array.from([0x80]), body, Uint8Array.from([0x00, 0x00])]
      ) as TRet<Uint8Array>;
    return concatBytes(...[tag, _BER.len(body.length, meta.lenBytes), body]) as TRet<Uint8Array>;
  },
  decode: (src: TArg<Uint8Array>, opts: { allowBER?: boolean } = {}): TRet<BERDoc> => {
    const allowBER = !!opts.allowBER;
    const nodes: BerNode[] = [];
    const der: Uint8Array[] = [];
    let pos = 0;
    while (pos < src.length) {
      const n = _BER.parse(src, pos, allowBER);
      nodes.push(_BER.meta(n));
      der.push(n.der);
      pos = n.pos;
    }
    return { nodes, der: concatBytes(...der) } as TRet<BERDoc>;
  },
  encode: (nodes: BerNode[], der: TArg<Uint8Array>): TRet<Uint8Array> => {
    const rawNodes: BerRawNode[] = [];
    let pos = 0;
    while (pos < der.length) {
      const n = _BER.parse(der, pos, false);
      rawNodes.push(n);
      pos = n.pos;
    }
    if (rawNodes.length !== nodes.length) throw new Error('BER root node count mismatch');
    return concatBytes(...rawNodes.map((n, i) => _BER.node(n, nodes[i]))) as TRet<Uint8Array>;
  },
  normalize: (src: TArg<Uint8Array>, opts: { allowBER?: boolean } = {}): TRet<Uint8Array> => {
    const allowBER = !!opts.allowBER;
    const out: Uint8Array[] = [];
    let pos = 0;
    while (pos < src.length) {
      const n = _BER.parse(src, pos, allowBER);
      out.push(n.der);
      pos = n.pos;
    }
    return concatBytes(...out) as TRet<Uint8Array>;
  },
} as const;
/** BER decoder/encoder used to normalize supported BER input to DER. */
export const BER: TRet<BERPub> = /* @__PURE__ */ deepFreeze({
  view: (src: TArg<Uint8Array>, opts: BEROpts = {}): TRet<BERDoc> =>
    _BER.decode(src, { allowBER: !!opts.allowBER }) as TRet<BERDoc>,
  decode: _BER.decode,
  encode: _BER.encode,
  normalize: _BER.normalize,
}) as unknown as TRet<BERPub>;
/** DER helpers. */
export const DER: TRet<DERPub> = /* @__PURE__ */ deepFreeze({
  length: DERLength,
}) as unknown as TRet<DERPub>;

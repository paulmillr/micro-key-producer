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
import type { CurvePoint, CurvePointCons, P_F } from '@noble/curves/abstract/curve.js';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { ed448, x448 } from '@noble/curves/ed448.js';
import { p256, p384, p521 } from '@noble/curves/nist.js';
import { equalBytes } from '@noble/curves/utils.js';
import { type TArg, type TRet } from '@noble/hashes/utils.js';
import { base64urlnopad, utils as baseUtils } from '@scure/base';
import * as P from 'micro-packed';
import { ASN1 } from './asn1.ts';
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
const RawTLV = ASN1.any;
// RFC 5480 https://www.rfc-editor.org/rfc/rfc5480
// RFC 5915 https://www.rfc-editor.org/rfc/rfc5915
// RFC 5958 https://www.rfc-editor.org/rfc/rfc5958
// RFC 8410 https://www.rfc-editor.org/rfc/rfc8410
// Keep explicit-domain support in the DER key schemas for low-level interop/vector coverage;
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

// DER key schemas preserve the full ECParameters choice for low-level parsing/roundtrips,
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
export const KeyAlgorithm: P.CoderType<Algo> = /* @__PURE__ */ (() =>
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
  }))() as unknown as P.CoderType<Algo>;
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
// attribute OIDs are open-ended, so the DER key schemas preserve opaque per-attribute
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
export const PKCS8SecretKey: P.CoderType<PKCS8Secret> = /* @__PURE__ */ (() =>
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
export const PKCS8: P.CoderType<PKCS8Key> = /* @__PURE__ */ (() =>
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
export const SPKI: P.CoderType<SPKIKey> = /* @__PURE__ */ (() =>
  ASN1.sequence({
    algorithm: KeyAlgorithm,
    publicKey: ASN1.BitString,
  }))() as unknown as P.CoderType<SPKIKey>;

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
export const RSAPrivateKey: P.CoderType<RSAKey> = P.apply(RSAPrivateKeyInner, {
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

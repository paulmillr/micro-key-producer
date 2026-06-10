/*! micro-key-producer - MIT License (c) 2024 Paul Miller (paulmillr.com) */
/**
 * x509 certificates. Conforms to parts of RFC 3820, RFC 5280, RFC 5652,
 * RFC 5754, RFC 5912, RFC 7633.
 * @module
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { ed448 } from '@noble/curves/ed448.js';
import { brainpoolP256r1, brainpoolP384r1, brainpoolP512r1 } from '@noble/curves/misc.js';
import { p256, p384, p521 } from '@noble/curves/nist.js';
import { equalBytes } from '@noble/curves/utils.js';
import { sha224, sha256, sha384, sha512 } from '@noble/hashes/sha2.js';
import { shake256 } from '@noble/hashes/sha3.js';
import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  isBytes,
  type TArg,
  type TRet,
} from '@noble/hashes/utils.js';
import { base64, hex } from '@scure/base';
import * as P from 'micro-packed';
import { ASN1, BER, oidName } from './asn1.ts';
import {
  PKCS8,
  RSAPrivateKey as DERRSAPrivateKey,
  SPKI,
  type ECParams as DERECParams,
  type PKCS8Key as DERPKCS8Key,
  type SPKIKey as DERSPKIKey,
} from './convert.ts';
import { astring, deepFreeze } from './utils.ts';

const _0n = /* @__PURE__ */ BigInt(0);
const _1n = /* @__PURE__ */ BigInt(1);
const _2n = /* @__PURE__ */ BigInt(2);
const _3n = /* @__PURE__ */ BigInt(3);
const _4n = /* @__PURE__ */ BigInt(4);
const _5n = /* @__PURE__ */ BigInt(5);
const SHAKE256_512_BITS = /* @__PURE__ */ BigInt(512);
const U16_MAX = /* @__PURE__ */ BigInt(65535);
const ASN1_NULL = /* @__PURE__ */ Uint8Array.from([0x05, 0x00]);
const ASN1_NULL_TLV = /* @__PURE__ */ ASN1.TLVNode.decode(ASN1_NULL);

/** Supported certificate/key curves. */
export type Curve =
  | 'P-256'
  | 'P-384'
  | 'P-521'
  | 'brainpoolP256r1'
  | 'brainpoolP384r1'
  | 'brainpoolP512r1';
/** Supported signing or key-agreement curve name. */
export type CertCurve = Curve | string;
/** Parsed PEM block with decoded DER bytes. */
export type PemBlock = {
  /** PEM block tag between `BEGIN` and `END`. */
  tag: string;
  /** Base64 payload exactly as it appeared in the PEM block. */
  b64: string;
  /** Decoded DER bytes for the PEM payload. */
  der: Uint8Array;
};
/** Parsed PKCS#8 attribute entry. */
export type Pkcs8Attr = {
  /** Attribute OID. */
  oid: string;
  /** Raw ASN.1 values carried by the attribute. */
  values: Uint8Array[];
};
type RSAPrivateKey = P.UnwrapCoder<typeof DERRSAPrivateKey>;
type StrictBytes = P.UnwrapCoder<typeof ASN1.any>;
type ASN1StringOrRaw = P.UnwrapCoder<typeof ASN1.StringOrRaw>;
type BERDoc = ReturnType<typeof BER.decode>;
type BEROpts = { allowBER?: boolean };
type TLVNode = P.UnwrapCoder<typeof ASN1.TLVNode>;
/** Decoded X.509 certificate. */
export type Cert = P.UnwrapCoder<typeof CERTUtils.Certificate>;
type KeyBase = {
  pem: string;
  der: Uint8Array;
  attributes?: Pkcs8Attr[];
};
/** Parsed private-key PEM/DER bundle. */
export type PrivateKey = KeyBase & { key: DERPKCS8Key; rsa?: RSAPrivateKey };
/** Leaf certificate, private key, and optional chain used for signing. */
export type SigningPem = {
  /** Leaf certificate used as the signer. */
  leaf: Cert;
  /** Private key matching the leaf certificate. */
  key: PrivateKey;
  /** Optional issuer chain sent alongside the leaf. */
  chain: Cert[];
};
/** CMS verification options. */
export type CmsVerifyOpts = {
  /** Validation time in UNIX milliseconds. */
  time?: number;
  /** Allow BER normalization before decoding. */
  allowBER?: boolean;
  /**
   * Whether to verify CMS and certificate signatures for supported algorithms.
   * When `false`, structure, path, and attribute validation still runs.
   */
  checkSignatures?: boolean;
  /** Intended verification purpose such as S/MIME or code signing. */
  purpose?: 'any' | 'smime' | 'codeSigning';
  /** Optional trust anchors or intermediates used for path building. */
  chain?: (string | Uint8Array | Cert)[];
};
/** Result of CMS verification. */
export type CmsVerify = {
  /** Signature algorithm OID from the CMS SignerInfo. */
  signatureOid: string;
  /** Parsed signer certificate. */
  signer: Cert;
  /** Whether signed attributes were present and validated. */
  signedAttrs: boolean;
  /** Parsed certificate path from signer toward issuer or root candidates. */
  chain: Cert[];
};
/** Detached CMS payload and signature pair. */
export type CmsDetached = {
  /** Original detached content bytes. */
  content: Uint8Array;
  /** Detached CMS SignedData blob. */
  signature: Uint8Array;
  /** Certificates bundled with the signature. */
  certs: Cert[];
};
/** CMS signing options. */
export type CmsSignOpts = BEROpts & {
  // Optional signing-time timestamp in UNIX milliseconds.
  // RFC 5652 section 11.3: signing-time is encoded as Time in signedAttrs.
  createdTs?: number;
  extraEntropy?: boolean | Uint8Array;
  // Optional signedAttrs S/MIME Capabilities values (attribute OID 1.2.840.113549.1.9.15).
  // Default behavior omits this attribute (OpenSSL `-nosmimecap` style);
  // pass values here to include it.
  // Values can be known capability names or raw capability OIDs.
  smimeCapabilities?: string[];
  // Optional override for signedAttrs messageDigest value (attribute OID 1.2.840.113549.1.9.4).
  messageDigest?: Uint8Array;
  // Optional override for SignerInfo.digestAlgorithm OID.
  digestAlgorithm?: string;
  // Optional digest AlgorithmIdentifier params encoding mode.
  // RFC 5754 allows SHA-2 params as absent or NULL; use 'null' for legacy byte parity.
  digestAlgorithmParams?: 'absent' | 'null';
  // Optional override for SignerInfo.signatureAlgorithm OID.
  signatureAlgorithm?: string;
};
/** Decoded certificate extension data. */
export type CertExt = {
  /** Extension OID. */
  oid: string;
  /** Whether the extension is marked critical. */
  critical: boolean;
  /** Subject Key Identifier extension. */
  ski?: Uint8Array;
  /** Basic Constraints extension. */
  basic?: { ca?: boolean; pathLen?: bigint };
  /** Key Usage extension bit string. */
  keyUsage?: { unused: number; bytes: Uint8Array };
  /** Extended Key Usage extension. */
  eku?: { list: string[] };
  /** Subject Alternative Name extension. */
  san?: { list: CertGeneralName[] };
  /** Authority Key Identifier extension. */
  aki?: {
    keyIdentifier?: Uint8Array;
    authorityCertIssuer?: { list: CertGeneralName[] };
    authorityCertSerialNumber?: bigint;
  };
  /** Authority Information Access extension. */
  aia?: { list: { method: string; location: CertGeneralName }[] };
  /** Proxy Certificate Information extension. */
  proxyCertInfo?: { pathLen?: bigint; policy: { language: string; policy?: string } };
  /** TLS Feature extension. */
  tlsFeature?: { list: bigint[] };
  /** Signed Certificate Timestamps extension. */
  sct?: {
    version: number;
    logID: Uint8Array;
    timestamp: bigint;
    extensions: string;
    hash: number;
    signatureAlgorithm: number;
    signature: Uint8Array;
  }[];
  /** CRL Distribution Points extension. */
  crlDistributionPoints?: {
    list: {
      distributionPoint?: CertDistributionPointName;
      reasons?: { unused: number; bytes: Uint8Array };
      cRLIssuer?: { list: CertGeneralName[] };
    }[];
  };
  /** Certificate Policies extension. */
  policies?: {
    list: {
      policy: string;
      qualifiers?: { list: CertPolicyQualifier[] };
    }[];
  };
  /** Name Constraints extension. */
  nameConstraints?: {
    permitted?: { list: CertGeneralSubtree[] };
    excluded?: { list: CertGeneralSubtree[] };
  };
  /** Subject Directory Attributes extension. */
  subjectDirectoryAttributes?: { list: { type: string; values: CertAny[] }[] };
  /** Private Key Usage Period extension. */
  privateKeyUsagePeriod?: { notBefore?: string; notAfter?: string };
  /** Issuer Alternative Name extension. */
  issuerAltName?: { list: CertGeneralName[] };
  /** Issuing Distribution Point extension. */
  issuingDistributionPoint?: {
    distributionPoint?: CertDistributionPointName;
    onlyContainsUserCerts?: boolean;
    onlyContainsCACerts?: boolean;
    onlySomeReasons?: { unused: number; bytes: Uint8Array };
    indirectCRL?: boolean;
    onlyContainsAttributeCerts?: boolean;
  };
  /** Certificate Issuer extension. */
  certificateIssuer?: { list: CertGeneralName[] };
  /** Policy Mappings extension. */
  policyMappings?: { list: { issuerDomainPolicy: string; subjectDomainPolicy: string }[] };
  /** Freshest CRL extension. */
  freshestCRL?: {
    list: {
      distributionPoint?: CertDistributionPointName;
      reasons?: { unused: number; bytes: Uint8Array };
      cRLIssuer?: { list: CertGeneralName[] };
    }[];
  };
  /** Policy Constraints extension. */
  policyConstraints?: { requireExplicitPolicy?: bigint; inhibitPolicyMapping?: bigint };
  /** Inhibit Any Policy extension. */
  inhibitAnyPolicy?: bigint;
  /** QC Statements extension. */
  qcStatements?: { list: { statementId: string; statementInfo: CertAny | undefined }[] };
  /** Subject Information Access extension. */
  subjectInfoAccess?: { list: { method: string; location: CertGeneralName }[] };
  /** Microsoft certificate type extension. */
  msCertType?: CertAny;
};
/** Parsed GeneralName value. */
export type CertGeneralName =
  | { TAG: 'otherName'; data: { type: string; value: Uint8Array } }
  | { TAG: 'rfc822Name'; data: string }
  | { TAG: 'dNSName'; data: string }
  | { TAG: 'x400Address'; data: Uint8Array }
  | { TAG: 'directoryName'; data: NameCodec }
  | { TAG: 'ediPartyName'; data: Uint8Array }
  | { TAG: 'uniformResourceIdentifier'; data: string }
  | { TAG: 'iPAddress'; data: string }
  | { TAG: 'registeredID'; data: string };
/** Parsed CRL distribution-point name. */
export type CertDistributionPointName =
  | { TAG: 'fullName'; data: { list: CertGeneralName[] } }
  | { TAG: 'nameRelativeToCRLIssuer'; data: Array<{ oid: string; value: ASN1StringOrRaw }> };
/** Parsed reason flags from CRL-related extensions. */
export type CertReasonFlags = {
  /** End-entity private key was compromised. */
  keyCompromise: boolean;
  /** CA private key was compromised. */
  cACompromise: boolean;
  /** Subject affiliation changed. */
  affiliationChanged: boolean;
  /** Certificate was superseded. */
  superseded: boolean;
  /** Subject ceased operation. */
  cessationOfOperation: boolean;
  /** Certificate was placed on hold. */
  certificateHold: boolean;
  /** Privileges were withdrawn. */
  privilegeWithdrawn: boolean;
  /** Attribute authority key was compromised. */
  aACompromise: boolean;
};
/** Parsed GeneralSubtree value. */
export type CertGeneralSubtree = {
  /** Base GeneralName covered by the subtree. */
  base: CertGeneralName;
  /** Minimum subtree depth, when explicitly present. */
  minimum?: bigint;
  /** Maximum subtree depth, when explicitly present. */
  maximum?: bigint;
};
/** Parsed certificate-policy qualifier. */
export type CertPolicyQualifier =
  | { TAG: 'cps'; data: string }
  | {
      TAG: 'userNotice';
      data: {
        noticeRef?: { organization: CertText; numbers: (number | bigint)[] };
        explicitText?: CertText;
      };
    }
  | { TAG: 'unknown'; data: { oid: string; value: TLVNode } };
/** Decoded text value from certificate fields. */
export type CertText = {
  /** Underlying ASN.1 string tag used by the source field. */
  tag: 'utf8' | 'ia5' | 'visible' | 'bmp';
  /** Decoded text content. */
  text: string;
};
/** Best-effort decoded arbitrary ASN.1 value. */
// RFC 5280 section 4.1.2.4 AttributeValue is ANY; non-string TLVs use the
// raw arm from the shared ASN.1 ANY codec instead of flowing through the
// DirectoryString text codec.
export type CertAny = P.UnwrapCoder<typeof ASN1.AnyValue>;
// RFC 7468 section 2 and section 3 ABNF allow single `-`/SP separators
// inside labels but not at either end; the END label must match like OpenSSL.
const pemRE =
  /-----BEGIN ([\x21-\x2c\x2e-\x7e](?:[- ]?[\x21-\x2c\x2e-\x7e])*)-----([\s\S]*?)-----END \1-----/g;
// The X.509 hash tables below are derived from hash-function metadata, so
// hashes without a DER OID are rejected here instead of producing incomplete
// OID maps.
const hashOid = (h: TArg<{ oid?: Uint8Array }>) => {
  if (!h.oid) throw new Error('hash.oid is missing');
  return ASN1.OID.decode(h.oid);
};
/**
 * Extracts all PEM blocks from a text blob.
 * @param text - Text containing one or more PEM blocks.
 * @returns Parsed PEM blocks with decoded DER bytes.
 * @example
 * Extract all PEM blocks from a text blob.
 * ```ts
 * import { pemBlocks } from 'micro-key-producer/x509.js';
 * pemBlocks(`-----BEGIN DATA-----
 * AA==
 * -----END DATA-----`);
 * ```
 */
export const pemBlocks = (text: string): TRet<PemBlock[]> => {
  text = astring(text, 'text');
  const out: PemBlock[] = [];
  // PEM files may contain multiple textual encoding instances; this helper
  // preserves source order and only normalizes whitespace inside each base64
  // body before strict decode.
  for (const m of text.matchAll(pemRE)) {
    const tag = m[1].trim();
    const b64 = m[2].trim();
    if (!tag || !b64) continue;
    out.push({ tag, b64, der: base64.decode(b64.replace(/\s+/g, '')) });
  }
  return out as TRet<PemBlock[]>;
};

const onePem = (text: string, tag?: string) => {
  const all = pemBlocks(text);
  if (!all.length) throw new Error('no PEM blocks found');
  // This helper is intentionally a selector: it returns the first PEM block, or
  // the first block with a matching tag, and leaves duplicate/ambiguity handling
  // to callers that need full bundle awareness.
  if (!tag) return all[0];
  const hit = all.find((i) => i.tag === tag);
  if (!hit) throw new Error(`no PEM block with tag=${tag}`);
  return hit;
};

const ecParamCurve = (d: DERECParams): CertCurve => {
  // PKIX EC parameters are namedCurve-only, but private keys from OpenSSL may
  // carry explicit parameters equivalent to a supported named curve.
  if (d.TAG === 'namedCurve') {
    const name = d.data;
    return name && name in CMS_ALG && 'ec' in CMS_ALG[name as AlgKey] ? name : d.data;
  }
  if (d.TAG === 'implicitCurve') return 'implicitCurve';
  const data = d.data;
  if (!data || typeof data !== 'object') return 'specifiedCurve';
  const raw = data as Record<string, unknown>;
  const fieldId = raw.fieldId as Record<string, unknown> | undefined;
  const info = fieldId?.info as Record<string, unknown> | undefined;
  const curve = raw.curve as Record<string, unknown> | undefined;
  if (info?.TAG !== 'primeField' || typeof info.data !== 'bigint') return 'specifiedCurve';
  if (!isBytes(curve?.a) || !isBytes(curve?.b)) return 'specifiedCurve';
  if (!isBytes(raw.base) || typeof raw.order !== 'bigint') return 'specifiedCurve';
  if (raw.cofactor !== undefined && typeof raw.cofactor !== 'bigint') return 'specifiedCurve';
  // OpenSSL can serialize a standard EC key with explicit domain parameters while the
  // matching cert/SPKI keeps the named-curve OID, so normalize equivalent parameters here.
  for (const name in CMS_ALG) {
    const alg = CMS_ALG[name as AlgKey];
    if (!('ec' in alg)) continue;
    const curveName = name as Curve;
    const known = alg.ec.Point.CURVE();
    if (info.data !== known.p) continue;
    if (
      BigInt(`0x${bytesToHex(curve.a) || '0'}`) !== known.a ||
      BigInt(`0x${bytesToHex(curve.b) || '0'}`) !== known.b
    )
      continue;
    if (raw.order !== known.n) continue;
    if (raw.cofactor !== undefined && raw.cofactor !== known.h) continue;
    const base = alg.ec.Point.BASE;
    if (!equalBytes(raw.base, base.toBytes(false)) && !equalBytes(raw.base, base.toBytes(true)))
      continue;
    return curveName;
  }
  return 'specifiedCurve';
};
const spkiCurve = (k: TArg<DERSPKIKey>): CertCurve => {
  // SubjectPublicKeyInfo callers use this as the EC-only unwrap layer; non-EC
  // SPKI algorithms fail here, while forbidden EC parameter variants still
  // propagate as sentinel strings from `ecParamCurve()`.
  if (k.algorithm.info.TAG !== 'EC')
    throw new Error(`expected EC SPKI key, got ${k.algorithm.info.TAG}`);
  return ecParamCurve(k.algorithm.info.data);
};
type EdKind = 'Ed25519' | 'Ed448';
type HashAlg = ((m: TArg<Uint8Array>) => TRet<Uint8Array>) & { oid?: Uint8Array };
type EcSignOpts = {
  prehash?: boolean;
  format?: 'der';
  lowS?: boolean;
  extraEntropy?: boolean | Uint8Array;
};
type EcVerifyOpts = { prehash?: boolean; format?: 'der'; lowS?: boolean };
// RFC 8419 section 3.1: CMS Ed448 with signedAttrs uses SHAKE256 with
// a 512-bit output, identified by id-shake256-len with INTEGER 512 params.
// OpenSSL 3.5.4 only emits id-shake256 when forced with `-md shake256` and
// cannot verify id-shake256-len, but this compact path follows RFC 8419 section 3.1.
const shake256_512: HashAlg = /* @__PURE__ */ (() =>
  // Keep the Ed448 CMS hash object lazy so pemBlocks/X509-only treeshake
  // bundles do not retain the id-shake256-len OID encoder call.
  Object.assign(
    (m: TArg<Uint8Array>): TRet<Uint8Array> => shake256(m, { dkLen: 64 }) as TRet<Uint8Array>,
    {
      oid: ASN1.OID.encode('shake256_512'),
    }
  ))();
type EcAlg = {
  ec: {
    sign: (m: Uint8Array, sk: Uint8Array, o?: EcSignOpts) => Uint8Array;
    verify: (sig: Uint8Array, m: Uint8Array, pk: Uint8Array, o?: EcVerifyOpts) => boolean;
    getPublicKey: (sk: Uint8Array, compressed?: boolean) => Uint8Array;
    lengths: { signature?: number };
    Point: {
      CURVE: () => { p: bigint; n: bigint; h: bigint; a: bigint; b: bigint };
      BASE: { toBytes: (compressed?: boolean) => Uint8Array };
    };
  };
  sigOid: string;
  hash: HashAlg;
  digestParams?: () => TLVNode;
};
type EdAlg = {
  ed: {
    sign: (m: Uint8Array, sk: Uint8Array) => Uint8Array;
    verify: (sig: Uint8Array, m: Uint8Array, pk: Uint8Array) => boolean;
    getPublicKey: (sk: Uint8Array) => Uint8Array;
  };
  sigOid: string;
  hash: HashAlg;
  digestParams?: () => TLVNode;
};
type CmsAlg = EcAlg | EdAlg;
const ED448_DIGEST_PARAMS = /* @__PURE__ */ (() =>
  ASN1.TLVNode.decode(ASN1.Integer.encode(SHAKE256_512_BITS)))();
// These rows drive both the signatureAlgorithm OID and the default CMS
// digestAlgorithm/messageDigest conventions during compact signing, so
// Ed25519 and Ed448 must follow RFC 8419's per-curve digest rules.
const CMS_ALG = {
  'P-256': { ec: p256, sigOid: 'ecdsa-with-SHA256', hash: sha256 },
  'P-384': { ec: p384, sigOid: 'ecdsa-with-SHA384', hash: sha384 },
  'P-521': { ec: p521, sigOid: 'ecdsa-with-SHA512', hash: sha512 },
  brainpoolP256r1: {
    ec: brainpoolP256r1,
    sigOid: 'ecdsa-with-SHA256',
    hash: sha256,
  },
  brainpoolP384r1: {
    ec: brainpoolP384r1,
    sigOid: 'ecdsa-with-SHA384',
    hash: sha384,
  },
  brainpoolP512r1: {
    ec: brainpoolP512r1,
    sigOid: 'ecdsa-with-SHA512',
    hash: sha512,
  },
  Ed25519: {
    ed: ed25519,
    sigOid: 'Ed25519',
    hash: sha512,
  },
  Ed448: {
    ed: ed448,
    sigOid: 'Ed448',
    hash: shake256_512,
    digestParams: () => ED448_DIGEST_PARAMS,
  },
} as const satisfies Record<Curve, EcAlg> & Record<EdKind, EdAlg>;
type AlgKey = Curve | EdKind;
// RFC 5754 section 2: this absent-or-NULL parameters rule applies to SHA-2
// AlgorithmIdentifiers specifically, so this set is intentionally SHA2-only
// (not a generic all-hashes OID table).
const SHA2_DIGESTS = /* @__PURE__ */ new Set(['sha224', 'sha256', 'sha384', 'sha512']);
const digestParamsEqual = (
  a: AlgorithmIdentifierCodec['params'],
  b: AlgorithmIdentifierCodec['params']
): boolean => {
  if (!a || !b) return !a && !b;
  return equalBytes(ASN1.TLVNode.encode(a), ASN1.TLVNode.encode(b));
};
// This only models RFC 5754's SHA-2 absent-vs-NULL compatibility rule;
// stricter digestAlgorithm parameter requirements still need caller checks.
const digestAlgParamsOk = (a: AlgorithmIdentifierCodec): boolean => {
  const id = oidName.decode(oidName.encode(a.algorithm));
  if (!SHA2_DIGESTS.has(id)) return true;
  const p = a.params ? ASN1.TLVNode.encode(a.params) : undefined;
  return !p || equalBytes(p, ASN1_NULL);
};
const digestAlgEqual = (a: AlgorithmIdentifierCodec, b: AlgorithmIdentifierCodec): boolean => {
  const aOid = oidName.decode(oidName.encode(a.algorithm));
  const bOid = oidName.decode(oidName.encode(b.algorithm));
  if (aOid !== bOid) return false;
  // RFC 5754 SHA-2 absent-vs-NULL equivalence is only a matching rule;
  // profile-specific digestAlgorithms validation still needs caller checks.
  if (!digestAlgParamsOk(a) || !digestAlgParamsOk(b)) return false;
  const aParams = a.params ? ASN1.TLVNode.encode(a.params) : undefined;
  const bParams = b.params ? ASN1.TLVNode.encode(b.params) : undefined;
  if (SHA2_DIGESTS.has(aOid)) return true;
  if (!aParams || !bParams) return !aParams && !bParams;
  return equalBytes(aParams, bParams);
};
const checkEdDigestParams = (
  kind: EdKind | undefined,
  a: AlgorithmIdentifierCodec,
  label: string,
  signedAttrs = true
): void => {
  if (!kind) return;
  // RFC 8419 sections 3.1 and 3.2 deliberately use different Ed448
  // digestAlgorithm identifiers depending on whether signedAttrs are present.
  const section = signedAttrs ? '3.1' : '3.2';
  const expected = kind === 'Ed448' && !signedAttrs ? 'shake256' : hashOid(CMS_ALG[kind].hash);
  const got = oidName.decode(oidName.encode(a.algorithm));
  if (got !== expected)
    throw new Error(
      `${kind} ${label} digestAlgorithm must be ${expected} by RFC 8419 section ${section}, got ${got}`
    );
  // RFC 8419 sections 3.1/3.2 fix EdDSA CMS digestAlgorithm parameters.
  // OpenSSL 3.5.4 forced Ed25519 CMS generation with `-md sha512` emits absent params too.
  if (kind === 'Ed25519' && a.params)
    throw new Error(
      `${kind} ${label} digestAlgorithm params must be absent by RFC 8419 section ${section}`
    );
  if (kind === 'Ed448' && !signedAttrs && a.params)
    throw new Error(
      `${kind} ${label} digestAlgorithm params must be absent by RFC 8419 section 3.2`
    );
  if (kind === 'Ed448' && !signedAttrs) return;
  if (kind === 'Ed448' && !digestParamsEqual(a.params, CMS_ALG.Ed448.digestParams()))
    throw new Error(
      `${kind} ${label} digestAlgorithm params must be INTEGER 512 by RFC 8419 section 3.1`
    );
};
// EC-only projection helper over CMS_ALG after callers narrow away EdDSA rows.
const ecCurve = (curve: Curve) => CMS_ALG[curve].ec;
// Narrow decoded certificate curve labels down to CMS_ALG's EC rows;
// unknown OID sentinels stay false until a concrete implementation exists.
const isSignCurve = (curve: CertCurve): curve is Curve =>
  curve in CMS_ALG && 'ec' in CMS_ALG[curve as AlgKey];
// Reverse lookup by signature OID only recovers hash/family metadata;
// EC curve selection still comes from SPKI because ECDSA OIDs are shared.
const CMS_ALG_BY_SIG_OID = /* @__PURE__ */ (() =>
  ({
    ...Object.fromEntries(Object.values(CMS_ALG).map((v) => [v.sigOid, v])),
    // RFC 5754 section 3.3 defines ECDSA-with-SHA224; the EC curve still comes from SPKI.
    'ecdsa-with-SHA224': { ec: p256, sigOid: 'ecdsa-with-SHA224', hash: sha224 },
  }) as Record<CmsAlg['sigOid'], CmsAlg>)();
// Keep the executable digest map in sync with public digestAlgorithm override
// names in `oidName`; missing rows turn accepted names into runtime
// "unsupported digestAlgorithm" failures in cmsSignCtx().
const CMS_HASH_BY_OID = /* @__PURE__ */ (() =>
  Object.fromEntries(
    [sha224, sha256, sha384, sha512, shake256_512].map((h) => [hashOid(h), h])
  ) as Record<string, HashAlg>)();
// Decode optional PKCS#8 attributes as raw Attribute OID + SET OF value TLVs;
// interpretation of individual attribute semantics stays above this helper.
const pkcs8Attrs = (k: TArg<DERPKCS8Key>): TRet<Pkcs8Attr[] | undefined> =>
  k.attributes?.map((raw) => (ASN1.Attribute as P.CoderType<Pkcs8Attr>).decode(raw)) as TRet<
    Pkcs8Attr[] | undefined
  >;
// Keep the original PEM/DER bundle alongside the decoded PKCS#8, and
// eagerly decode the inner RSAPrivateKey only for the RSA branch.
const pkcs8FromPem = (pem: string, der: TArg<Uint8Array>): TRet<PrivateKey> => {
  const key = PKCS8.decode(der);
  const t = key.algorithm.info.TAG;
  if (t === 'rsaEncryption') {
    if (key.privateKey.TAG !== 'raw')
      throw new Error('RSA PKCS#8: expected raw private key payload');
    return {
      pem,
      der,
      attributes: pkcs8Attrs(key),
      key,
      rsa: DERRSAPrivateKey.decode(key.privateKey.data),
    } as TRet<PrivateKey>;
  }
  return { pem, der, attributes: pkcs8Attrs(key), key } as TRet<PrivateKey>;
};
// Extract EC/Ed signing material from already-decoded PKCS#8; optional public
// keys are convenience data here, and later caller paths still verify or
// recompute key/certificate consistency separately.
const pkcs8SignKey = (
  k: TArg<DERPKCS8Key>
): TRet<
  | { kind: 'EC'; curve: CertCurve; secretKey: Uint8Array; publicKey?: Uint8Array }
  | { kind: EdKind; secretKey: Uint8Array; publicKey: Uint8Array }
> => {
  const key = k as DERPKCS8Key;
  const tag = key.algorithm.info.TAG;
  if (tag === 'EC') {
    const curve = ecParamCurve(key.algorithm.info.data);
    if (key.privateKey.TAG !== 'struct')
      throw new Error('EC PKCS#8: expected structured ECPrivateKey payload');
    const s = key.privateKey.data;
    if (s.parameters && ecParamCurve(s.parameters) !== curve)
      throw new Error('EC PKCS#8: algorithm and key parameters mismatch');
    return {
      kind: 'EC',
      curve,
      secretKey: s.privateKey,
      publicKey: key.publicKey || s.publicKey,
    } as TRet<{ kind: 'EC'; curve: CertCurve; secretKey: Uint8Array; publicKey?: Uint8Array }>;
  }
  if (tag === 'Ed25519' || tag === 'Ed448') {
    if (key.privateKey.TAG !== 'raw')
      throw new Error(`${tag} PKCS#8: expected raw private key payload`);
    // RFC 8032 sections 5.1.5/5.2.5 derive Ed public keys from the private
    // seed, and RFC 8410 Appendix A calls provided-public-key disagreement a
    // key mismatch error. Match OpenSSL by ignoring the optional PKCS#8 copy
    // here; CMS signing below uses the seed, so certificate matching must too.
    return {
      kind: tag,
      secretKey: key.privateKey.data,
      publicKey: CMS_ALG[tag].ed.getPublicKey(key.privateKey.data),
    } as TRet<{ kind: EdKind; secretKey: Uint8Array; publicKey: Uint8Array }>;
  }
  throw new Error(`expected EC/Ed PKCS#8 key, got ${tag}`);
};

// Internal bare-certificate decode path: normalize optional BER once, then
// feed the canonical DER bytes into the X.509 Certificate coder.
const certItem = (der: TArg<Uint8Array>, opts: BEROpts = {}): Cert =>
  X509C.Certificate.decode(BER.view(der, opts).der);
// Re-encode certificate SubjectPublicKeyInfo through the shared DER SPKI coder
// so certificate-key handling stays aligned with convert.ts.
const certSpkiKey = (spki: TArg<TBSCertificateCodec['spki']>): TRet<DERSPKIKey> =>
  SPKI.decode(X509SPKI.encode(spki as TBSCertificateCodec['spki'])) as TRet<DERSPKIKey>;

// Certificate/private-key matching is limited to the EC/Ed paths this module
// can actually sign with; PKCS#8 embedded public keys are only convenience
// copies, while later signing still uses the secretKey bytes.
const matchCertKey = (cert: Cert, key: TArg<PrivateKey>): boolean => {
  const priv = key as PrivateKey;
  const k = certSpkiKey(cert.tbs.spki);
  const tag = k.algorithm.info.TAG;
  if (tag === 'EC') {
    if (priv.key.algorithm.info.TAG !== 'EC') return false;
    const curve = spkiCurve(k);
    if (!isSignCurve(curve)) return false;
    const kk = pkcs8SignKey(priv.key);
    if (kk.kind !== 'EC' || curve !== kk.curve) return false;
    const cmp = ecCurve(curve).getPublicKey(kk.secretKey, false);
    const cmpC = ecCurve(curve).getPublicKey(kk.secretKey, true);
    return equalBytes(k.publicKey, cmp) || equalBytes(k.publicKey, cmpC);
  }
  if (tag === 'Ed25519' || tag === 'Ed448') {
    if (priv.key.algorithm.info.TAG !== tag) return false;
    const kk = pkcs8SignKey(priv.key);
    if (kk.kind !== tag) return false;
    return (
      equalBytes(k.publicKey, kk.publicKey) ||
      equalBytes(k.publicKey, CMS_ALG[tag].ed.getPublicKey(kk.secretKey))
    );
  }
  throw new Error('matchCertKey supports EC/Ed keys only');
};

// RFC 5280 section 4.1.2.5.1 and 4.1.2.5.2: cert validity uses Zulu time and fixed second precision.
// This regex only enforces the shared UTC second-precision text shape;
// numeric field ranges and calendar rollover checks happen in `X509Time.decode`.
const TimeRE = /^(\d{2}|\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/;
const X509Time: {
  decode: (der: TArg<Uint8Array>) => number;
  encode: (ts: number) => TRet<Uint8Array>;
} = {
  decode: (der: TArg<Uint8Array>): number => {
    // Raw ASN.1 CHOICE only: decoders must accept either arm, while canonical
    // year-range selection and RFC 5280 time-profile checks happen here.
    const t = ASN1.Time.decode(der);
    const m = TimeRE.exec(t.data);
    if (!m) throw new Error(`expected X509 time YY|YYYYMMDDHHMMSSZ, got ${t.data}`);
    const yRaw = m[1];
    if (t.TAG === 'utc' && yRaw.length !== 2)
      throw new Error(`expected UTCTime year=2 digits, got ${t.data}`);
    if (t.TAG === 'generalized' && yRaw.length !== 4)
      throw new Error(`expected GeneralizedTime year=4 digits, got ${t.data}`);
    const yNum = Number(yRaw);
    const y = t.TAG === 'utc' ? (yNum >= 50 ? 1900 + yNum : 2000 + yNum) : yNum;
    const mo = Number(m[2]);
    const d = Number(m[3]);
    const h = Number(m[4]);
    const mi = Number(m[5]);
    const s = Number(m[6]);
    if (mo < 1 || mo > 12) throw new Error(`expected month 01..12, got ${m[2]}`);
    if (d < 1 || d > 31) throw new Error(`expected day 01..31, got ${m[3]}`);
    if (h > 23) throw new Error(`expected hour 00..23, got ${m[4]}`);
    if (mi > 59) throw new Error(`expected minute 00..59, got ${m[5]}`);
    if (s > 59) throw new Error(`expected second 00..59, got ${m[6]}`);
    const rawDate = new Date(0);
    // Date.UTC treats years 0..99 as 1900..1999; RFC 5280 GeneralizedTime
    // uses literal four-digit years, and OpenSSL accepts 0000..0099.
    rawDate.setUTCFullYear(y, mo - 1, d);
    rawDate.setUTCHours(h, mi, s, 0);
    const ms = rawDate.getTime();
    const dt = new Date(ms);
    // RFC 5280 section 4.1.2.5: certificate time fields are exact UTC calendar components and must not roll over.
    if (
      dt.getUTCFullYear() !== y ||
      dt.getUTCMonth() + 1 !== mo ||
      dt.getUTCDate() !== d ||
      dt.getUTCHours() !== h ||
      dt.getUTCMinutes() !== mi ||
      dt.getUTCSeconds() !== s
    )
      throw new Error(`invalid calendar date in X509 time: ${t.data}`);
    return Math.floor(ms / 1000);
  },
  encode: (ts: number): TRet<Uint8Array> => {
    if (!Number.isFinite(ts)) throw new Error(`expected finite timestamp, got ${ts}`);
    const d = new Date(Math.floor(ts) * 1000);
    const pad2 = (n: number): string => `${n}`.padStart(2, '0');
    const pad4 = (n: number): string => `${n}`.padStart(4, '0');
    const y = d.getUTCFullYear();
    // RFC 5280 / RFC 5652 GeneralizedTime uses the fixed `YYYY...` profile,
    // so years outside 0000..9999 must be rejected before formatting.
    if (!Number.isInteger(y) || y < 0 || y > 9999)
      throw new Error(`expected X509 GeneralizedTime year 0000..9999, got ${y}`);
    const text =
      y >= 1950 && y <= 2049
        ? `${pad2(y % 100)}${pad2(d.getUTCMonth() + 1)}${pad2(d.getUTCDate())}${pad2(d.getUTCHours())}${pad2(d.getUTCMinutes())}${pad2(d.getUTCSeconds())}Z`
        : `${pad4(y)}${pad2(d.getUTCMonth() + 1)}${pad2(d.getUTCDate())}${pad2(d.getUTCHours())}${pad2(d.getUTCMinutes())}${pad2(d.getUTCSeconds())}Z`;
    return (y >= 1950 && y <= 2049 ? ASN1.UTCTime : ASN1.GeneralizedTime).encode(
      text
    ) as TRet<Uint8Array>;
  },
} as const;
// Canonicalize a decoded `Time` choice through the strict profile parser
// before comparing certificate validity instants.
const timeEpoch = (time: P.UnwrapCoder<typeof ASN1.Time>): number =>
  X509Time.decode(ASN1.Time.encode(time));
// Low-level PKCS#8 Attribute wrapper only: keep the OID plus raw SET OF
// value TLVs here, and leave OID-specific attribute semantics to callers.
type NameCodec = { rdns: Array<Array<{ oid: string; value: ASN1StringOrRaw }>> };
type ValidityCodec = {
  notBefore: P.UnwrapCoder<typeof ASN1.Time>;
  notAfter: P.UnwrapCoder<typeof ASN1.Time>;
};
type ExtCodec = { oid: string; rest: StrictBytes };
// RFC 5280 section 4.1.1.2 and RFC 5652 sections 10.1.1/10.1.2:
// AlgorithmIdentifier parameters are OPTIONAL.
// `params` keeps parsed ASN.1 ANY TLV when present; `undefined` means absent.
// Keep known AlgorithmIdentifier OIDs user-friendly on the public surface,
// but preserve unknown OIDs and raw params losslessly as raw dotted strings + TLVNode.
type AlgorithmIdentifierCodec = P.UnwrapCoder<typeof ASN1.AlgorithmIdentifier>;
type TBSCertificateCodec = {
  version: bigint | undefined;
  serial: bigint;
  signature: AlgorithmIdentifierCodec;
  issuer: NameCodec;
  validity: ValidityCodec;
  subject: NameCodec;
  spki: { algorithm: AlgorithmIdentifierCodec; publicKey: StrictBytes };
  issuerUniqueID: P.UnwrapCoder<typeof ASN1.BitStringRaw> | undefined;
  subjectUniqueID: P.UnwrapCoder<typeof ASN1.BitStringRaw> | undefined;
  extensions: { list: ExtCodec[] } | undefined;
};
type CertificateCodec = {
  tbs: TBSCertificateCodec;
  sigAlg: AlgorithmIdentifierCodec;
  sig: StrictBytes;
};
const strictBytes = /* @__PURE__ */ P.apply<P.Bytes, StrictBytes>(/* @__PURE__ */ P.bytes(null), {
  encode: (b: P.Bytes): StrictBytes => b as StrictBytes,
  decode: (b: StrictBytes): P.Bytes => b as P.Bytes,
});
// X.520 defines id-at-objectIdentifier(106) under the RFC 5280 `id-at`
// arc { joint-iso-ccitt(2) ds(5) 4 }; `otherName` is a GeneralName label.
// AttributeTypeAndValue wrapper: keep the raw type OID and delegate the
// attribute-value decoding boundary to the RFC 5280 ANY-preserving codec.
// RFC 5280 section 4.1.2.4: AttributeValue is ANY DEFINED BY AttributeType.
// The generic TLV-to-string/raw parsing lives in convert.ts; X.509 only keeps
// the AttributeType-specific schema and matching rules around this boundary.
const NameAttr = /* @__PURE__ */ (() =>
  ASN1.sequence({ oid: ASN1.OID, value: ASN1.StringOrRaw }))();
// PKIX `Name` currently has only the `rdnSequence` CHOICE arm, so model the
// inner SEQUENCE directly and leave per-RDN member order to the DER SET bytes.
const X509Name = /* @__PURE__ */ ASN1.sequence({
  rdns: /* @__PURE__ */ P.array(null, /* @__PURE__ */ ASN1.set(NameAttr)),
});
// RFC 5912 (PKIX1Explicit-2009): Extension.
// Raw Extension shell: keep `extnID` separate and leave the
// `critical`/`extnValue` pair packed in `rest` for ExtBody.
const X509Ext = /* @__PURE__ */ (() => ASN1.sequence({ oid: ASN1.OID, rest: strictBytes }))();
// RFC 5912 (PKIX1Explicit-2009): SubjectPublicKeyInfo.
// Raw SubjectPublicKeyInfo shell: keep AlgorithmIdentifier and the
// subjectPublicKey BIT STRING separate; key-shape checks live later.
const X509SPKI = /* @__PURE__ */ (() =>
  ASN1.sequence({
    algorithm: ASN1.AlgorithmIdentifier,
    publicKey: ASN1.BitString,
  }))();
// RFC 5912 (PKIX1Explicit-2009): TBSCertificate.
// Raw TBSCertificate shell: preserve the tagged version/UID/extension fields
// here and leave RFC 5280 version-coupling checks to later certificate validation.
const X509TBSCertificate = /* @__PURE__ */ (() =>
  ASN1.sequence({
    version: /* @__PURE__ */ ASN1.optional(/* @__PURE__ */ ASN1.explicit(0, ASN1.Integer)),
    serial: ASN1.Integer,
    signature: ASN1.AlgorithmIdentifier,
    issuer: X509Name,
    // Raw Validity wrapper only: preserve the encoded Time fields here and leave
    // ordering / current-time checks to higher-level certificate validation.
    validity: /* @__PURE__ */ ASN1.sequence({
      notBefore: ASN1.Time,
      notAfter: ASN1.Time,
    }),
    subject: X509Name,
    spki: X509SPKI,
    // RFC 5280 §4.1 defines UniqueIdentifier as plain BIT STRING; unlike
    // SubjectPublicKeyInfo/signatureValue, PKITS vectors use non-byte-aligned
    // IDs, so expose the raw BIT STRING shape and preserve the DER unused-bit count.
    issuerUniqueID: /* @__PURE__ */ ASN1.optional(
      /* @__PURE__ */ ASN1.implicit(1, ASN1.BitStringRaw)
    ),
    subjectUniqueID: /* @__PURE__ */ ASN1.optional(
      /* @__PURE__ */ ASN1.implicit(2, ASN1.BitStringRaw)
    ),
    extensions: /* @__PURE__ */ ASN1.optional(
      /* @__PURE__ */ ASN1.explicit(
        3,
        /* @__PURE__ */ ASN1.sequence({ list: /* @__PURE__ */ P.array(null, X509Ext) })
      )
    ),
  }))();
// RFC 5912 (PKIX1Explicit-2009): Certificate.
// Raw Certificate shell: preserve the signed TBSCertificate, outer
// signatureAlgorithm, and signatureValue fields; cross-field checks live later.
const X509Certificate = /* @__PURE__ */ (() =>
  ASN1.sequence({
    tbs: X509TBSCertificate,
    sigAlg: ASN1.AlgorithmIdentifier,
    sig: ASN1.BitString,
  }))();
const X509C: {
  Name: P.CoderType<NameCodec>;
  TBSCertificate: P.CoderType<TBSCertificateCodec>;
  Certificate: P.CoderType<CertificateCodec>;
} = {
  Name: X509Name,
  TBSCertificate: X509TBSCertificate,
  Certificate: X509Certificate,
};
type AttributeCodec = { oid: string; values: StrictBytes[] };
type SignerIdentifierCodec =
  | { TAG: 'issuerSerial'; data: { issuer: NameCodec; serial: bigint } }
  | { TAG: 'subjectKeyIdentifier'; data: StrictBytes };
type SignerInfoCodec = {
  version: bigint;
  sid: SignerIdentifierCodec;
  digestAlg: AlgorithmIdentifierCodec;
  signedAttrs: AttributeCodec[] | undefined;
  signatureAlg: AlgorithmIdentifierCodec;
  signature: StrictBytes;
  unsignedAttrs: AttributeCodec[] | undefined;
};
type SignedDataCodec = {
  version: bigint;
  digestAlgorithms: AlgorithmIdentifierCodec[];
  encapContentInfo: { eContentType: string; eContent: StrictBytes | undefined };
  certificates: CMSCertificateChoiceCodec[] | undefined;
  crls: CMSRevocationInfoChoiceCodec[] | undefined;
  signerInfos: SignerInfoCodec[];
};
type ContentInfoCodec = { contentType: string; content: StrictBytes };
type CMSCertificateChoiceCodec =
  | { TAG: 'certificate'; data: P.UnwrapCoder<typeof X509C.Certificate> }
  | { TAG: 'extendedCertificate'; data: StrictBytes }
  | { TAG: 'v1AttrCert'; data: StrictBytes }
  | { TAG: 'v2AttrCert'; data: StrictBytes }
  | { TAG: 'other'; data: StrictBytes };
type CMSRevocationInfoChoiceCodec =
  | {
      TAG: 'crl';
      data: {
        tbsCertList: StrictBytes;
        signatureAlgorithm: AlgorithmIdentifierCodec;
        signatureValue: StrictBytes;
      };
    }
  | { TAG: 'other'; data: { format: string; info: StrictBytes } };
// RFC 5652 section 10.2.2: CertificateChoices.
const CMSCertificateChoices: P.CoderType<CMSCertificateChoiceCodec> = /* @__PURE__ */ (() =>
  ASN1.choice({
    certificate: X509C.Certificate,
    // Legacy attribute-certificate and other-certificate branches stay opaque here;
    // current signer-cert resolution only consumes the ordinary certificate arm.
    extendedCertificate: ASN1.tagged(0xa0, strictBytes),
    // RFC 5652 section 12.2: ACv1 module; parsed as opaque branch and not consumed by signer-cert selection.
    v1AttrCert: ASN1.tagged(0xa1, strictBytes),
    v2AttrCert: ASN1.tagged(0xa2, strictBytes),
    other: ASN1.tagged(0xa3, strictBytes),
  }))();
// RFC 5652 section 10.2.1: RevocationInfoChoice and OtherRevocationInfoFormat.
const CMSCertificateList = /* @__PURE__ */ (() =>
  ASN1.sequence({
    // Raw CertificateList shell: keep TBSCertList opaque here and leave CRL
    // semantics plus outer/inner signature checks to later revocation handling.
    tbsCertList: ASN1.any,
    signatureAlgorithm: ASN1.AlgorithmIdentifier,
    signatureValue: ASN1.BitString,
  }))();
// Raw OtherRevocationInfoFormat shell: keep the identifying OID separate and
// preserve one opaque ASN.1 payload for format-specific revocation info.
const CMSOtherRevocationInfoFormat = /* @__PURE__ */ (() =>
  ASN1.sequence({ format: ASN1.OID, info: ASN1.any }))();
// Raw RevocationInfoChoice wrapper: select between the X.509 CertificateList
// shell and the opaque [1] other-format envelope without extra narrowing here.
const CMSRevocationInfoChoice: P.CoderType<CMSRevocationInfoChoiceCodec> = /* @__PURE__ */ (() =>
  ASN1.choice({
    crl: CMSCertificateList,
    other: ASN1.implicit(1, CMSOtherRevocationInfoFormat),
  }))();
// RFC 5652 sections 10.1.1 and 10.1.2: DigestAlgorithmIdentifier/SignatureAlgorithmIdentifier ::= AlgorithmIdentifier.
// RFC 5652 section 5.3: Attribute ::= SEQUENCE { attrType OBJECT IDENTIFIER, attrValues SET OF AttributeValue }.
// Raw CMS Attribute shell: keep attrType separate and preserve attrValues as
// opaque TLVs here, while known single-valued signed attributes are enforced below.
const CMSAttribute = /* @__PURE__ */ (() =>
  P.validate(ASN1.Attribute, (a) => {
    // RFC 5652 section 11.1: content-type attrValues is SET SIZE (1) OF AttributeValue.
    // RFC 5652 section 11.2: message-digest attrValues is SET SIZE (1) OF AttributeValue.
    // RFC 5652 section 11.3: signing-time attrValues is SET SIZE (1) OF AttributeValue.
    const name = CMS_SIGNED_ATTR_NAME[a.oid as keyof typeof CMS_SIGNED_ATTR_NAME] || '';
    if (name && a.values.length !== 1)
      throw new Error(`${name} attribute must have exactly one value, got ${a.values.length}`);
    return a;
  }))() satisfies P.CoderType<AttributeCodec>;
// RFC 5652 section 10.2.4 (used by section 5.3 SignerIdentifier): IssuerAndSerialNumber.
// Raw IssuerAndSerialNumber shell: preserve issuer Name plus certificate
// serial INTEGER here, and leave certificate-identity matching to later CMS logic.
const CMSIssuerAndSerial = /* @__PURE__ */ (() =>
  ASN1.sequence({
    issuer: X509C.Name,
    serial: ASN1.Integer,
  }))();
// RFC 5652 section 5.3: SignerIdentifier (IssuerAndSerialNumber / SubjectKeyIdentifier).
// Raw SignerIdentifier CHOICE: preserve both issuer/serial and implicit [0]
// subjectKeyIdentifier forms here, and leave version/certificate matching to later CMS logic.
const CMSSignerIdentifier = /* @__PURE__ */ (() =>
  ASN1.choice({
    issuerSerial: CMSIssuerAndSerial,
    subjectKeyIdentifier: ASN1.implicit(0, ASN1.OctetString),
  }))();
// RFC 5652 section 5.3: SignerInfo.
// Raw SignerInfo shell: preserve the ASN.1 field layout here; higher-level
// CMS helpers are responsible for RFC 5652 version/cardinality/profile checks.
const CMSSignerInfo = /* @__PURE__ */ (() =>
  ASN1.sequence({
    version: ASN1.Integer,
    sid: CMSSignerIdentifier,
    digestAlg: ASN1.AlgorithmIdentifier,
    // RFC 5652 section 5.3: SignedAttributes MUST be DER encoded even if the
    // rest of the CMS object is BER, so keep SET OF order validation here.
    signedAttrs: ASN1.optional(ASN1.implicit(0, ASN1.set(CMSAttribute))),
    signatureAlg: ASN1.AlgorithmIdentifier,
    signature: ASN1.OctetString,
    unsignedAttrs: ASN1.optional(ASN1.implicit(1, ASN1.set(CMSAttribute, { ber: true }))),
  }))();
// RFC 5652 section 5.2: EncapsulatedContentInfo.
// Raw EncapsulatedContentInfo shell: preserve the contentType OID plus the
// optional explicit [0] OCTET STRING, and leave detached/degenerate rules to later CMS logic.
const CMSEncapContentInfo = /* @__PURE__ */ (() =>
  ASN1.sequence({
    eContentType: ASN1.OID,
    eContent: ASN1.optional(ASN1.explicit(0, ASN1.OctetString)),
  }))();
// RFC 5652 section 5.1: SignedData.
// Raw SignedData shell: preserve the ASN.1 field layout here; version,
// digest-set, and signer/profile coupling checks live in later CMS helpers.
const CMSSignedData: P.CoderType<SignedDataCodec> = /* @__PURE__ */ (() =>
  ASN1.sequence({
    version: ASN1.Integer,
    // RFC 5652 sections 1 and 1.1.1 make CMS BER-facing by default; signed
    // attributes and authenticated attributes are the only CMS data types that
    // require DER, so outer SignedData SET OF fields accept BER order on decode.
    digestAlgorithms: ASN1.set(ASN1.AlgorithmIdentifier, { ber: true }),
    encapContentInfo: CMSEncapContentInfo,
    // RFC 5652 section 10.2.3: CertificateSet ::= SET OF CertificateChoices.
    certificates: ASN1.optional(ASN1.implicit(0, ASN1.set(CMSCertificateChoices, { ber: true }))),
    crls: ASN1.optional(ASN1.implicit(1, ASN1.set(CMSRevocationInfoChoice, { ber: true }))),
    signerInfos: ASN1.set(CMSSignerInfo, { ber: true }),
  }))();
// RFC 5652 section 3: ContentInfo.
// Raw outer CMS wrapper: keep one explicit [0] TLV payload here and leave
// contentType-specific inner decoding to later CMS helpers.
const CMSContentInfo = /* @__PURE__ */ (() =>
  ASN1.sequence({
    contentType: ASN1.OIDMap,
    content: ASN1.explicit(0, ASN1.any),
  }))();
// treeshake: direct object literal retains CMS schema refs in X509-only bundles.
const CMSX: {
  AlgorithmIdentifier: typeof ASN1.AlgorithmIdentifier;
  Attribute: P.CoderType<AttributeCodec>;
  SignerInfo: P.CoderType<SignerInfoCodec>;
  SignedData: P.CoderType<SignedDataCodec>;
  ContentInfo: P.CoderType<ContentInfoCodec>;
} = /* @__PURE__ */ (() => ({
  AlgorithmIdentifier: ASN1.AlgorithmIdentifier,
  Attribute: CMSAttribute,
  SignerInfo: CMSSignerInfo,
  SignedData: CMSSignedData,
  ContentInfo: CMSContentInfo,
}))();
// micro-packed coders for full X.509 cert decode/encode.
/**
 * Low-level X.509 coders used by the higher-level APIs.
 * @example
 * Use the low-level coders when you need to encode or decode individual X.509 structures.
 * ```ts
 * import { CERTUtils } from 'micro-key-producer/x509.js';
 * CERTUtils.Name.encode({
 *   rdns: [[{ oid: 'commonName', value: { TAG: 'utf8', data: 'example.com' } }]],
 * });
 * ```
 */
export const CERTUtils: {
  Name: typeof X509C.Name;
  TBSCertificate: typeof X509C.TBSCertificate;
  Certificate: typeof X509C.Certificate;
} = /* @__PURE__ */ deepFreeze(
  /* @__PURE__ */ (() => ({
    Name: X509C.Name,
    TBSCertificate: X509C.TBSCertificate,
    Certificate: X509C.Certificate,
  }))()
);

// Generic IP coders (not ASN.1-specific): bytes <-> textual address.
// Textual IPv4 should stay in strict dotted-decimal `dec-octet` form rather
// than accepting legacy leading-zero variants that other parsers normalize.
const IPv4: P.CoderType<string> = /* @__PURE__ */ P.apply(/* @__PURE__ */ P.bytes(4), {
  encode: (b: TArg<Uint8Array>): string => {
    const bytes = b as Uint8Array;
    return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`;
  },
  decode: (s: string): TRet<Uint8Array> => {
    const p = s.split('.');
    if (p.length !== 4) throw new Error(`invalid IPv4 address ${s}`);
    const out = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
      // RFC 3986 section 3.2.2: `dec-octet` permits only canonical 0..255 decimal
      // octets; section 7.4 warns that broader leading-zero forms are platform-dependent.
      if (!/^(?:0|[1-9][0-9]?|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$/.test(p[i]))
        throw new Error(`invalid IPv4 address ${s}`);
      const n = Number(p[i]);
      if (!Number.isInteger(n) || n < 0 || n > 255) throw new Error(`invalid IPv4 address ${s}`);
      out[i] = n;
    }
    return out as TRet<Uint8Array>;
  },
}) satisfies P.CoderType<string>;
// Generic IP coders (not ASN.1-specific): bytes <-> textual address.
// Textual IPv6 should accept the full RFC 3986 / RFC 4291 surface,
// including mixed `ls32` dotted-quad tails like `::ffff:192.0.2.1`.
const IPv6: P.CoderType<string> = /* @__PURE__ */ P.apply(/* @__PURE__ */ P.bytes(16), {
  encode: (b: TArg<Uint8Array>): string => {
    const bytes = b as Uint8Array;
    const w = new Array<number>(8);
    for (let i = 0; i < 8; i++) w[i] = (bytes[i * 2] << 8) | bytes[i * 2 + 1];
    let bestAt = -1;
    let bestLen = 0;
    for (let i = 0; i < 8; ) {
      if (w[i] !== 0) {
        i++;
        continue;
      }
      let j = i;
      while (j < 8 && w[j] === 0) j++;
      const len = j - i;
      if (len > bestLen && len > 1) {
        bestLen = len;
        bestAt = i;
      }
      i = j;
    }
    const hexw = w.map((x) => x.toString(16));
    if (bestAt < 0) return hexw.join(':');
    const left = hexw.slice(0, bestAt).join(':');
    const right = hexw.slice(bestAt + bestLen).join(':');
    if (!left && !right) return '::';
    if (!left) return `::${right}`;
    if (!right) return `${left}::`;
    return `${left}::${right}`;
  },
  decode: (s: string): TRet<Uint8Array> => {
    if (s.includes(':::')) throw new Error(`invalid IPv6 address ${s}`);
    if ((s.match(/::/g) || []).length > 1) throw new Error(`invalid IPv6 address ${s}`);
    const [l, r] = s.split('::');
    const part = (p: string, dottedTail: boolean): string[] => {
      if (!p) return [];
      // RFC 3986 section 3.2.2: IPv6address uses `h16 ":"` segments and the
      // only valid empty segment marker is one `::` zero-run elision.
      if (p.startsWith(':') || p.endsWith(':') || p.includes('::'))
        throw new Error(`invalid IPv6 address ${s}`);
      const items = p.split(':').filter((i) => i.length);
      const out: string[] = [];
      for (let i = 0; i < items.length; i++) {
        const x = items[i];
        if (!x.includes('.')) {
          out.push(x);
          continue;
        }
        // RFC 3986 section 3.2.2: `ls32` may be an IPv4address; RFC 4291
        // section 2.2 lists mixed `x:x:x:x:x:x:d.d.d.d` IPv6 text.
        if (!dottedTail || i !== items.length - 1) throw new Error(`invalid IPv6 address ${s}`);
        const ip = IPv4.encode(x);
        out.push(((ip[0] << 8) | ip[1]).toString(16), ((ip[2] << 8) | ip[3]).toString(16));
      }
      return out;
    };
    const lp = part(l, r === undefined);
    const rp = r !== undefined ? part(r, true) : [];
    if (
      !lp.every((i) => /^[0-9a-fA-F]{1,4}$/.test(i)) ||
      !rp.every((i) => /^[0-9a-fA-F]{1,4}$/.test(i))
    )
      throw new Error(`invalid IPv6 address ${s}`);
    const total = lp.length + rp.length;
    if (!((s.includes('::') && total <= 8) || (!s.includes('::') && total === 8)))
      throw new Error(`invalid IPv6 address ${s}`);
    const mid = s.includes('::') ? new Array<string>(8 - total).fill('0') : [];
    const words = [...lp, ...mid, ...rp];
    if (words.length !== 8) throw new Error(`invalid IPv6 address ${s}`);
    const out = new Uint8Array(16);
    for (let i = 0; i < 8; i++) {
      const n = Number.parseInt(words[i], 16);
      if (!Number.isFinite(n) || n < 0 || n > 0xffff) throw new Error(`invalid IPv6 address ${s}`);
      out[i * 2] = n >>> 8;
      out[i * 2 + 1] = n & 0xff;
    }
    return out as TRet<Uint8Array>;
  },
}) satisfies P.CoderType<string>;
// RFC 5280 reuses iPAddress for both plain 4/16-octet GeneralName addresses
// and 8/32-octet nameConstraints CIDR ranges on the same tagged arm.
const IPAddress = /* @__PURE__ */ ASN1.tagged(
  0x87,
  /* @__PURE__ */ P.apply(/* @__PURE__ */ P.bytes(null), {
    encode: (b: TArg<Uint8Array>): string => {
      const bytes = b as Uint8Array;
      if (bytes.length === 4) return IPv4.decode(bytes);
      if (bytes.length === 16) return IPv6.decode(bytes);
      return `hex:${bytesToHex(bytes)}`;
    },
    decode: (s: string): TRet<Uint8Array> => {
      if (s.startsWith('hex:')) return hexToBytes(s.slice(4)) as TRet<Uint8Array>;
      if (s.includes('.')) return IPv4.encode(s) as TRet<Uint8Array>;
      if (s.includes(':')) return IPv6.encode(s) as TRet<Uint8Array>;
      throw new Error(`invalid SAN iPAddress ${s}`);
    },
  }) satisfies P.CoderType<string>
);
const cidrPrefix = (mask: TArg<Uint8Array>, bits: number): number => {
  const bytes = mask as Uint8Array;
  if (bytes.length * 8 !== bits) throw new Error('invalid nameConstraints iPAddress mask');
  let prefix = 0;
  let zero = false;
  for (const byte of bytes) {
    for (let bit = 7; bit >= 0; bit--) {
      const one = !!(byte & (1 << bit));
      if (!one) {
        zero = true;
        continue;
      }
      if (zero) throw new Error('invalid nameConstraints iPAddress mask');
      prefix++;
    }
  }
  return prefix;
};
const cidrMask = (prefix: number, bytes: number): TRet<Uint8Array> => {
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bytes * 8)
    throw new Error('invalid nameConstraints iPAddress prefix');
  const out = new Uint8Array(bytes);
  for (let i = 0; i < prefix; i++) out[i >>> 3] |= 0x80 >>> (i & 7);
  return out as TRet<Uint8Array>;
};
const NameConstraintIPAddress = /* @__PURE__ */ ASN1.tagged(
  0x87,
  /* @__PURE__ */ P.apply(/* @__PURE__ */ P.bytes(null), {
    encode: (b: TArg<Uint8Array>): string => {
      const bytes = b as Uint8Array;
      if (bytes.length === 8)
        return `${IPv4.decode(bytes.subarray(0, 4))}/${cidrPrefix(bytes.subarray(4), 32)}`;
      if (bytes.length === 32)
        return `${IPv6.decode(bytes.subarray(0, 16))}/${cidrPrefix(bytes.subarray(16), 128)}`;
      throw new Error('invalid nameConstraints iPAddress length');
    },
    decode: (s: string): TRet<Uint8Array> => {
      const p = s.split('/');
      if (p.length !== 2 || !p[0] || !/^[0-9]+$/.test(p[1]))
        throw new Error(`invalid nameConstraints iPAddress ${s}`);
      const prefix = Number(p[1]);
      if (p[0].includes('.') && !p[0].includes(':'))
        return concatBytes(IPv4.encode(p[0]), cidrMask(prefix, 4)) as TRet<Uint8Array>;
      return concatBytes(IPv6.encode(p[0]), cidrMask(prefix, 16)) as TRet<Uint8Array>;
    },
  }) satisfies P.CoderType<string>
);
// RFC 5280 section 4.2.1.6: OtherName.value is [0] EXPLICIT
// ANY DEFINED BY type-id, so unknown type IDs must keep the raw DER value.
const ExtOtherName = /* @__PURE__ */ (() =>
  ASN1.sequence({
    type: ASN1.OID,
    value: /* @__PURE__ */ ASN1.explicit(0, ASN1.any),
  }))();
// RFC 5280 section 4.2.1.6: GeneralName.
// Structured opaque name forms such as x400Address and ediPartyName still
// need their context-specific wrappers to stay constructed on the wire.
const extGeneralName = (iPAddress: P.CoderType<string>) =>
  ASN1.choice({
    otherName: /* @__PURE__ */ ASN1.implicit(0, ExtOtherName),
    rfc822Name: /* @__PURE__ */ ASN1.implicit(1, ASN1.IA5String),
    dNSName: /* @__PURE__ */ ASN1.implicit(2, ASN1.IA5String),
    // RFC 5280 section 4.2.1.6 / Appendix A: x400Address [3] ORAddress and
    // ediPartyName [5] EDIPartyName are structured values, so preserve their
    // constructed context-specific wrappers while leaving the bodies opaque.
    x400Address: /* @__PURE__ */ ASN1.tagged(0xa3, P.bytes(null)),
    directoryName: /* @__PURE__ */ ASN1.explicit(4, X509Name),
    ediPartyName: /* @__PURE__ */ ASN1.tagged(0xa5, P.bytes(null)),
    uniformResourceIdentifier: /* @__PURE__ */ ASN1.implicit(6, ASN1.IA5String),
    iPAddress,
    registeredID: /* @__PURE__ */ ASN1.implicit(8, ASN1.OID),
  });
const ExtGeneralName = /* @__PURE__ */ extGeneralName(IPAddress);
// RFC 5280 section 4.2.1.10: nameConstraints iPAddress is address plus CIDR mask,
// encoded as 8 octets for IPv4 or 32 octets for IPv6, unlike plain SAN/IAN addresses.
const ExtNameConstraintGeneralName = /* @__PURE__ */ extGeneralName(NameConstraintIPAddress);
const extNonEmpty = <T extends { list: unknown[] }>(
  coder: P.CoderType<T>,
  name: string,
  item: string
): P.CoderType<T> =>
  // Shared RFC SIZE (1..MAX) guard for extension shells that are otherwise
  // just `{ list: ... }` sequences underneath.
  P.validate(coder, (x) => nonEmptyList(x, name, item));
const nonEmptyList = <T extends { list: unknown[] }>(x: T, name: string, item: string): T => {
  // RFC 5280 section 4.2.1.6 defines GeneralNames as `SEQUENCE SIZE (1..MAX)`;
  // sibling extension shells use the same helper for their own ASN.1 SIZE rules.
  if (!x.list.length) throw new Error(`${name} must contain at least one ${item}`);
  return x;
};
const ExtGeneralNamesRaw = /* @__PURE__ */ ASN1.sequence({
  // GeneralNames itself is RFC 5280 `SIZE (1..MAX)`, so bare reuse sites
  // use the checked wrapper below while implicit-tag sites validate after decode.
  list: /* @__PURE__ */ P.array(null, ExtGeneralName),
});
const ExtGeneralNames = /* @__PURE__ */ P.validate(ExtGeneralNamesRaw, (x) =>
  nonEmptyList(x, 'GeneralNames', 'GeneralName')
) satisfies P.CoderType<P.UnwrapCoder<typeof ExtGeneralNamesRaw>>;
// RFC 5280 section 4.2.1.6: subjectAltName uses GeneralNames SIZE (1..MAX).
// It also forbids CAs from issuing empty GeneralName payloads, but leaves
// client behavior undefined; OpenSSL verifies raw-forced empty names, so
// certificate-user decode preserves them instead of enforcing CA generation policy.
const ExtSAN = /* @__PURE__ */ P.validate(ExtGeneralNamesRaw, (x) => {
  nonEmptyList(x, 'subjectAltName', 'GeneralName');
  return x;
});
// RFC 5280 section 4.2.1.7: issuerAltName uses GeneralNames SIZE (1..MAX).
const ExtIAN = /* @__PURE__ */ extNonEmpty(ExtGeneralNamesRaw, 'issuerAltName', 'GeneralName');
// RFC 5280 section 4.2.1.1: AuthorityKeyIdentifier.
const ExtAKI = /* @__PURE__ */ (() =>
  P.validate(
    ASN1.sequence({
      keyIdentifier: ASN1.optional(ASN1.implicit(0, ASN1.OctetString)),
      authorityCertIssuer: ASN1.optional(ASN1.implicit(1, ExtGeneralNamesRaw)),
      authorityCertSerialNumber: ASN1.optional(ASN1.implicit(2, ASN1.Integer)),
    }),
    (x) => {
      if (x.authorityCertIssuer)
        // RFC 5280 section 4.2.1.1 uses GeneralNames for authorityCertIssuer,
        // so the RFC 5280 section 4.2.1.6 SIZE (1..MAX) rule applies here too.
        nonEmptyList(
          x.authorityCertIssuer,
          'authorityKeyIdentifier authorityCertIssuer',
          'GeneralName'
        );
      // RFC 5280 Appendix A: authorityCertIssuer and authorityCertSerialNumber
      // "MUST both be present or both be absent".
      if (!!x.authorityCertIssuer !== (x.authorityCertSerialNumber !== undefined))
        throw new Error(
          'authorityKeyIdentifier authorityCertIssuer and authorityCertSerialNumber must both be present or both be absent'
        );
      return x;
    }
  ))();
// Raw AccessDescription shell reused by both AIA and SIA; the enclosing
// wrappers enforce the outer SIZE (1..MAX) rule.
const ExtAccessInfo = /* @__PURE__ */ (() =>
  ASN1.sequence({
    list: P.array(null, ASN1.sequence({ method: ASN1.OID, location: ExtGeneralName })),
  }))();
// RFC 5280 section 4.2.2.1: AuthorityInfoAccessSyntax is SEQUENCE SIZE (1..MAX) OF AccessDescription.
const ExtAIA = /* @__PURE__ */ extNonEmpty(
  ExtAccessInfo,
  'authorityInfoAccess',
  'AccessDescription'
);
// RFC 5280 section 4.2.2.2: SubjectInfoAccessSyntax is SEQUENCE SIZE (1..MAX) OF AccessDescription.
const ExtSIA = /* @__PURE__ */ extNonEmpty(ExtAccessInfo, 'subjectInfoAccess', 'AccessDescription');
// RFC 3820 section 3.8: ProxyCertInfo extension.
// proxyPolicy is an arbitrary OCTET STRING; keep the public `policy` field as canonical lowercase
// hex so raw policy bytes survive decode/encode without ASN.1-specific interpretation.
const OctetsHex = /* @__PURE__ */ ASN1.tagged(
  0x04,
  /* @__PURE__ */ P.apply(/* @__PURE__ */ P.bytes(null), hex)
);
// This raw shell mirrors RFC 3820 section 3.8 structure only; range and special-language
// policy rules are enforced in ExtProxyCertInfoChecked before the public extension surface uses it.
const ExtProxyCertInfo = /* @__PURE__ */ (() =>
  ASN1.sequence({
    pathLen: ASN1.optional(ASN1.Integer),
    policy: ASN1.sequence({
      language: ASN1.OID,
      policy: ASN1.optional(OctetsHex),
    }),
  }))();
const ExtProxyCertInfoChecked = /* @__PURE__ */ P.validate(ExtProxyCertInfo, (x) => {
  // RFC 3820 section 3.8.1: pCPathLenConstraint is INTEGER (0..MAX) when present.
  if (x.pathLen !== undefined && x.pathLen < _0n)
    throw new Error('proxyCertInfo pCPathLenConstraint must be >= 0');
  // RFC 3820 section 3.8.2: inheritAll/independent MUST NOT carry policy bytes.
  if (
    (x.policy.language === 'proxyPolicyInheritAll' ||
      x.policy.language === 'proxyPolicyIndependent') &&
    x.policy.policy !== undefined
  )
    throw new Error(
      'proxyCertInfo policy MUST be absent for inheritAll/independent policy language'
    );
  return x;
}) satisfies P.CoderType<{
  pathLen: bigint | undefined;
  policy: { language: string; policy: string | undefined };
}>;
// RFC 7633 section 4.1 + IANA TLS extension registry: Features are TLS extension identifiers (uint16 space).
const ExtTLSFeature = /* @__PURE__ */ (() =>
  P.validate(ASN1.sequence({ list: P.array(null, ASN1.Integer) }), (x) => {
    for (const f of x.list) {
      if (f < _0n || f > U16_MAX) throw new Error(`tlsFeature value must be in 0..65535, got ${f}`);
    }
    return x;
  }))() satisfies P.CoderType<{ list: bigint[] }>;
// This is the RFC 6962 v1 SignedCertificateTimestamp wire image; version gating and
// SerializedSCT list handling live in SCTListInner rather than this fixed-layout item codec.
const SCTItem = /* @__PURE__ */ (() =>
  P.struct({
    version: P.U8,
    logID: P.bytes(32),
    timestamp: P.U64BE,
    extensions: P.apply(P.bytes(P.U16BE), hex),
    hash: P.U8,
    signatureAlgorithm: P.U8,
    signature: P.bytes(P.U16BE),
  }))();
// RFC 6962 section 3.3 makes SerializedSCT opaque at the list layer, but this
// typed decoder intentionally accepts only the defined RFC 6962 v1 SCT format.
// CT v2 uses RFC 9162 TransItem/extension OID 1.3.101.75, not version=1 blobs here.
const SCTListInner = /* @__PURE__ */ (() =>
  P.validate(
    P.apply(P.bytes(null), {
      encode: (b: TArg<Uint8Array>): TRet<P.UnwrapCoder<typeof SCTItem>[]> => {
        // RFC 6962 section 3.3: X.509 extension carries SignedCertificateTimestampList inside ASN.1 OCTET STRING.
        // The extension decoder usually passes the unwrapped OCTET STRING bytes,
        // and a valid raw two-byte list length can itself start with 0x04; only
        // unwrap when the input is exactly one DER OCTET STRING TLV.
        const raw = b as Uint8Array;
        let body = raw;
        if (raw.length && raw[0] === 0x04) {
          try {
            const inner = ASN1.OctetString.decode(raw);
            if (equalBytes(ASN1.OctetString.encode(inner), raw)) body = inner;
          } catch {}
        }
        return P.prefix(P.U16BE, P.array(null, P.prefix(P.U16BE, SCTItem))).decode(body) as TRet<
          P.UnwrapCoder<typeof SCTItem>[]
        >;
      },
      decode: (v: TArg<P.UnwrapCoder<typeof SCTItem>[]>): TRet<Uint8Array> =>
        P.prefix(P.U16BE, P.array(null, P.prefix(P.U16BE, SCTItem))).encode(
          v as P.UnwrapCoder<typeof SCTItem>[]
        ) as TRet<Uint8Array>,
    }),
    (x) => {
      // RFC 6962 section 3.3: SignedCertificateTimestampList.sct_list is <1..2^16-1>.
      if (!x.length) throw new Error('sct list must contain at least one SerializedSCT');
      // RFC 6962 section 3.2: sct_version for v1 is 0; reject opaque/proprietary blobs
      // on this typed v1 surface instead of preserving unauthenticated unknown payloads.
      for (const sct of x) {
        if (sct.version !== 0) throw new Error(`sct_version must be v1 (0), got ${sct.version}`);
      }
      return x;
    }
  ))() satisfies P.CoderType<P.UnwrapCoder<typeof SCTItem>[]>;
// RFC 5280 section 4.2.1.13: DistributionPointName.
// The nameRelativeToCRLIssuer branch is a RelativeDistinguishedName, so it must stay a non-empty
// SET OF AttributeTypeAndValue rather than an arbitrary possibly-empty attribute list.
const ExtDistributionPointName = /* @__PURE__ */ (() =>
  P.validate(
    ASN1.choice({
      fullName: ASN1.implicit(0, ExtGeneralNamesRaw),
      nameRelativeToCRLIssuer: ASN1.implicit(1, ASN1.set(NameAttr)),
    }),
    (x) => {
      // Validate after the CHOICE: ASN1.implicit needs inner ASN.1 tag metadata,
      // while P.validate intentionally returns a plain coder without that metadata.
      // RFC 5280 section 4.2.1.13 uses GeneralNames for fullName, so the
      // RFC 5280 section 4.2.1.6 SIZE (1..MAX) rule applies here too.
      if (x.TAG === 'fullName') nonEmptyList(x.data, 'distributionPoint fullName', 'GeneralName');
      // RFC 5280 Appendix A: RelativeDistinguishedName is
      // `SET SIZE (1..MAX) OF AttributeTypeAndValue`.
      if (x.TAG === 'nameRelativeToCRLIssuer' && !x.data.length)
        throw new Error('nameRelativeToCRLIssuer must contain at least one AttributeTypeAndValue');
      return x;
    }
  ))();
// RFC 5280 section 4.2.1.13: DistributionPoint and CRLDistributionPoints.
// cRLIssuer is encoded as GeneralNames on the wire, but RFC 5280 restricts it to distinguished
// name values from the CRL issuer field rather than arbitrary GeneralName alternatives.
const ExtCRLDP = /* @__PURE__ */ (() =>
  P.validate(
    ASN1.sequence({
      list: P.array(
        null,
        ASN1.sequence({
          distributionPoint: ASN1.optional(ASN1.explicit(0, ExtDistributionPointName)),
          reasons: ASN1.optional(ASN1.implicit(1, ASN1.BitStringRaw)),
          cRLIssuer: ASN1.optional(ASN1.implicit(2, ExtGeneralNamesRaw)),
        })
      ),
    }),
    (x) => {
      // RFC 5280 section 4.2.1.13: CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint.
      if (!x.list.length)
        throw new Error('cRLDistributionPoints must contain at least one DistributionPoint');
      // RFC 5280 section 4.2.1.13: DistributionPoint MUST NOT contain only reasons;
      // either distributionPoint or cRLIssuer must be present.
      for (const dp of x.list) {
        if (!dp.distributionPoint && !dp.cRLIssuer) {
          throw new Error('DistributionPoint must include distributionPoint or cRLIssuer');
        }
        if (dp.cRLIssuer) {
          // RFC 5280 section 4.2.1.13 uses GeneralNames for cRLIssuer, so the
          // RFC 5280 section 4.2.1.6 SIZE (1..MAX) rule applies here too.
          nonEmptyList(dp.cRLIssuer, 'cRLIssuer', 'GeneralName');
          // RFC 5280 section 4.2.1.13: if present, cRLIssuer "MUST only contain
          // the distinguished name (DN)" from the referenced CRL issuer field.
          for (const n of dp.cRLIssuer.list) {
            if (n.TAG !== 'directoryName')
              throw new Error('cRLIssuer must only contain directoryName values');
          }
        }
      }
      return x;
    }
  ))() satisfies P.CoderType<{
  list: {
    distributionPoint: P.UnwrapCoder<typeof ExtDistributionPointName> | undefined;
    reasons: P.UnwrapCoder<typeof ASN1.BitStringRaw> | undefined;
    cRLIssuer: P.UnwrapCoder<typeof ExtGeneralNames> | undefined;
  }[];
}>;
type PolicyUserNotice = Extract<CertPolicyQualifier, { TAG: 'userNotice' }>['data'];
// RFC 5280 section 4.2.1.4: CertificatePolicies.
const ExtPolicies = /* @__PURE__ */ (() => {
  const displayTextRaw = ASN1.choice({
    utf8: ASN1.UTF8String,
    ia5: ASN1.IA5String,
    visible: ASN1.VisibleString,
    bmp: ASN1.BMPString,
  });
  // RFC 5280 section 4.2.1.4 / Appendix A.1 defines every DisplayText arm as
  // SIZE (1..200). The stricter explicitText encoding profile is checked higher
  // in the UserNotice wrapper.
  const displayText = P.validate(displayTextRaw, (d) => {
    const len = Array.from(d.data).length;
    if (len < 1 || len > 200)
      throw new Error('DisplayText must contain 1..200 characters by RFC 5280 section 4.2.1.4');
    return d;
  });
  // RFC 5280 models noticeNumbers as a bare SEQUENCE OF INTEGER here, so this shell keeps the
  // raw organization-plus-number-list structure and leaves any notice-file semantics to callers.
  const policyNoticeRef = ASN1.sequence({
    organization: displayText,
    numbers: ASN1.sequence({ list: P.array(null, ASN1.Integer) }),
  });
  const userNotice = P.apply(
    ASN1.sequence({
      noticeRef: ASN1.optional(policyNoticeRef),
      // RFC 5280 section 4.2.1.4 makes explicitText a DisplayText value. It
      // forbids conforming CAs from generating VisibleString/BMPString here, but
      // does not require certificate users to reject them, and OpenSSL decodes
      // real-world vectors with VisibleString explicitText.
      explicitText: ASN1.optional(displayText),
    }),
    {
      encode: (n): PolicyUserNotice => ({
        noticeRef: n.noticeRef
          ? {
              organization: {
                tag: n.noticeRef.organization.TAG,
                text: n.noticeRef.organization.data,
              },
              // RFC 5280 section 4.2.1.4: NoticeReference.noticeNumbers are
              // ASN.1 INTEGER values, so decode preserves values outside the
              // JavaScript safe-number range instead of silently rounding them.
              numbers: n.noticeRef.numbers.list.map((v) => v),
            }
          : undefined,
        explicitText: n.explicitText
          ? { tag: n.explicitText.TAG, text: n.explicitText.data }
          : undefined,
      }),
      decode: (d: PolicyUserNotice) => ({
        noticeRef: d.noticeRef
          ? {
              organization: {
                TAG: d.noticeRef.organization.tag,
                data: d.noticeRef.organization.text,
              } as P.UnwrapCoder<typeof displayText>,
              numbers: {
                list: d.noticeRef.numbers.map((n) => {
                  if (typeof n === 'number' && !Number.isSafeInteger(n))
                    throw new Error('noticeNumbers number input must be a safe integer');
                  return BigInt(n);
                }),
              },
            }
          : undefined,
        explicitText: d.explicitText
          ? ({ TAG: d.explicitText.tag, data: d.explicitText.text } as P.UnwrapCoder<
              typeof displayText
            >)
          : undefined,
      }),
    }
  ) satisfies P.CoderType<PolicyUserNotice>;
  // RFC 5280 models PolicyQualifierInfo as `{ policyQualifierId, qualifier ANY DEFINED BY id }`,
  // so this raw shell keeps the OID plus one qualifier TLV and leaves OID-specific decoding to
  // the next wrapper.
  const raw = ASN1.sequence({ oid: ASN1.OID, value: ASN1.any });
  // This wrapper only gives typed views to the standard CPS/UserNotice qualifier rows; unknown
  // qualifier OIDs stay raw here so any policy-ID-specific restrictions can be enforced above it.
  const qualifier = P.apply(raw, {
    encode: (x: P.UnwrapCoder<typeof raw>): CertPolicyQualifier => {
      if (x.oid === 'idQtCps') return { TAG: 'cps', data: ASN1.IA5String.decode(x.value) };
      if (x.oid === 'idQtUnotice') return { TAG: 'userNotice', data: userNotice.decode(x.value) };
      return { TAG: 'unknown', data: { oid: x.oid, value: ASN1.TLVNode.decode(x.value) } };
    },
    decode: (q: CertPolicyQualifier): P.UnwrapCoder<typeof raw> => {
      if (q.TAG === 'unknown')
        return {
          oid: q.data.oid,
          value: ASN1.TLVNode.encode(q.data.value) as StrictBytes,
        };
      if (q.TAG === 'cps')
        return {
          oid: 'idQtCps',
          value: ASN1.IA5String.encode(q.data) as StrictBytes,
        };
      return {
        oid: 'idQtUnotice',
        value: userNotice.encode(q.data) as StrictBytes,
      };
    },
  }) satisfies P.CoderType<CertPolicyQualifier>;
  return P.validate(
    ASN1.sequence({
      list: P.array(
        null,
        ASN1.sequence({
          policy: ASN1.OID,
          qualifiers: ASN1.optional(ASN1.sequence({ list: P.array(null, qualifier) })),
        })
      ),
    }),
    (x) => {
      // RFC 5280 section 4.2.1.4: certificatePolicies and policyQualifiers are SIZE (1..MAX),
      // and a certificate policy OID must not appear more than once in one extension.
      if (!x.list.length)
        throw new Error('certificatePolicies must contain at least one PolicyInformation');
      const policies = new Set<string>();
      for (const p of x.list) {
        // RFC 5280 section 4.2.1.4: "A certificate policy OID MUST NOT appear more than once".
        if (policies.has(p.policy))
          throw new Error('certificatePolicies policyIdentifier must not appear more than once');
        policies.add(p.policy);
        if (p.qualifiers && !p.qualifiers.list.length)
          throw new Error(
            'policyQualifiers must contain at least one PolicyQualifierInfo when present'
          );
      }
      return x;
    }
  );
})() satisfies P.CoderType<{
  list: {
    policy: string;
    qualifiers: { list: CertPolicyQualifier[] } | undefined;
  }[];
}>;
// Raw GeneralSubtree shell only: preserve absent DEFAULT minimum and optional
// maximum here, then let NameConstraints apply the RFC 5280 profile rule that
// minimum stays 0 and maximum stays absent.
const ExtGeneralSubtree = /* @__PURE__ */ (() =>
  ASN1.sequence({
    base: ExtNameConstraintGeneralName,
    minimum: /* @__PURE__ */ ASN1.optional(/* @__PURE__ */ ASN1.implicit(0, ASN1.Integer)),
    maximum: /* @__PURE__ */ ASN1.optional(/* @__PURE__ */ ASN1.implicit(1, ASN1.Integer)),
  }))();
// RFC 5280 section 4.2.1.10: NameConstraints.
const ExtNameConstraints = /* @__PURE__ */ (() =>
  P.validate(
    ASN1.sequence({
      permitted: ASN1.optional(
        // RFC 5280 Appendix A PKIX1Implicit88 defines extension syntax under
        // IMPLICIT TAGS, so [0]/[1] replace the GeneralSubtrees SEQUENCE tag.
        ASN1.implicit(0, ASN1.sequence({ list: P.array(null, ExtGeneralSubtree) }))
      ),
      excluded: ASN1.optional(
        ASN1.implicit(1, ASN1.sequence({ list: P.array(null, ExtGeneralSubtree) }))
      ),
    }),
    (x) => {
      // RFC 5280 section 4.2.1.10: empty NameConstraints sequence is forbidden.
      if (!x.permitted && !x.excluded)
        throw new Error('nameConstraints must contain permittedSubtrees or excludedSubtrees');
      // RFC 5280 section 4.2.1.10: GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree.
      if (x.permitted && !x.permitted.list.length)
        throw new Error(
          'nameConstraints permittedSubtrees must contain at least one GeneralSubtree'
        );
      if (x.excluded && !x.excluded.list.length)
        throw new Error(
          'nameConstraints excludedSubtrees must contain at least one GeneralSubtree'
        );
      // RFC 5280 profile requirement: minimum MUST be 0 and maximum MUST be absent.
      const all = [...(x.permitted?.list || []), ...(x.excluded?.list || [])];
      for (const g of all) {
        if (g.maximum !== undefined)
          throw new Error(
            'nameConstraints GeneralSubtree.maximum is not supported by this profile'
          );
        if (g.minimum !== undefined && g.minimum !== _0n)
          throw new Error('nameConstraints GeneralSubtree.minimum must be 0 in this profile');
      }
      return x;
    }
  ))() satisfies P.CoderType<{
  permitted: { list: P.UnwrapCoder<typeof ExtGeneralSubtree>[] } | undefined;
  excluded: { list: P.UnwrapCoder<typeof ExtGeneralSubtree>[] } | undefined;
}>;
// Raw SubjectDirectoryAttributes shell only: keep the non-empty Attribute /
// AttributeValue lists here, while extension-level profile rules such as RFC
// 5280's non-critical recommendation stay above.
const ExtSubjectDirectoryAttributes = /* @__PURE__ */ (() =>
  P.validate(
    ASN1.sequence({
      list: P.array(
        null,
        ASN1.sequence({
          type: ASN1.OIDMap,
          values: ASN1.set(ASN1.AnyValue),
        })
      ),
    }),
    (x) => {
      // RFC 5280 section 4.2.1.8: SubjectDirectoryAttributes is
      // SEQUENCE SIZE (1..MAX) OF Attribute.
      if (!x.list.length)
        throw new Error('subjectDirectoryAttributes must contain at least one attribute');
      // Attribute syntax (X.501, used by RFC 5280) requires SET SIZE (1..MAX) OF AttributeValue.
      for (const a of x.list) {
        if (!a.values.length)
          throw new Error(
            'subjectDirectoryAttributes attribute values must contain at least one value'
          );
      }
      return x;
    }
  ))() satisfies P.CoderType<{ list: { type: string; values: CertAny[] }[] }>;
// RFC 5280 Appendix A keeps the inherited ISO syntax and says one of notBefore / notAfter MUST be
// present if this extension is encoded, even though the main profile body removed the old section.
const ExtPrivateKeyUsagePeriod = /* @__PURE__ */ (() =>
  P.validate(
    ASN1.sequence({
      notBefore: ASN1.optional(ASN1.implicit(0, ASN1.GeneralizedTime)),
      notAfter: ASN1.optional(ASN1.implicit(1, ASN1.GeneralizedTime)),
    }),
    (x) => {
      // RFC 5280 Appendix A: "either notBefore or notAfter MUST be present".
      if (x.notBefore === undefined && x.notAfter === undefined)
        throw new Error('privateKeyUsagePeriod must contain notBefore or notAfter');
      // RFC 5280 section 4.1.2.5.2: GeneralizedTime values are `YYYYMMDDHHMMSSZ`.
      if (x.notBefore !== undefined) X509Time.decode(ASN1.GeneralizedTime.encode(x.notBefore));
      if (x.notAfter !== undefined) X509Time.decode(ASN1.GeneralizedTime.encode(x.notAfter));
      return x;
    }
  ))();
// RFC 5280 section 5.2.5 forbids the empty sequence, allows at most one of the three scope booleans
// to be TRUE, and says conforming CRL issuers MUST keep onlyContainsAttributeCerts at FALSE.
const ExtIssuingDistributionPoint = /* @__PURE__ */ (() =>
  P.validate(
    ASN1.sequence({
      distributionPoint: ASN1.optional(ASN1.explicit(0, ExtDistributionPointName)),
      onlyContainsUserCerts: ASN1.optional(ASN1.implicit(1, ASN1.Boolean)),
      onlyContainsCACerts: ASN1.optional(ASN1.implicit(2, ASN1.Boolean)),
      onlySomeReasons: ASN1.optional(ASN1.implicit(3, ASN1.BitStringRaw)),
      indirectCRL: ASN1.optional(ASN1.implicit(4, ASN1.Boolean)),
      onlyContainsAttributeCerts: ASN1.optional(ASN1.implicit(5, ASN1.Boolean)),
    }),
    (x) => {
      if (x.onlyContainsAttributeCerts)
        throw new Error('issuingDistributionPoint onlyContainsAttributeCerts must be false');
      const scope =
        +!!x.onlyContainsUserCerts + +!!x.onlyContainsCACerts + +!!x.onlyContainsAttributeCerts;
      // RFC 5280 section 5.2.5: if all scope booleans are FALSE, either distributionPoint
      // or onlySomeReasons must be present; it also allows at most one scope boolean to be TRUE.
      if (scope > 1) throw new Error('issuingDistributionPoint must set at most one scope boolean');
      if (
        !x.distributionPoint &&
        !x.onlySomeReasons &&
        !x.onlyContainsUserCerts &&
        !x.onlyContainsCACerts &&
        !x.indirectCRL
      )
        throw new Error('issuingDistributionPoint must not be an empty sequence');
      return x;
    }
  ))();
// Raw PolicyMappings shell only: keep the issuer/subject OID pairs here, then let the checked
// wrapper below enforce RFC 5280's non-empty list and anyPolicy prohibition on the public path.
const ExtPolicyMappings = /* @__PURE__ */ (() =>
  ASN1.sequence({
    list: /* @__PURE__ */ P.array(
      null,
      /* @__PURE__ */ ASN1.sequence({
        issuerDomainPolicy: ASN1.OID,
        subjectDomainPolicy: ASN1.OID,
      })
    ),
  }))();
const ExtPolicyMappingsChecked = /* @__PURE__ */ (() =>
  P.validate(ExtPolicyMappings, (x) => {
    // RFC 5280 section 4.2.1.5: policyMappings is SIZE (1..MAX), and either side MUST NOT be anyPolicy.
    if (!x.list.length) throw new Error('policyMappings must contain at least one mapping');
    for (const m of x.list) {
      if (m.issuerDomainPolicy === 'anyPolicy' || m.subjectDomainPolicy === 'anyPolicy')
        throw new Error('policyMappings must not contain anyPolicy');
    }
    return x;
  }))() satisfies P.CoderType<{
  list: { issuerDomainPolicy: string; subjectDomainPolicy: string }[];
}>;
const ExtPolicyConstraints = /* @__PURE__ */ (() =>
  P.validate(
    ASN1.sequence({
      requireExplicitPolicy: ASN1.optional(ASN1.implicit(0, ASN1.Integer)),
      inhibitPolicyMapping: ASN1.optional(ASN1.implicit(1, ASN1.Integer)),
    }),
    (x) => {
      // RFC 5280 section 4.2.1.11: conforming CAs MUST NOT emit empty PolicyConstraints.
      if (x.requireExplicitPolicy === undefined && x.inhibitPolicyMapping === undefined)
        throw new Error(
          'policyConstraints must contain requireExplicitPolicy or inhibitPolicyMapping'
        );
      // RFC 5280 section 4.2.1.11 / ASN.1: both fields are SkipCerts ::= INTEGER (0..MAX).
      if (x.requireExplicitPolicy !== undefined && x.requireExplicitPolicy < _0n)
        throw new Error('policyConstraints requireExplicitPolicy must be >= 0');
      // RFC 5280 section 4.2.1.11 / ASN.1: both fields are SkipCerts ::= INTEGER (0..MAX).
      if (x.inhibitPolicyMapping !== undefined && x.inhibitPolicyMapping < _0n)
        throw new Error('policyConstraints inhibitPolicyMapping must be >= 0');
      return x;
    }
  ))() satisfies P.CoderType<{
  requireExplicitPolicy: bigint | undefined;
  inhibitPolicyMapping: bigint | undefined;
}>;
const ExtQCStatements = /* @__PURE__ */ (() =>
  // RFC 3739 leaves QCStatements open by statementId, so keep statementInfo generic here and
  // let higher layers decide whether a known statement OID needs stricter typed semantics.
  ASN1.sequence({
    list: P.array(
      null,
      ASN1.sequence({
        statementId: ASN1.OIDMap,
        statementInfo: /* @__PURE__ */ ASN1.optional(ASN1.AnyValue),
      })
    ),
  }))() satisfies P.CoderType<{
  list: { statementId: string; statementInfo: CertAny | undefined }[];
}>;
const ExtBody = /* @__PURE__ */ (() =>
  // Raw Extension body shell only: preserve the optional BOOLEAN DEFAULT FALSE here and let the
  // later extension decoder normalize an absent `critical` field to the public `false` boolean.
  ASN1.sequence({
    critical: ASN1.optional(ASN1.Boolean),
    extnValue: ASN1.OctetString,
  }))();
const ExtBasic = /* @__PURE__ */ (() =>
  P.validate(
    // Raw BasicConstraints body only: enforce the local cA/pathLenConstraint
    // coupling here, then let later certificate-level logic handle keyCertSign
    // coupling and criticality requirements.
    /* @__PURE__ */ ASN1.sequence({
      ca: /* @__PURE__ */ ASN1.optional(ASN1.Boolean),
      pathLen: /* @__PURE__ */ ASN1.optional(ASN1.Integer),
    }),
    (x) => {
      // RFC 5280 section 4.2.1.9: pathLenConstraint MUST be >= 0 and only meaningful with cA asserted.
      if (x.pathLen !== undefined && x.pathLen < _0n)
        throw new Error('basicConstraints pathLenConstraint must be >= 0');
      // RFC 5280 section 4.2.1.9: CAs MUST NOT include pathLenConstraint unless cA is asserted.
      if (x.pathLen !== undefined && !x.ca)
        throw new Error('basicConstraints pathLenConstraint requires cA=true');
      return x;
    }
  ))() satisfies P.CoderType<{ ca: boolean | undefined; pathLen: bigint | undefined }>;
const ExtEKU = /* @__PURE__ */ (() =>
  // `X509.extensions()` currently reaches this typed EKU coder only on decode;
  // raw certificate re-encode still preserves extension bytes from `ExtCodec`,
  // so friendly-name rows must stay synced.
  // RFC 5280 section 4.2.1.12: ExtKeyUsageSyntax is `SEQUENCE SIZE (1..MAX) OF KeyPurposeId`.
  extNonEmpty(
    /* @__PURE__ */ ASN1.sequence({
      list: /* @__PURE__ */ P.array(null, ASN1.OIDMap),
    }),
    'extendedKeyUsage',
    'KeyPurposeId'
  ))() satisfies P.CoderType<{ list: string[] }>;
const ExtKnownIDs = [
  'subjectKeyIdentifier',
  'basicConstraints',
  'keyUsage',
  'extendedKeyUsage',
  'subjectAltName',
  'authorityKeyIdentifier',
  'authorityInfoAccess',
  'proxyCertInfo',
  'tlsFeature',
  'sctList',
  'crlDistributionPoints',
  'certificatePolicies',
  'nameConstraints',
  'subjectDirectoryAttributes',
  'privateKeyUsagePeriod',
  'issuerAltName',
  'issuingDistributionPoint',
  'certificateIssuer',
  'policyMappings',
  'policyConstraints',
  'freshestCRL',
  'inhibitAnyPolicy',
  'qcStatements',
  'subjectInfoAccess',
  'msCertType',
] as const;
const KnownCriticalCert = /* @__PURE__ */ (() =>
  new Set<string>(
    ExtKnownIDs.filter((name) => {
      // RFC 5280 section 5.2.5 defines issuingDistributionPoint for CRLs, and
      // section 5.3.3 defines certificateIssuer for CRL entries; OpenSSL rejects
      // these as critical certificate extensions with "unhandled critical extension".
      return name !== 'issuingDistributionPoint' && name !== 'certificateIssuer';
    })
  ))();
const bitFlags = <T extends Record<string, number>>(
  bs: TArg<{ unused: number; bytes: Uint8Array }>,
  ix: T,
  name: string
): { [K in keyof T]: boolean } => {
  const bitsrc = bs as { unused: number; bytes: Uint8Array };
  if (bitsrc.unused > 7)
    throw new Error(`${name} BIT STRING invalid unused bits: ${bitsrc.unused}`);
  const bits = P.array(bitsrc.bytes.length * 8, P.bits(1)).decode(bitsrc.bytes);
  const used = bits.length - bitsrc.unused;
  const get = (i: number): boolean => (i < used ? !!bits[i] : false);
  const out: Partial<{ [K in keyof T]: boolean }> = {};
  for (const k in ix) out[k] = get(ix[k]);
  return out as { [K in keyof T]: boolean };
};
const keyUsageBits = (
  bs: TArg<{
    unused: number;
    bytes: Uint8Array;
  }>
): {
  digitalSignature: boolean;
  nonRepudiation: boolean;
  keyEncipherment: boolean;
  dataEncipherment: boolean;
  keyAgreement: boolean;
  keyCertSign: boolean;
  cRLSign: boolean;
  encipherOnly: boolean;
  decipherOnly: boolean;
} => {
  // RFC 5280 section 4.2.1.3 uses fixed KeyUsage BIT STRING numbering;
  // omitted trailing bits stay false.
  return bitFlags(
    bs,
    {
      digitalSignature: 0,
      nonRepudiation: 1,
      keyEncipherment: 2,
      dataEncipherment: 3,
      keyAgreement: 4,
      keyCertSign: 5,
      cRLSign: 6,
      encipherOnly: 7,
      decipherOnly: 8,
    },
    'KeyUsage'
  );
};
const ExtValueByOID = /* @__PURE__ */ (() =>
  P.mappedTag(ASN1.OID, {
    // This decode map includes a few CRL/CRL-entry OIDs for low-level inspection; the
    // certificate critical-extension allowlist above is intentionally narrower.
    ski: ['subjectKeyIdentifier', ASN1.OctetString],
    basic: ['basicConstraints', ExtBasic],
    keyUsage: ['keyUsage', ASN1.BitStringRaw],
    eku: ['extendedKeyUsage', ExtEKU],
    san: ['subjectAltName', ExtSAN],
    aki: ['authorityKeyIdentifier', ExtAKI],
    aia: ['authorityInfoAccess', ExtAIA],
    proxyCertInfo: ['proxyCertInfo', ExtProxyCertInfoChecked],
    tlsFeature: ['tlsFeature', ExtTLSFeature],
    sct: ['sctList', SCTListInner],
    crlDistributionPoints: ['crlDistributionPoints', ExtCRLDP],
    policies: ['certificatePolicies', ExtPolicies],
    nameConstraints: ['nameConstraints', ExtNameConstraints],
    subjectDirectoryAttributes: ['subjectDirectoryAttributes', ExtSubjectDirectoryAttributes],
    privateKeyUsagePeriod: ['privateKeyUsagePeriod', ExtPrivateKeyUsagePeriod],
    issuerAltName: ['issuerAltName', ExtIAN],
    issuingDistributionPoint: ['issuingDistributionPoint', ExtIssuingDistributionPoint],
    certificateIssuer: ['certificateIssuer', ExtGeneralNames],
    policyMappings: ['policyMappings', ExtPolicyMappingsChecked],
    policyConstraints: ['policyConstraints', ExtPolicyConstraints],
    freshestCRL: ['freshestCRL', ExtCRLDP],
    inhibitAnyPolicy: ['inhibitAnyPolicy', ASN1.Integer],
    qcStatements: ['qcStatements', ExtQCStatements],
    subjectInfoAccess: ['subjectInfoAccess', ExtSIA],
    msCertType: ['msCertType', ASN1.AnyValue],
  }))();
const extValueDecode = /* @__PURE__ */ (() => {
  const known = new Set<string>(ExtKnownIDs);
  return ((id: string, val: TArg<Uint8Array>) =>
    known.has(id)
      ? ExtValueByOID.decode(concatBytes(ASN1.OID.encode(id), val as Uint8Array))
      : undefined) as TRet<
    (id: string, val: Uint8Array) => P.UnwrapCoder<typeof ExtValueByOID> | undefined
  >;
})();

type X509Api = {
  decode: (der: Uint8Array, opts?: BEROpts) => Cert;
  encode: (cert: Cert) => Uint8Array;
  extensions: (cert: Cert) => CertExt[];
};
const X509Api: X509Api = /* @__PURE__ */ deepFreeze({
  // Public certificate wrapper: BER-normalized decode, raw DER re-encode, and
  // best-effort typed extension projection.
  decode: (der: TArg<Uint8Array>, opts: BEROpts = {}): Cert => {
    const cert = X509C.Certificate.decode(BER.view(der, opts).der);
    // RFC 5280 §4.1 defines Extension as critical BOOLEAN plus extnValue OCTET STRING;
    // raw X509.decode preserves extension bytes, so run that DER shell before returning.
    for (const e of cert.tbs.extensions?.list || []) {
      const body = ExtBody.inner.decode(e.rest);
      if (e.oid !== 'keyUsage') continue;
      // RFC 5280 §4.2.1.3 defines KeyUsage as a BIT STRING inside Extension.extnValue;
      // raw X509.decode preserves extension bytes, so enforce X.690 §11.2.1 here too.
      ASN1.BitStringRaw.decode(body.extnValue);
    }
    return cert;
  },
  encode: (cert: Cert): TRet<Uint8Array> => X509C.Certificate.encode(cert) as TRet<Uint8Array>,
  extensions: (cert: Cert): TRet<CertExt[]> => {
    const out: CertExt[] = [];
    for (const e of cert.tbs.extensions?.list || []) {
      const body = ExtBody.inner.decode(e.rest);
      const d: CertExt = { oid: e.oid, critical: !!body.critical };
      const k = extValueDecode(e.oid, body.extnValue);
      if (k) (d as Record<string, unknown>)[k.TAG] = k.data;
      out.push(d);
    }
    return out as TRet<CertExt[]>;
  },
});
/** X.509 certificate DER helpers. */
export const X509: TRet<X509Api> = X509Api as unknown as TRet<X509Api>;
// Collapse parsed extension state into the CA/pathLen/keyUsage/EKU summary shared by
// signer and issuer checks; purpose-specific validation still belongs to the callers.
const certInfo = (
  cert: Cert
): {
  isCA: boolean;
  pathLen?: bigint;
  keyUsage?: ReturnType<typeof keyUsageBits>;
  eku?: Set<string>;
  critical: string[];
} => {
  let isCA = false;
  let pathLen: bigint | undefined;
  let keyUsage: ReturnType<typeof keyUsageBits> | undefined;
  let eku: Set<string> | undefined;
  const critical: string[] = [];
  const exts = X509.extensions(cert);
  for (const e of exts) {
    if (e.critical) critical.push(e.oid);
    if (e.basic) {
      isCA = !!e.basic.ca;
      pathLen = e.basic.pathLen;
    }
    if (e.keyUsage) keyUsage = keyUsageBits(e.keyUsage);
    if (e.eku) eku = new Set(e.eku.list);
  }
  // RFC 5280 section 4.2.1.9: if cA is not asserted, keyCertSign MUST NOT be asserted.
  if (!isCA && keyUsage?.keyCertSign)
    throw new Error('keyUsage keyCertSign requires basicConstraints cA=true');
  return { isCA, pathLen, keyUsage, eku, critical };
};
// Exact DER form of the subject Name, kept for diagnostics and exact identity
// checks. RFC 5280 section 7.1 defines DN comparison through RFC 4518
// StringPrep for PrintableString/UTF8String DirectoryString values: RFC 4518
// sections 2.2/2.3/2.6.1 require mapping, NFKC, and insignificant-space
// handling, while RFC 5280 section 7.1 adds RFC 3454 Appendix B.2 case folding
// and says RDN SET members are unordered but RDN order is significant.
//
// This comparator covers:
// - exact DER equality
// - RFC 4518 map-to-space/drop characters; OpenSSL only maps ASCII spaces
// - NFKC; OpenSSL does not normalize UTF8 strings
// - JavaScript lowercasing; OpenSSL lowercases only ASCII bytes
// - RFC 4518 attribute-value space compression; OpenSSL compresses ASCII spaces to one SP
// - unordered attributes inside each RDN
// - raw ANY AttributeValue tags by exact TLV bytes; OpenSSL preserves unsupported entries
//
// Missing pieces:
// - full RFC 3454 Appendix B.2 case-fold table
// - RFC 4518 section 2.4 prohibited/unassigned Unicode 3.2 tables
// - per-AttributeType equality rules such as RFC 5280 section 7.3 domainComponent
const subjectDer = (cert: Cert): TRet<Uint8Array> =>
  X509C.Name.encode(cert.tbs.subject) as TRet<Uint8Array>;
const nameEqual = (a: NameCodec, b: NameCodec): boolean => {
  if (equalBytes(X509C.Name.encode(a), X509C.Name.encode(b))) return true;
  const key = (n: NameCodec): string =>
    JSON.stringify(
      n.rdns.map((rdn) =>
        rdn
          .map((attr) => {
            if (attr.value.TAG === 'raw')
              return JSON.stringify([
                attr.oid,
                `raw:${bytesToHex(ASN1.TLVNode.encode(attr.value.data))}`,
              ]);
            let mapped = '';
            for (const ch of attr.value.data) {
              const c = ch.codePointAt(0)!;
              // RFC 4518 section 2.2 maps these separators to U+0020 before NFKC.
              // Keep the RFC's closed list here; JS whitespace classes include extra chars.
              const space =
                c === 0x09 ||
                c === 0x0a ||
                c === 0x0b ||
                c === 0x0c ||
                c === 0x0d ||
                c === 0x20 ||
                c === 0x85 ||
                c === 0xa0 ||
                c === 0x1680 ||
                (c >= 0x2000 && c <= 0x200a) ||
                c === 0x2028 ||
                c === 0x2029 ||
                c === 0x202f ||
                c === 0x205f ||
                c === 0x3000;
              if (space) {
                mapped += ' ';
                continue;
              }
              // RFC 4518 section 2.2 maps ignorable/control-function chars to nothing.
              // The first clauses mirror RFC 3454 Appendix B.1 values named by RFC 4518;
              // the later clauses are RFC 4518's complete control-function list.
              const drop =
                c === 0x00ad ||
                c === 0x034f ||
                c === 0x1806 ||
                (c >= 0x180b && c <= 0x180e) ||
                (c >= 0x200b && c <= 0x200f) ||
                (c >= 0x202a && c <= 0x202e) ||
                (c >= 0x2060 && c <= 0x206f) ||
                (c >= 0xfe00 && c <= 0xfe0f) ||
                c === 0xfeff ||
                (c >= 0xfff9 && c <= 0xfffc) ||
                (c >= 0x1d173 && c <= 0x1d17a) ||
                c === 0xe0001 ||
                (c >= 0xe0020 && c <= 0xe007f) ||
                (c >= 0x00 && c <= 0x08) ||
                (c >= 0x0e && c <= 0x1f) ||
                (c >= 0x7f && c <= 0x84) ||
                (c >= 0x86 && c <= 0x9f) ||
                c === 0x06dd ||
                c === 0x070f;
              // This is comparison canonicalization only; RFC 4518 section 2.4
              // prohibited/unassigned enforcement is intentionally still missing above.
              if (!drop) mapped += ch;
            }
            const folded = mapped.toLowerCase().normalize('NFKC');
            const parts = folded.split(' ').filter((p) => p.length);
            return JSON.stringify([
              attr.oid,
              `text:${parts.length ? ` ${parts.join('  ')} ` : '  '}`,
            ]);
          })
          .sort()
      )
    );
  return key(a) === key(b);
};
const ensureCritical = (c: Cert): void => {
  // RFC 5280 section 4.2: unrecognized critical extensions require certificate rejection.
  for (const id of certInfo(c).critical) {
    if (!KnownCriticalCert.has(id)) throw new Error(`unknown critical extension ${id}`);
  }
};

const checkSignerInfoShape = (signerInfo: TArg<SignerInfoCodec>): void => {
  const info = signerInfo as SignerInfoCodec;
  // RFC 5652 section 10.2.5: CMSVersion is v0..v5.
  if (info.version < _0n || info.version > _5n)
    throw new Error(`SignerInfo.version CMSVersion must be in v0..v5, got ${info.version}`);
  // RFC 5652 section 5.3: SignedAttributes/UnsignedAttributes are SET SIZE (1..MAX) OF Attribute.
  if (info.signedAttrs && info.signedAttrs.length === 0)
    throw new Error('SignedAttributes present but empty');
  if (info.unsignedAttrs && info.unsignedAttrs.length === 0)
    throw new Error('UnsignedAttributes present but empty');
  // RFC 5652 section 5.3: SignerInfo.version is coupled to SignerIdentifier choice.
  // issuerAndSerialNumber => version 1, subjectKeyIdentifier => version 3.
  if (info.sid.TAG === 'issuerSerial' && info.version !== _1n)
    throw new Error(`SignerInfo.version must be 1 for issuerSerial SID, got ${info.version}`);
  if (info.sid.TAG === 'subjectKeyIdentifier') {
    if (!info.sid.data.length)
      throw new Error('SignerInfo.sid subjectKeyIdentifier must be non-empty');
    if (info.version !== _3n)
      throw new Error(
        `SignerInfo.version must be 3 for subjectKeyIdentifier SID, got ${info.version}`
      );
  }
};

// Strict CMS SignedData parser: decode ContentInfo->SignedData and enforce the
// version/content invariants this API relies on before higher-level checks run.
const cmsSignedData = (
  src: TArg<Uint8Array>
): {
  contentInfo: P.UnwrapCoder<typeof CMSX.ContentInfo>;
  signedData: P.UnwrapCoder<typeof CMSX.SignedData>;
} => {
  const contentInfo = CMSX.ContentInfo.decode(src as Uint8Array);
  // RFC 5652 section 3: contentType identifies the associated [0] EXPLICIT content payload type.
  // RFC 5652 sections 10.2.6 (UserKeyingMaterial/UKM) and 10.2.7 (OtherKeyAttribute)
  // apply to recipient/key-management flows under EnvelopedData, which are intentionally
  // unsupported in this signed-data-only API.
  if (contentInfo.contentType !== 'signedData')
    throw new Error(`expected SignedData contentType, got ${contentInfo.contentType}`);
  // RFC 5652 section 5.2.1: PKCS #7 compatibility fallback to `content ANY` is MAY, not MUST.
  // This implementation is strict CMS-only and intentionally does not attempt PKCS #7 ANY fallback decode.
  const signedData = CMSX.SignedData.decode(contentInfo.content);
  // RFC 5652 section 10.2.5: CMSVersion ::= INTEGER { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }.
  const badSignedVersion = signedData.version < _0n || signedData.version > _5n;
  if (badSignedVersion)
    throw new Error(`SignedData.version CMSVersion must be in v0..v5, got ${signedData.version}`);
  for (const si of signedData.signerInfos) checkSignerInfoShape(si);
  // RFC 5652 section 5.1: SignedData.version depends on cert/crl choices, signer versions, and eContentType.
  const signedDataVersion = (() => {
    const certs = signedData.certificates || [];
    const crls = signedData.crls || [];
    if (certs.some((i) => i.TAG === 'other') || crls.some((i) => i.TAG === 'other')) return _5n;
    if (certs.some((i) => i.TAG === 'v2AttrCert')) return _4n;
    if (
      certs.some((i) => i.TAG === 'v1AttrCert') ||
      signedData.signerInfos.some((i) => i.version === _3n) ||
      signedData.encapContentInfo.eContentType !== 'data'
    )
      return _3n;
    return _1n;
  })();
  if (signedData.version !== signedDataVersion)
    throw new Error(`SignedData.version must be ${signedDataVersion}, got ${signedData.version}`);
  // RFC 5652 section 5.3: signedAttrs MUST be present when encapContentInfo.eContentType is not id-data.
  if (signedData.encapContentInfo.eContentType !== 'data') {
    for (const signerInfo of signedData.signerInfos) {
      if (!signerInfo.signedAttrs)
        throw new Error('SignerInfo.signedAttrs must be present when eContentType is not id-data');
    }
  }
  for (const signerInfo of signedData.signerInfos) {
    for (const attr of signerInfo.signedAttrs || []) {
      // RFC 8551 section 2.5.2: sMIMECapabilities Attribute MUST include only
      // one AttributeValue; OpenSSL 3.5.4 accepts but does not generate duplicates.
      if (attr.oid === 'attrSMIMECapabilities' && attr.values.length !== 1)
        throw new Error(
          `sMIMECapabilities attribute must have exactly one value, got ${attr.values.length}`
        );
    }
  }
  // RFC 5652 section 5.1: digestAlgorithms is the collection of digest algorithm identifiers for SignerInfos.
  for (const signerInfo of signedData.signerInfos) {
    const digest = signedData.digestAlgorithms.find((d) => digestAlgEqual(d, signerInfo.digestAlg));
    if (!digest)
      throw new Error('SignedData.digestAlgorithms must include each SignerInfo.digestAlgorithm');
  }
  // RFC 5652 section 5.2: degenerate SignedData (no signers) MUST be id-data with omitted eContent.
  if (
    signedData.signerInfos.length === 0 &&
    (signedData.encapContentInfo.eContentType !== 'data' || signedData.encapContentInfo.eContent)
  )
    throw new Error('degenerate SignedData must use id-data and omit eContent');
  return { contentInfo, signedData };
};
const cmsCerts = (signedData: P.UnwrapCoder<typeof CMSX.SignedData>): Cert[] => {
  const certs: Cert[] = [];
  for (const i of signedData.certificates || []) {
    // RFC 5652 section 12.2: v1AttrCert is accepted at ASN.1 layer but unsupported for signer-cert resolution.
    if (i.TAG !== 'certificate') continue;
    certs.push(i.data as Cert);
  }
  return certs;
};
const cmsSignerInfo = (
  signedData: P.UnwrapCoder<typeof CMSX.SignedData>
): P.UnwrapCoder<typeof CMSX.SignerInfo> => {
  // RFC 5652 section 5.1 allows SET OF SignerInfo; this API profile is single-signer only.
  // Exported CMS.verify currently returns one signer result and rejects multi-signer SignedData
  // here instead of selecting or returning multiple verified signers.
  if (signedData.signerInfos.length !== 1)
    throw new Error(
      `this API supports exactly one SignerInfo, got ${signedData.signerInfos.length}`
    );
  // RFC 5652 section 5.3: SignerInfo.version is coupled to SignerIdentifier choice.
  // issuerAndSerialNumber => version 1, subjectKeyIdentifier => version 3.
  const signerInfo = signedData.signerInfos[0];
  if (!signerInfo) throw new Error('SignerInfo[0] missing');
  checkSignerInfoShape(signerInfo);
  return signerInfo;
};
const cmsVerifyEc = (der: TArg<Uint8Array>, opts: TArg<CmsVerifyOpts> = {}): CmsVerify => {
  const cfg = opts as CmsVerifyOpts;
  // RFC 5280 section 6 support profile in this verifier:
  // - implemented subset: validity windows, issuer chaining, basic constraints, key usage, AKI/SKI linkage,
  //   critical-extension handling, and (when checkSignatures=true) certificate-signature continuity checks.
  // - not implemented: full policy-tree processing and full name-constraints path processing.
  //   those controls are fail-closed when present (see checkCoreCertFields).
  const verifyIssuedCert = (child: Cert, issuer: Cert): void => {
    // RFC 5280 section 6.1.3(a)(1): verify each cert signature with issuer public key.
    // RFC 8017 Appendix A.2 defines RSA PKCS #1 signature OIDs for X.509/PKCS #7,
    // but this package intentionally does not implement RSA; RSA-issued chains fail closed.
    const key = certSpkiKey(issuer.tbs.spki);
    const msg = X509C.TBSCertificate.encode(child.tbs);
    const sigOid = oidName.decode(oidName.encode(child.sigAlg.algorithm));
    const alg = CMS_ALG_BY_SIG_OID[sigOid as CmsAlg['sigOid']];
    if (!alg) throw new Error(`unsupported certificate signatureAlgorithm OID ${sigOid}`);
    if (key.algorithm.info.TAG === 'EC') {
      if (!('ec' in alg))
        throw new Error(
          `certificate signatureAlgorithm OID ${sigOid} is not compatible with EC issuer key`
        );
      if (child.sigAlg.params && sigOid.startsWith('ecdsa-with-'))
        throw new Error('ECDSA certificate signatureAlgorithm params must be absent');
      const curve = spkiCurve(key);
      if (!isSignCurve(curve))
        throw new Error(`unsupported issuer curve ${curve} for certificate signature verification`);
      if (!ecdsaVerifyDer(curve, child.sig, alg.hash(msg), key.publicKey))
        throw new Error('certificate signature invalid');
      return;
    }
    if (key.algorithm.info.TAG === 'Ed25519' || key.algorithm.info.TAG === 'Ed448') {
      if (!('ed' in alg) || CMS_ALG[key.algorithm.info.TAG].sigOid !== sigOid)
        throw new Error(
          `certificate signatureAlgorithm OID ${sigOid} is not compatible with issuer key`
        );
      if (!CMS_ALG[key.algorithm.info.TAG].ed.verify(child.sig, msg, key.publicKey))
        throw new Error('certificate signature invalid');
      return;
    }
    throw new Error(
      `unsupported issuer key algorithm ${key.algorithm.info.TAG} for certificate signature verification`
    );
  };
  const checkCoreCertFields = (cert: Cert, where: string): void => {
    // RFC 5280 section 4.1.2.1: version values are v1(0), v2(1), v3(2); absent field means v1.
    const v = cert.tbs.version === undefined ? _0n : cert.tbs.version;
    if (v < _0n || v > _2n) throw new Error(`${where}: certificate version must be 0..2, got ${v}`);
    // RFC 5280 section 4.1.2.8: issuer/subject unique identifiers MUST NOT appear in v1 certificates.
    if (v === _0n && (cert.tbs.issuerUniqueID || cert.tbs.subjectUniqueID))
      throw new Error(`${where}: certificate unique identifiers require version v2 or v3`);
    // RFC 5280 section 4.1 / 4.1.2.1: TBSCertificate.extensions [3] is only valid for v3 certificates.
    if (v < _2n && cert.tbs.extensions)
      throw new Error(`${where}: certificate extensions require version v3`);
    // RFC 5280 section 4.1.2.2: certificate serialNumber MUST be a positive INTEGER.
    if (cert.tbs.serial <= _0n)
      throw new Error(`${where}: certificate serialNumber must be positive`);
    // RFC 5280 section 4.1.2.2: conforming CAs MUST NOT use serialNumber values longer than 20 octets.
    const serialBytes = ASN1.Integer.inner.encode(cert.tbs.serial).length;
    if (serialBytes > 20)
      throw new Error(`${where}: certificate serialNumber must be <= 20 octets`);
    // RFC 5280 section 4.1.2.4: issuer field MUST contain a non-empty distinguished name.
    if (!cert.tbs.issuer.rdns.length || cert.tbs.issuer.rdns.some((rdn) => rdn.length === 0))
      throw new Error(`${where}: certificate issuer distinguished name must be non-empty`);
    // RFC 5280 section 4.1.2.6: subject field is either a non-empty DN, or an empty DN only
    // when subjectAltName is present and marked critical (section 4.2.1.6).
    if (cert.tbs.subject.rdns.some((rdn) => rdn.length === 0))
      throw new Error(
        `${where}: certificate subject distinguished name must not contain empty RDNs`
      );
    // RFC 5280 sections 4.1.1.2 and 4.1.2.3: Certificate.signatureAlgorithm MUST match TBSCertificate.signature.
    if (
      !equalBytes(
        ASN1.AlgorithmIdentifier.encode(cert.tbs.signature),
        ASN1.AlgorithmIdentifier.encode(cert.sigAlg)
      )
    )
      throw new Error(
        `${where}: certificate signatureAlgorithm must match tbsCertificate.signature`
      );
    // RFC 5280 section 4.1.1.3: signatureValue is the certificate signature BIT STRING and must be non-empty.
    if (!cert.sig.length) throw new Error(`${where}: certificate signatureValue must be non-empty`);
    // RFC 5280 section 4.1.2.7: SubjectPublicKeyInfo MUST carry a subjectPublicKey BIT STRING.
    if (!cert.tbs.spki.publicKey.length)
      throw new Error(`${where}: certificate SubjectPublicKeyInfo.publicKey must be non-empty`);
    // RFC 5280 section 4.1.2.5: validity period is [notBefore, notAfter], so notAfter MUST NOT precede notBefore.
    if (timeEpoch(cert.tbs.validity.notAfter) < timeEpoch(cert.tbs.validity.notBefore))
      throw new Error(`${where}: certificate validity notAfter must be >= notBefore`);
    // RFC 5280 section 4.2.1.2: SubjectKeyIdentifier identifies the cert's public key; empty SKI is invalid.
    // Extension-profile checks below are the verify-time gate for RFC 5280
    // certificate acceptance rules that are not already enforced by the typed
    // extension decoders themselves.
    const exts = X509.extensions(cert);
    // RFC 5280 section 4.2: a certificate MUST NOT include more than one instance of a particular extension.
    const seenExt = new Set<string>();
    for (const e of exts) {
      if (seenExt.has(e.oid))
        throw new Error(`${where}: certificate contains duplicate extension ${e.oid}`);
      seenExt.add(e.oid);
    }
    if (!cert.tbs.subject.rdns.length) {
      const san = exts.find((e) => e.san);
      if (!san || !san.critical)
        throw new Error(`${where}: empty subject requires critical subjectAltName extension`);
    }
    const ski = exts.find((e) => e.ski)?.ski;
    if (ski && !ski.length)
      throw new Error(`${where}: certificate subjectKeyIdentifier must be non-empty`);
    const proxyExt = exts.find((e) => e.proxyCertInfo);
    if (proxyExt) {
      // RFC 3820 section 3.8: proxyCertInfo extension MUST be critical.
      if (!proxyExt.critical) throw new Error(`${where}: proxyCertInfo extension must be critical`);
      // RFC 3820 section 3.7: proxy certificate basicConstraints cA MUST NOT be TRUE.
      const isCA = !!exts.find((e) => e.basic)?.basic?.ca;
      if (isCA) throw new Error(`${where}: proxy certificate basicConstraints cA MUST NOT be TRUE`);
    }
    // RFC 5280 section 4.2.1.15: freshestCRL extension MUST be non-critical.
    const freshest = exts.find((e) => e.freshestCRL);
    if (freshest?.critical) throw new Error(`${where}: freshestCRL extension must be non-critical`);
    // RFC 5280 section 4.2.2.1: authorityInfoAccess extension MUST be non-critical.
    const aia = exts.find((e) => e.aia);
    if (aia?.critical)
      throw new Error(`${where}: authorityInfoAccess extension must be non-critical`);
    // RFC 5280 section 4.2.2.2: subjectInfoAccess extension MUST be non-critical.
    const sia = exts.find((e) => e.subjectInfoAccess);
    if (sia?.critical)
      throw new Error(`${where}: subjectInfoAccess extension must be non-critical`);
    // RFC 5280 sections 4.2.1.10 / 4.2.1.11 / 4.2.1.14: these path-processing extensions MUST be critical.
    const nc = exts.find((e) => e.nameConstraints);
    if (nc && !nc.critical) throw new Error(`${where}: nameConstraints extension must be critical`);
    const pc = exts.find((e) => e.policyConstraints);
    if (pc && !pc.critical)
      throw new Error(`${where}: policyConstraints extension must be critical`);
    const iap = exts.find((e) => e.oid === 'inhibitAnyPolicy');
    if (iap && !iap.critical)
      throw new Error(`${where}: inhibitAnyPolicy extension must be critical`);
    // RFC 5280 section 6 policy/name processing (policy tree + name constraints checks) is not implemented in this verifier.
    const pm = exts.find((e) => e.policyMappings);
    if (nc || pc || iap || pm)
      throw new Error(
        `${where}: nameConstraints/policyMappings/policyConstraints/inhibitAnyPolicy present but RFC 5280 section 6 processing is not implemented`
      );
  };
  const { checkSignatures = true } = cfg;
  const { signedData } = cmsSignedData(BER.view(der, cfg).der);
  const certs = cmsCerts(signedData).map((c) => X509.decode(X509C.Certificate.encode(c), cfg));
  const signerInfo = cmsSignerInfo(signedData);
  const signerOid = oidName.decode(oidName.encode(signerInfo.signatureAlg.algorithm));
  const signerKind =
    signerOid === CMS_ALG.Ed25519.sigOid
      ? 'Ed25519'
      : signerOid === CMS_ALG.Ed448.sigOid
        ? 'Ed448'
        : undefined;
  const hasSignedAttrs = !!signerInfo.signedAttrs;
  // RFC 8419 sections 3.1/3.2 EdDSA digestAlgorithm constraints are validation
  // profile checks, not structural CMS decode checks; keep CMS.signed() able to
  // inspect nonconforming OpenSSL-forced output, but reject it here.
  checkEdDigestParams(signerKind, signerInfo.digestAlg, 'SignerInfo', hasSignedAttrs);
  const signerDigest = signedData.digestAlgorithms.find((d) =>
    digestAlgEqual(d, signerInfo.digestAlg)
  );
  if (!signerDigest)
    throw new Error('SignedData.digestAlgorithms must include each SignerInfo.digestAlgorithm');
  checkEdDigestParams(signerKind, signerDigest, 'SignedData.digestAlgorithms', hasSignedAttrs);
  const chainSrc = cfg.chain || [];
  const chainItems = chainSrc.map((c) => {
    if (typeof c === 'string') return X509.decode(onePem(c, 'CERTIFICATE').der, cfg);
    if (isBytes(c)) return X509.decode(c, cfg);
    return X509.decode(X509C.Certificate.encode(c), cfg);
  });
  // RFC 5652 section 5.1 makes CertificateSet optional, and says the signer's
  // certificate MAY be included; use opts.chain as the alternate signer source.
  const oneMatch = (
    items: Cert[],
    test: (c: Cert) => boolean,
    msg:
      | 'SignerInfo.sid issuerSerial matched multiple certificates'
      | 'SignerInfo.sid subjectKeyIdentifier matched multiple certificates'
  ): Cert | undefined => {
    const matches = items.filter(test);
    if (matches.length > 1) throw new Error(msg);
    return matches[0];
  };
  const signerMatch = (
    test: (c: Cert) => boolean,
    msg:
      | 'SignerInfo.sid issuerSerial matched multiple certificates'
      | 'SignerInfo.sid subjectKeyIdentifier matched multiple certificates'
  ): Cert | undefined => {
    const a = oneMatch(certs, test, msg);
    const b = oneMatch(chainItems, test, msg);
    // RFC 5652 section 5.3 identifies an X.509 signer certificate by
    // issuerAndSerialNumber or subjectKeyIdentifier. Exact DER duplicates across
    // the CMS CertificateSet and opts.chain are the same cert; distinct matches
    // with the same identifier are ambiguous and fail closed.
    if (a && b && !equalBytes(X509C.Certificate.encode(a), X509C.Certificate.encode(b)))
      throw new Error(msg);
    return a || b;
  };
  const signerCert = (() => {
    const sid = signerInfo.sid;
    if (sid.TAG === 'issuerSerial') {
      const test = (c: Cert): boolean => {
        return nameEqual(sid.data.issuer, c.tbs.issuer) && sid.data.serial === c.tbs.serial;
      };
      return signerMatch(test, 'SignerInfo.sid issuerSerial matched multiple certificates');
    }
    const test = (c: Cert): boolean => {
      const ski = X509.extensions(c).find((e) => e.ski)?.ski;
      return ski ? equalBytes(ski, sid.data) : false;
    };
    return signerMatch(test, 'SignerInfo.sid subjectKeyIdentifier matched multiple certificates');
  })();
  if (!signerCert) throw new Error('SignerInfo cert not found in certificate set or opts.chain');
  checkCoreCertFields(signerCert, 'signer');
  const nowMs = cfg.time === undefined ? Date.now() : cfg.time;
  if (!Number.isSafeInteger(nowMs))
    throw new Error(`expected safe integer time in milliseconds, got ${nowMs}`);
  const now = Math.floor(nowMs / 1000);
  if (
    now < timeEpoch(signerCert.tbs.validity.notBefore) ||
    now > timeEpoch(signerCert.tbs.validity.notAfter)
  )
    // RFC 5280 section 6.1.3(a)(2): certificate validity period must include validation time.
    throw new Error('signer certificate outside validity window');
  const signerCertInfo = certInfo(signerCert);
  // RFC 5280 section 4.2.1.9 cA=true only controls certificate-signature use; section 4.2.1.3
  // explicitly allows digitalSignature/nonRepudiation together with keyCertSign for other objects.
  // RFC 5750 section 4.4.2: S/MIME message signatures require digitalSignature or nonRepudiation
  // when keyUsage is present, so do not reject CA signer certs solely because cA is asserted.
  if (
    signerCertInfo.keyUsage &&
    !signerCertInfo.keyUsage.digitalSignature &&
    !signerCertInfo.keyUsage.nonRepudiation
  )
    throw new Error('signer keyUsage missing digitalSignature or nonRepudiation');
  const purpose = cfg.purpose || 'any';
  const eku = signerCertInfo.eku;
  // RFC 5280 section 4.2.1.12: if EKU is present, certificate use is constrained to listed purposes
  // (except anyExtendedKeyUsage).
  if (eku && purpose !== 'any' && !eku.has('anyExtendedKeyUsage')) {
    if (purpose === 'smime' && !eku.has('emailProtection'))
      throw new Error('EKU missing emailProtection');
    if (purpose === 'codeSigning' && !eku.has('codeSigning'))
      throw new Error('EKU missing codeSigning');
  }
  ensureCritical(signerCert);
  const pool = [...certs, ...chainItems].filter(
    (c) =>
      !(equalBytes(subjectDer(c), subjectDer(signerCert)) && c.tbs.serial === signerCert.tbs.serial)
  );
  for (const c of pool) ensureCritical(c);
  const seen = new Set<string>();
  const chain: Cert[] = [signerCert];
  let cur = signerCert;
  while (true) {
    const id = `${base64.encode(subjectDer(cur))}:${cur.tbs.serial.toString(16)}`;
    if (seen.has(id)) throw new Error('certificate chain loop detected');
    seen.add(id);
    const curDer = X509C.Certificate.encode(cur);
    const curSubject = subjectDer(cur);
    if (now < timeEpoch(cur.tbs.validity.notBefore) || now > timeEpoch(cur.tbs.validity.notAfter))
      // RFC 5280 section 6.1.3(a)(2): each certificate in the path must be valid at validation time.
      throw new Error(`certificate not valid at time: ${base64.encode(curSubject)}`);
    const curExts = X509.extensions(cur);
    const curAki = curExts.find((e) => e.aki)?.aki;
    const selfIssued = nameEqual(cur.tbs.issuer, cur.tbs.subject);
    if (checkSignatures && selfIssued) {
      try {
        // RFC 5280 section 3.2: self-signed is the self-issued terminal case
        // whose signature verifies with its own public key.
        verifyIssuedCert(cur, cur);
        break;
      } catch {}
    }
    const candidatesAll = pool.filter(
      (i) =>
        !equalBytes(X509C.Certificate.encode(i), curDer) && nameEqual(cur.tbs.issuer, i.tbs.subject)
    );
    const candidates = (() => {
      const out: Cert[] = [];
      const seenIssuer = new Set<string>();
      for (const c of candidatesAll) {
        // Keep near-duplicates distinct for ambiguity checks; only collapse exact DER duplicates.
        const key = base64.encode(X509C.Certificate.encode(c));
        if (seenIssuer.has(key)) continue;
        seenIssuer.add(key);
        out.push(c);
      }
      return out;
    })();
    if (!candidates.length) {
      // RFC 5280 section 6.1 path validation is anchored in trust anchors supplied by relying party.
      // Without supplied anchors (common in browser/wasm contexts), return best-effort partial chain.
      // RFC 5280 sections 3.2 and 6.1.4(l)/(m): self-issued intermediates are processed in
      // the path; issuer==subject terminates only after no separate parent candidate remains.
      if (!checkSignatures || !chainItems.length || selfIssued) break;
      if (chain.length === 1) throw new Error('no issuer found for signer in chain');
      throw new Error(`no issuer found in chain for certificate at depth ${chain.length}`);
    }
    const akiState = (
      issuer: Cert
    ): {
      keyIdentifierOk: boolean;
      authorityCertIssuerOk: boolean;
      authorityCertSerialOk: boolean;
    } => {
      if (!curAki)
        return { keyIdentifierOk: true, authorityCertIssuerOk: true, authorityCertSerialOk: true };
      let keyIdentifierOk = true;
      if (curAki.keyIdentifier) {
        const issuerSki = X509.extensions(issuer).find((e) => e.ski)?.ski;
        keyIdentifierOk = !issuerSki || equalBytes(curAki.keyIdentifier, issuerSki);
      }
      let authorityCertIssuerOk = true;
      if (curAki.authorityCertIssuer) {
        const names = curAki.authorityCertIssuer.list.filter((n) => n.TAG === 'directoryName');
        if (names.length)
          authorityCertIssuerOk = names.some((n) => nameEqual(n.data, issuer.tbs.subject));
      }
      const authorityCertSerialOk =
        curAki.authorityCertSerialNumber === undefined ||
        curAki.authorityCertSerialNumber === issuer.tbs.serial;
      return { keyIdentifierOk, authorityCertIssuerOk, authorityCertSerialOk };
    };
    let issuer = candidates[0];
    if (candidates.length > 1) {
      const akiMatches = curAki
        ? candidates.filter((i) => {
            const a = akiState(i);
            return a.keyIdentifierOk && a.authorityCertIssuerOk && a.authorityCertSerialOk;
          })
        : [];
      if (akiMatches.length === 1) issuer = akiMatches[0];
      else {
        if (!checkSignatures) {
          const msg =
            akiMatches.length > 1
              ? `multiple issuer certificates match authorityKeyIdentifier at depth ${chain.length}`
              : `multiple issuer certificates found for certificate at depth ${chain.length}`;
          throw new Error(msg);
        }
        const sigPool = akiMatches.length > 1 ? akiMatches : candidates;
        const sigMatches: Cert[] = [];
        for (const i of sigPool) {
          try {
            verifyIssuedCert(cur, i);
            sigMatches.push(i);
          } catch {}
        }
        if (sigMatches.length === 1) issuer = sigMatches[0];
        else if (sigMatches.length > 1)
          throw new Error(
            `multiple issuer certificates have valid signatures for certificate at depth ${chain.length}`
          );
        else {
          if (chain.length === 1) throw new Error('no issuer found for signer in chain');
          throw new Error(`no issuer found in chain for certificate at depth ${chain.length}`);
        }
      }
    }
    const issuerInfo = certInfo(issuer);
    checkCoreCertFields(issuer, 'issuer');
    // RFC 5280 section 4.2.1.1: when AKI fields are present in child cert, they identify the issuer cert.
    const aki = akiState(issuer);
    if (!aki.keyIdentifierOk)
      throw new Error(
        'authorityKeyIdentifier keyIdentifier does not match issuer subjectKeyIdentifier'
      );
    if (curAki?.authorityCertIssuer && !aki.authorityCertIssuerOk) {
      // RFC 5280 section 4.2.1.1: authorityCertIssuer/authorityCertSerialNumber, when present,
      // identify the CA certificate that contains the keyIdentifier.
      throw new Error('authorityKeyIdentifier authorityCertIssuer does not match issuer subject');
    }
    // RFC 5280 section 4.2.1.1: authorityCertSerialNumber identifies the same issuer certificate.
    if (!aki.authorityCertSerialOk)
      throw new Error(
        'authorityKeyIdentifier authorityCertSerialNumber does not match issuer serial'
      );
    // RFC 5280 section 4.2.1.9: certificate-signing issuer must be a CA (basicConstraints cA asserted).
    if (!issuerInfo.isCA) throw new Error('issuer certificate is not CA');
    // RFC 5280 section 4.2.1.9 makes critical basicConstraints a conforming-CA
    // generation requirement; path validation in section 6.1.4(k) only requires
    // the extension to be present with cA asserted, so verifiers accept it here.
    // RFC 5280 section 4.2.1.3: CA cert used to issue certs must allow keyCertSign.
    if (issuerInfo.keyUsage && !issuerInfo.keyUsage.keyCertSign)
      throw new Error('issuer keyUsage missing keyCertSign');
    // RFC 5280 section 4.2.1.9: the final certificate is not an intermediate
    // and is not included in pathLenConstraint even when it is a CA certificate.
    // RFC 5280 section 6.1.4(l)/(m): count only non-self-issued CA intermediates.
    const pathLenUsed = chain.reduce((acc, c, i) => {
      if (i === 0) return acc;
      const isCA = certInfo(c).isCA;
      const selfIssued = nameEqual(c.tbs.issuer, c.tbs.subject);
      return isCA && !selfIssued ? acc + _1n : acc;
    }, _0n);
    if (issuerInfo.pathLen !== undefined && pathLenUsed > issuerInfo.pathLen)
      throw new Error('issuer pathLenConstraint exceeded');
    if (checkSignatures) verifyIssuedCert(cur, issuer);
    chain.push(issuer);
    cur = issuer;
  }
  if (checkSignatures && chainItems.length) {
    // RFC 5280 section 6 path validation is anchored in trust anchors supplied by the relying party.
    const end = chain[chain.length - 1];
    const endDer = X509C.Certificate.encode(end);
    const trusted = chainItems.some((a) => equalBytes(X509C.Certificate.encode(a), endDer));
    // RFC 5280 section 6.1: validated path is rooted at an input trust anchor.
    if (!trusted)
      throw new Error('certificate chain does not terminate at a supplied trust anchor');
  }
  const out = {
    signatureOid: oidName.decode(oidName.encode(signerInfo.signatureAlg.algorithm)),
    signer: signerCert,
    signedAttrs: !!signerInfo.signedAttrs,
    chain,
  };
  const key = certSpkiKey(out.signer.tbs.spki);
  const attrs = signerInfo.signedAttrs;
  const content = signedData.encapContentInfo.eContent;
  const digestHash =
    CMS_HASH_BY_OID[oidName.decode(oidName.encode(signerInfo.digestAlg.algorithm))];
  const checkDigestParams = (): void => {
    const da = signerInfo.digestAlg;
    // RFC 5754 section 2: for SHA-2 digest OIDs, params MUST be accepted as absent or NULL.
    if (!digestAlgParamsOk(da))
      throw new Error('SHA-2 digestAlgorithm params must be absent or NULL');
  };
  const checkDigestAlg = (a: TArg<CmsAlg>): void => {
    const alg = a as CmsAlg;
    const da = signerInfo.digestAlg;
    if (signerKind && 'ed' in alg) {
      checkEdDigestParams(signerKind, da, 'SignerInfo', hasSignedAttrs);
      return;
    }
    // This compare assumes `a.hash` already reflects the RFC-defined CMS
    // digestAlgorithm for the signer family, so per-algorithm exceptions such
    // as RFC 8419 Ed448 need to be modeled in the signer table first.
    const expected = hashOid(alg.hash);
    const got = oidName.decode(oidName.encode(da.algorithm));
    if (got !== expected)
      throw new Error(`digestAlgorithm OID mismatch: expected ${expected}, got ${got}`);
    const digestParams = alg.digestParams?.();
    if (digestParams) {
      if (!digestParamsEqual(da.params, digestParams))
        throw new Error('digestAlgorithm params mismatch');
      return;
    }
    checkDigestParams();
  };
  const checkSignedAttrs = (hash?: TArg<(m: Uint8Array) => Uint8Array>): void => {
    const unsigned = signerInfo.unsignedAttrs || [];
    // This only covers the RFC 5652 core signed-only attributes tracked in the
    // local table; profile-level MUST-signed attrs such as sMIMECapabilities
    // need their own OID checks here if this verifier claims those profiles.
    // RFC 5652 sections 11.1/11.2/11.3: these attributes MUST be signed/authenticated, not unsigned.
    for (const id in CMS_SIGNED_ATTR_NAME) {
      if (unsigned.some((a) => a.oid === id))
        throw new Error(
          `${CMS_SIGNED_ATTR_NAME[id as keyof typeof CMS_SIGNED_ATTR_NAME]} attribute MUST NOT be unsigned`
        );
    }
    // RFC 2634 S/MIME/ESS attribute table: smimeCapabilities has Signed=MUST.
    // RFC 5652 section 5.3 defines unsignedAttrs as attributes that are not signed.
    if (unsigned.some((a) => a.oid === 'attrSMIMECapabilities'))
      throw new Error('sMIMECapabilities attribute MUST NOT be unsigned');
    // RFC 5652 section 11.4: countersignature MUST be unsigned; this API does not implement it.
    if (unsigned.some((a) => a.oid === 'attrCountersignature'))
      throw new Error('countersignature is unsupported by this API');
    if (!attrs) return;
    if (attrs.some((a) => a.oid === 'attrCountersignature'))
      throw new Error('countersignature MUST NOT be a signed attribute');
    const getAttrs = (oid: string) => attrs.filter((a) => a.oid === oid);
    const attrOne = (oid: string, name: string): TRet<AttributeCodec> => {
      const all = getAttrs(oid);
      if (all.length !== 1)
        throw new Error(
          `signedAttrs MUST include exactly one ${name} attribute, got ${all.length}`
        );
      return all[0] as TRet<AttributeCodec>;
    };
    const attrZeroOrOne = (oid: string, name: string): TRet<AttributeCodec | undefined> => {
      const all = getAttrs(oid);
      if (all.length > 1)
        throw new Error(
          `signedAttrs MUST NOT include multiple ${name} attributes, got ${all.length}`
        );
      return all[0] as TRet<AttributeCodec | undefined>;
    };
    // RFC 5652 section 5.6: when signedAttrs exists, content-type attr MUST match encapContentInfo.eContentType.
    const ctAttr = attrOne('attrContentType', 'content-type');
    const ct = ASN1.OID.decode(ctAttr.values[0]);
    if (ct !== signedData.encapContentInfo.eContentType)
      throw new Error('content-type attribute does not match encapContentInfo.eContentType');
    const mdAttr = attrOne('attrMessageDigest', 'messageDigest');
    ASN1.OctetString.decode(mdAttr.values[0]);
    const st = attrZeroOrOne('attrSigningTime', 'signingTime');
    if (st) X509Time.decode(st.values[0]);
    // RFC 5652 section 5.4: digest input starts from eContent OCTET STRING value bytes (no tag/len).
    // Detached verification provides content externally via CMS.verifyDetached; plain CMS.verify
    // without signature checks may still be used for detached structure/path validation.
    if (content === undefined || !hash) return;
    const got = ASN1.OctetString.decode(mdAttr.values[0]);
    const exp = (hash as (m: Uint8Array) => Uint8Array)(content);
    if (!equalBytes(got, exp)) throw new Error('messageDigest attribute does not match eContent');
  };
  const verifyInputs = (
    a: TArg<CmsAlg>,
    verifyOne: TArg<(data: Uint8Array) => boolean>
  ): CmsVerify => {
    const alg = a as CmsAlg;
    const verify = verifyOne as (data: Uint8Array) => boolean;
    checkDigestAlg(alg);
    checkSignedAttrs(alg.hash);
    if (signedData.encapContentInfo.eContent === undefined)
      throw new Error(
        'CMS.verify({checkSignatures:true}) requires attached eContent; use CMS.verifyDetached'
      );
    for (const data of inputs) if (verify(data)) return out;
    throw new Error('CMS signature invalid');
  };
  // RFC 5652 section 5.4: when signedAttrs is present, the IMPLICIT [0] tag
  // is not used; verify only the DER EXPLICIT SET OF encoding.
  const inputs: Uint8Array[] = attrs
    ? [ASN1.set(CMSX.Attribute).encode(attrs)]
    : content
      ? [content]
      : [];
  const tag = key.algorithm.info.TAG;
  if (!checkSignatures) {
    checkDigestParams();
    checkSignedAttrs(digestHash);
    return out;
  }
  const sigOid = oidName.decode(
    oidName.encode(signerInfo.signatureAlg.algorithm)
  ) as CmsAlg['sigOid'];
  const sig = CMS_ALG_BY_SIG_OID[sigOid];
  if (!sig) throw new Error(`unsupported signatureAlgorithm OID ${sigOid}`);
  if (tag === 'EC') {
    const curve = spkiCurve(key);
    if (!isSignCurve(curve))
      throw new Error(`CMS.verify({checkSignatures:true}) unsupported signer curve ${curve}`);
    if (!('ec' in sig)) throw new Error(`unsupported signatureAlgorithm OID ${sigOid}`);
    // RFC 5754 section 3.3: ECDSA-with-SHA2 AlgorithmIdentifier parameters MUST be absent.
    if (signerInfo.signatureAlg.params && sigOid.startsWith('ecdsa-with-'))
      throw new Error('ECDSA signatureAlgorithm params must be absent');
    return verifyInputs(sig, (data: TArg<Uint8Array>) =>
      ecdsaVerifyDer(curve, signerInfo.signature, sig.hash(data), key.publicKey)
    );
  }
  if (tag === 'Ed25519' || tag === 'Ed448') {
    if (!('ed' in sig)) throw new Error(`unsupported signatureAlgorithm OID ${sigOid}`);
    if (CMS_ALG[tag].sigOid !== sigOid)
      throw new Error(`unsupported signatureAlgorithm OID ${signerInfo.signatureAlg.algorithm}`);
    return verifyInputs(sig, (data: TArg<Uint8Array>) =>
      CMS_ALG[tag].ed.verify(signerInfo.signature, data as Uint8Array, key.publicKey)
    );
  }
  throw new Error('CMS.verify({checkSignatures:true}) supports EC/Ed signer certificates only');
};
type CMSApi = {
  decode: (
    der: Uint8Array,
    opts?: BEROpts
  ) => P.UnwrapCoder<typeof CMSX.ContentInfo> & { ber?: BERDoc };
  encode: (contentInfo: P.UnwrapCoder<typeof CMSX.ContentInfo> & { ber?: BERDoc }) => Uint8Array;
  contentType: (der: Uint8Array, opts?: BEROpts) => string;
  signed: (der: Uint8Array, opts?: BEROpts) => P.UnwrapCoder<typeof CMSX.SignedData>;
  verify: (der: Uint8Array, opts?: CmsVerifyOpts) => CmsVerify;
  detach: (der: Uint8Array, opts?: BEROpts) => CmsDetached;
  attach: (signature: Uint8Array, content: Uint8Array, opts?: BEROpts) => Uint8Array;
  verifyDetached: (signature: Uint8Array, content: Uint8Array, opts?: CmsVerifyOpts) => CmsVerify;
  sign: (
    content: string | Uint8Array,
    signingCertPem: string,
    privateKeyPem: string,
    chainPem?: string,
    opts?: CmsSignOpts
  ) => Uint8Array;
  signDetached: (
    content: string | Uint8Array,
    signingCertPem: string,
    privateKeyPem: string,
    chainPem?: string,
    opts?: CmsSignOpts
  ) => Uint8Array;
  compact: {
    sign: (
      content: string | Uint8Array,
      signingCertPem: string,
      privateKeyPem: string,
      opts?: Pick<
        CmsSignOpts,
        'createdTs' | 'extraEntropy' | 'smimeCapabilities' | 'messageDigest' | 'digestAlgorithm'
      >
    ) => Uint8Array;
    build: (
      content: string | Uint8Array,
      signature: Uint8Array,
      signingCertPem: string,
      chainPem?: string,
      opts?: CmsCompactBuildOpts
    ) => Uint8Array;
  };
};
type CmsCompactBuildOpts = Pick<
  CmsSignOpts,
  | 'createdTs'
  | 'smimeCapabilities'
  | 'messageDigest'
  | 'digestAlgorithm'
  | 'signatureAlgorithm'
  | 'digestAlgorithmParams'
>;
// `compact.build` reconstructs CMS signedAttrs from these options.
// They must match the options/data used by `compact.sign`, or CMS.verify will fail.
// OpenSSL compatibility notes:
// - `content: Uint8Array` matches `cms -sign -binary` (no text canonicalization).
// - `content: string` matches default text mode (LF/CRLF normalized to CRLF before signing).
const CMS_SIGNED_ATTR_NAME = /* @__PURE__ */ (() =>
  // This local name map only covers the core CMS signed-attribute OIDs that the
  // current high-level checks treat specially; supported profile attrs such as
  // sMIMECapabilities need explicit rows if they should share those checks.
  ({
    attrContentType: 'content-type',
    attrMessageDigest: 'messageDigest',
    attrSigningTime: 'signingTime',
  }) as const)();
// Plain friendly-name rows only work when the SMIMECapability value is just
// the algorithm OID; RFC 3851 §2.5.2.1 gives RC2 an INTEGER key-length
// parameter, so `rc2-cbc` needs extra handling beyond this name allowlist.
const SMIME_CAP_NAMES = /* @__PURE__ */ new Set([
  'aes256-cbc',
  'aes192-cbc',
  'aes128-cbc',
  'aes256-gcm',
  'aes192-gcm',
  'aes128-gcm',
  'aes256-cfb',
  'aes192-cfb',
  'aes128-cfb',
  'aes256-kw',
  'aes192-kw',
  'aes128-kw',
  'des-ede3-cbc',
  'rc2-cbc',
  'des-cbc',
]);
const SMIME_CAPS_REQUIRES_PARAMS = /* @__PURE__ */ new Set([
  // RFC 3851 section 2.5.2.1: rc2-cbc SMIMECapability parameters MUST
  // contain the effective key length.
  'rc2-cbc',
  // RFC 3278 section 7: these ECC key-agreement SMIMECapabilities require
  // KeyWrapAlgorithm parameters.
  'dhSinglePass_stdDH_sha1kdf_scheme',
  'dhSinglePass_cofactorDH_sha1kdf_scheme',
  'mqvSinglePass_sha1kdf_scheme',
  // RFC 5990 section 2.4: id-rsa-kem SMIMECapability MUST include GenericHybridParameters.
  'rsaKem',
]);
const cmsSmimeCapabilities = (names: string[]): TRet<Uint8Array> =>
  // This string-only helper can only build parameter-free SMIMECapability
  // values; RFC 3851 §2.5.2.1 RC2, RFC 3278 §7 ECC key agreement, and
  // RFC 5990 §2.4 RSA-KEM all need parameters and must not flow through the
  // raw-OID branch here as bare capabilityID values.
  ASN1.sequence({
    list: P.array(
      null,
      ASN1.sequence({
        capabilityID: ASN1.OID,
      })
    ),
  }).encode({
    list: names.map((name) => {
      const n = name.trim().toLowerCase();
      let capabilityID: string;
      if (SMIME_CAP_NAMES.has(n)) capabilityID = n;
      else if (/^[0-9]+(?:\.[0-9]+)+$/.test(n)) capabilityID = oidName.decode(oidName.encode(n));
      else throw new Error(`unknown S/MIME capability ${name}`);
      // RFC 8551 section 2.5.2: capability parameters must identify values
      // needed to distinguish algorithm instances; this string-only helper has
      // no parameter API, so reject known parameter-required alias/raw OID use.
      if (SMIME_CAPS_REQUIRES_PARAMS.has(capabilityID))
        throw new Error(`S/MIME capability ${name} requires parameters`);
      return { capabilityID };
    }),
  }) as TRet<Uint8Array>;
type CmsSignerType = { tag: 'EC'; curve: Curve; alg: CmsAlg } | { tag: EdKind; alg: CmsAlg };
const cmsAttrs = (
  data: TArg<Uint8Array>,
  algHash: TArg<HashAlg>,
  createdTs: number | undefined,
  smimeCapabilities: string[] | undefined,
  messageDigest: TArg<Uint8Array | undefined>
): TRet<AttributeCodec[]> => {
  const hash = algHash as HashAlg;
  const msgDigest = messageDigest as Uint8Array | undefined;
  // This builder only emits the current id-data signedAttrs subset for the
  // public sign path: mandatory content-type/message-digest plus optional
  // signing-time and sMIMECapabilities when the caller asks for them.
  const attrs: AttributeCodec[] = [
    { oid: 'attrContentType', values: [ASN1.OID.encode('data') as StrictBytes] },
  ];
  if (createdTs !== undefined) {
    if (!Number.isSafeInteger(createdTs))
      throw new Error(`expected safe integer createdTs in UNIX milliseconds, got ${createdTs}`);
    attrs.push({
      oid: 'attrSigningTime',
      values: [X509Time.encode(Math.floor(createdTs / 1000))],
    });
  }
  attrs.push({
    oid: 'attrMessageDigest',
    values: [ASN1.OctetString.encode(msgDigest || hash(data as Uint8Array)) as StrictBytes],
  });
  if (smimeCapabilities && smimeCapabilities.length)
    attrs.push({
      oid: 'attrSMIMECapabilities',
      values: [cmsSmimeCapabilities(smimeCapabilities) as StrictBytes],
    });
  return attrs as TRet<AttributeCodec[]>;
};
const cmsCertSet = (leaf: Cert, chain: Cert[]) => {
  // RFC 5652 section 10.2.3: CertificateSet ::= SET OF CertificateChoices.
  // Sort by DER for SET OF and drop adjacent duplicate DER entries; OpenSSL
  // cms -sign also emits one certificate when signer and -certfile repeat it.
  const items = [
    { TAG: 'certificate' as const, data: leaf },
    ...chain.map((c) => ({ TAG: 'certificate' as const, data: c })),
  ]
    .map((v) => ({ v, der: CMSCertificateChoices.encode(v) }))
    .sort((x, y) => {
      const a = x.der;
      const b = y.der;
      const n = Math.min(a.length, b.length);
      for (let i = 0; i < n; i++) {
        const d = a[i] - b[i];
        if (d) return d;
      }
      return a.length - b.length;
    });
  const out: typeof items = [];
  for (const i of items) {
    const prev = out[out.length - 1];
    if (!prev || !equalBytes(prev.der, i.der)) out.push(i);
  }
  return out.map((x) => x.v);
};
const cmsBuild = (
  data: TArg<Uint8Array>,
  leaf: Cert,
  chain: Cert[],
  attrs: TArg<AttributeCodec[]>,
  signature: TArg<Uint8Array>,
  digestAlgorithm: string,
  signatureAlgorithm: string,
  digestParams: TLVNode | undefined
): TRet<Uint8Array> => {
  const rawData = data as StrictBytes;
  const rawAttrs = attrs as AttributeCodec[];
  const sig = signature as StrictBytes;
  // This is the current one-signer attached id-data assembler for the public
  // compact/sign path; versioning and identifier choices stay fixed here and
  // broader CMS compatibility is handled in surrounding helpers.
  const signerInfo = {
    // RFC 5652 section 5.3: issuerAndSerialNumber SID => version 1.
    version: _1n,
    sid: {
      TAG: 'issuerSerial' as const,
      data: { issuer: leaf.tbs.issuer, serial: leaf.tbs.serial },
    },
    digestAlg: { algorithm: digestAlgorithm, params: digestParams },
    signedAttrs: rawAttrs,
    signatureAlg: { algorithm: signatureAlgorithm, params: undefined },
    signature: sig,
    unsignedAttrs: undefined,
  };
  const signedData = {
    version: _1n,
    digestAlgorithms: [{ algorithm: digestAlgorithm, params: digestParams }],
    // RFC 5652 section 4: encapsulated content type is id-data for octet payload.
    encapContentInfo: { eContentType: 'data', eContent: rawData },
    certificates: cmsCertSet(leaf, chain),
    crls: undefined,
    signerInfos: [signerInfo],
  };
  const contentInfo = {
    contentType: 'signedData',
    content: CMSX.SignedData.encode(signedData) as StrictBytes,
  };
  return CMSX.ContentInfo.encode(contentInfo) as TRet<Uint8Array>;
};
const ecdsaVerifyDer = (
  curve: Curve,
  signature: TArg<Uint8Array>,
  msgHash: TArg<Uint8Array>,
  publicKey: TArg<Uint8Array>
): boolean => {
  // This is the strict DER ECDSA-Sig-Value gate plus curve verify step; the
  // caller still binds the hash algorithm and signer curve before reaching it.
  const sig = signature as Uint8Array;
  // Raw DER ECDSA signature pair shape only; scalar range and curve-specific
  // validity stay with the later signature verification step.
  ASN1.ECDSASig.decode(sig);
  return ecCurve(curve).verify(sig, msgHash as Uint8Array, publicKey as Uint8Array, {
    format: 'der',
    lowS: false,
    prehash: false,
  });
};
const cmsSignCtx = (
  content: TArg<string | Uint8Array>,
  signingCertPem: string,
  createdTs: number | undefined,
  smimeCapabilities: string[] | undefined,
  messageDigest: TArg<Uint8Array | undefined>,
  digestAlgorithm: string | undefined
): TRet<{
  data: Uint8Array;
  leaf: Cert;
  signer: CmsSignerType;
  digestHash: HashAlg;
  attrs: AttributeCodec[];
  toSign: Uint8Array;
}> => {
  const input = content as string | Uint8Array;
  // String input takes the S/MIME text convenience path here: line endings are
  // canonicalized to CRLF before UTF-8 encoding, while Uint8Array is treated
  // as already-canonical content bytes for CMS signedAttrs and eContent.
  const data =
    typeof input === 'string'
      ? new TextEncoder().encode(input.replace(/\r\n|\r|\n/g, '\r\n'))
      : input;
  const leaf = certItem(onePem(signingCertPem, 'CERTIFICATE').der);
  const leafKey = certSpkiKey(leaf.tbs.spki);
  const leafTag = leafKey.algorithm.info.TAG;
  const signer = (() => {
    if (leafTag === 'EC') {
      const curve = spkiCurve(leafKey);
      if (!isSignCurve(curve)) throw new Error(`cmsSign unsupported signer curve ${curve}`);
      return { tag: 'EC' as const, curve: curve, alg: CMS_ALG[curve] };
    }
    if (leafTag === 'Ed25519' || leafTag === 'Ed448')
      return { tag: leafTag, alg: CMS_ALG[leafTag] };
    throw new Error('cmsSign supports EC/Ed cert/key only');
  })();
  const defaultDigestOid = hashOid(signer.alg.hash);
  const digestOid = digestAlgorithm
    ? oidName.decode(oidName.encode(digestAlgorithm))
    : defaultDigestOid;
  // RFC 8419 section 3.1 fixes Ed25519/Ed448 digestAlgorithm OIDs when
  // signedAttrs are present; this CMS API always emits signedAttrs.
  checkEdDigestParams(
    signer.tag === 'Ed25519' || signer.tag === 'Ed448' ? signer.tag : undefined,
    {
      algorithm: digestOid,
      params: 'digestParams' in signer.alg ? signer.alg.digestParams() : undefined,
    },
    'SignerInfo'
  );
  const digestHash = digestAlgorithm ? CMS_HASH_BY_OID[digestOid] : signer.alg.hash;
  if (!digestHash) throw new Error(`unsupported digestAlgorithm OID ${digestAlgorithm}`);
  const attrs = cmsAttrs(data, digestHash, createdTs, smimeCapabilities, messageDigest);
  const toSign = ASN1.set(CMSX.Attribute).encode(attrs);
  return { data, leaf, signer, digestHash, attrs, toSign } as TRet<{
    data: Uint8Array;
    leaf: Cert;
    signer: CmsSignerType;
    digestHash: HashAlg;
    attrs: AttributeCodec[];
    toSign: Uint8Array;
  }>;
};
const cmsCompactSign = (
  signer: TArg<CmsSignerType>,
  leaf: Cert,
  privateKeyPem: string,
  toSign: TArg<Uint8Array>,
  digestHash: TArg<HashAlg>,
  extraEntropy: TArg<boolean | Uint8Array | undefined>
): TRet<Uint8Array> => {
  const sign = signer as CmsSignerType;
  const msg = toSign as Uint8Array;
  const hash = digestHash as HashAlg;
  const entropy = extraEntropy as boolean | Uint8Array | undefined;
  // This helper is the compact-sign emission boundary: require PKCS#8
  // PRIVATE KEY input, confirm the private key matches the leaf cert, then
  // emit either DER ECDSA-Sig-Value or raw EdDSA signature bytes.
  const keyBlock = onePem(privateKeyPem);
  if (keyBlock.tag !== 'PRIVATE KEY')
    throw new Error(`expected PKCS#8 PRIVATE KEY PEM, got ${keyBlock.tag}`);
  const key = pkcs8FromPem(privateKeyPem, keyBlock.der);
  if (!matchCertKey(leaf, key)) throw new Error('certificate and private key do not match');
  const keyTag = key.key.algorithm.info.TAG;
  const kk = pkcs8SignKey(key.key);
  if (sign.tag === 'EC') {
    if (keyTag !== 'EC' || kk.kind !== 'EC' || !isSignCurve(kk.curve) || kk.curve !== sign.curve)
      throw new Error('cmsSign key type mismatch');
    // RFC 5652 section 5.4 hashes DER SignedAttrs with SignerInfo.digestAlgorithm;
    // RFC 5754 section 3.3 then identifies the matching ECDSA-with-SHA2 OID.
    return ecCurve(sign.curve).sign(hash(msg), kk.secretKey, {
      prehash: false,
      format: 'der',
      lowS: false,
      extraEntropy: entropy === undefined ? true : entropy,
    }) as TRet<Uint8Array>;
  }
  if (keyTag !== sign.tag || kk.kind !== sign.tag) throw new Error('cmsSign key type mismatch');
  return CMS_ALG[sign.tag].ed.sign(msg, kk.secretKey) as TRet<Uint8Array>;
};

/**
 * CMS SignedData helpers for X.509 certificates.
 *
 * Public wrapper over the stricter helper layers below: ContentInfo shell
 * handling, attached/detached eContent transforms, and sign/verify convenience
 * composition live here, while most RFC/profile validation stays in child helpers.
 */
const CMSApiImpl: CMSApi = /* @__PURE__ */ deepFreeze({
  decode: (
    der: TArg<Uint8Array>,
    opts: TArg<BEROpts> = {}
  ): TRet<P.UnwrapCoder<typeof CMSX.ContentInfo> & { ber?: BERDoc }> => {
    const ber = BER.view(der, opts);
    const contentInfo = CMSX.ContentInfo.decode(ber.der) as P.UnwrapCoder<
      typeof CMSX.ContentInfo
    > & {
      ber?: BERDoc;
    };
    contentInfo.ber = ber;
    return contentInfo as TRet<P.UnwrapCoder<typeof CMSX.ContentInfo> & { ber?: BERDoc }>;
  },
  encode: (
    contentInfo: TArg<P.UnwrapCoder<typeof CMSX.ContentInfo> & { ber?: BERDoc }>
  ): TRet<Uint8Array> => {
    const ci = contentInfo as P.UnwrapCoder<typeof CMSX.ContentInfo> & { ber?: BERDoc };
    const der = CMSX.ContentInfo.encode(ci);
    const ber = ci.ber;
    if (!ber) return der as TRet<Uint8Array>;
    return BER.encode(ber.nodes, der) as TRet<Uint8Array>;
  },
  contentType: (der: TArg<Uint8Array>, opts: TArg<BEROpts> = {}) =>
    CMSApiImpl.decode(der, opts).contentType,
  signed: (
    der: TArg<Uint8Array>,
    opts: TArg<BEROpts> = {}
  ): TRet<P.UnwrapCoder<typeof CMSX.SignedData>> => {
    return cmsSignedData(BER.view(der, opts).der).signedData as TRet<
      P.UnwrapCoder<typeof CMSX.SignedData>
    >;
  },
  verify: (der: TArg<Uint8Array>, opts: TArg<CmsVerifyOpts> = {}): CmsVerify =>
    cmsVerifyEc(der, opts),
  detach: (der: TArg<Uint8Array>, opts: TArg<BEROpts> = {}): TRet<CmsDetached> => {
    // RFC 5652 section 5.2: detached signatures are represented by absent eContent.
    const { contentInfo, signedData } = cmsSignedData(BER.view(der, opts).der);
    if (signedData.encapContentInfo.eContent === undefined)
      throw new Error('CMS.detach expects attached CMS with present eContent');
    const content = signedData.encapContentInfo.eContent;
    const certs = cmsCerts(signedData);
    signedData.encapContentInfo.eContent = undefined;
    contentInfo.content = CMSX.SignedData.encode(signedData) as StrictBytes;
    return {
      content,
      signature: CMSX.ContentInfo.encode(contentInfo),
      certs,
    } as TRet<CmsDetached>;
  },
  attach: (
    signature: TArg<Uint8Array>,
    content: TArg<Uint8Array>,
    opts: TArg<BEROpts> = {}
  ): TRet<Uint8Array> => {
    // RFC 5652 section 5.2: attached form carries eContent as OCTET STRING value bytes.
    const { contentInfo, signedData } = cmsSignedData(BER.view(signature, opts).der);
    if (signedData.encapContentInfo.eContent !== undefined)
      throw new Error('CMS.attach expects detached signature with absent eContent');
    signedData.encapContentInfo.eContent = content as StrictBytes;
    contentInfo.content = CMSX.SignedData.encode(signedData) as StrictBytes;
    return CMSX.ContentInfo.encode(contentInfo) as TRet<Uint8Array>;
  },
  verifyDetached: (
    signature: TArg<Uint8Array>,
    content: TArg<Uint8Array>,
    opts: TArg<CmsVerifyOpts> = {}
  ): CmsVerify => cmsVerifyEc(CMSApiImpl.attach(signature, content, opts), opts),
  sign: (
    content: TArg<string | Uint8Array>,
    signingCertPem: string,
    privateKeyPem: string,
    chainPem = '',
    opts: TArg<CmsSignOpts> = {}
  ): TRet<Uint8Array> => {
    const cfg = opts as CmsSignOpts;
    const compactOpts = {
      createdTs: cfg.createdTs,
      smimeCapabilities: cfg.smimeCapabilities,
      messageDigest: cfg.messageDigest,
      digestAlgorithm: cfg.digestAlgorithm,
    };
    const compactBuildOpts = {
      ...compactOpts,
      digestAlgorithmParams: cfg.digestAlgorithmParams,
      signatureAlgorithm: cfg.signatureAlgorithm,
    };
    return CMSApiImpl.compact.build(
      content,
      CMSApiImpl.compact.sign(content, signingCertPem, privateKeyPem, {
        ...compactOpts,
        extraEntropy: cfg.extraEntropy,
      }),
      signingCertPem,
      chainPem,
      compactBuildOpts
    ) as TRet<Uint8Array>;
  },
  signDetached: (
    content: TArg<string | Uint8Array>,
    signingCertPem: string,
    privateKeyPem: string,
    chainPem = '',
    opts: TArg<CmsSignOpts> = {}
  ): TRet<Uint8Array> =>
    CMSApiImpl.detach(CMSApiImpl.sign(content, signingCertPem, privateKeyPem, chainPem, opts))
      .signature as TRet<Uint8Array>,
  compact: {
    sign: (
      content: TArg<string | Uint8Array>,
      signingCertPem: string,
      privateKeyPem: string,
      opts: TArg<
        Pick<
          CmsSignOpts,
          'createdTs' | 'extraEntropy' | 'smimeCapabilities' | 'messageDigest' | 'digestAlgorithm'
        >
      > = {}
    ): TRet<Uint8Array> => {
      const cfg = opts as Pick<
        CmsSignOpts,
        'createdTs' | 'extraEntropy' | 'smimeCapabilities' | 'messageDigest' | 'digestAlgorithm'
      >;
      const c = cmsSignCtx(
        content,
        signingCertPem,
        cfg.createdTs,
        cfg.smimeCapabilities,
        cfg.messageDigest,
        cfg.digestAlgorithm
      );
      return cmsCompactSign(
        c.signer,
        c.leaf,
        privateKeyPem,
        c.toSign,
        c.digestHash,
        cfg.extraEntropy
      );
    },
    build: (
      content: TArg<string | Uint8Array>,
      signature: TArg<Uint8Array>,
      signingCertPem: string,
      chainPem = '',
      opts: TArg<CmsCompactBuildOpts> = {}
    ): TRet<Uint8Array> => {
      const cfg = opts as CmsCompactBuildOpts;
      const sig = signature as Uint8Array;
      const c = cmsSignCtx(
        content,
        signingCertPem,
        cfg.createdTs,
        cfg.smimeCapabilities,
        cfg.messageDigest,
        cfg.digestAlgorithm
      );
      const defaultDigestAlgorithm = hashOid(c.signer.alg.hash);
      const digestAlgorithm = cfg.digestAlgorithm
        ? oidName.decode(oidName.encode(cfg.digestAlgorithm))
        : defaultDigestAlgorithm;
      let signatureAlgorithm: string | undefined = cfg.signatureAlgorithm
        ? oidName.decode(oidName.encode(cfg.signatureAlgorithm))
        : undefined;
      if (!signatureAlgorithm && c.signer.tag === 'EC') {
        // Keep this CMS-only selection local so X509-only treeshake bundles do
        // not retain the ECDSA digest/signature OID table.
        if (digestAlgorithm === hashOid(sha224)) signatureAlgorithm = 'ecdsa-with-SHA224';
        else if (digestAlgorithm === hashOid(sha256)) signatureAlgorithm = 'ecdsa-with-SHA256';
        else if (digestAlgorithm === hashOid(sha384)) signatureAlgorithm = 'ecdsa-with-SHA384';
        else if (digestAlgorithm === hashOid(sha512)) signatureAlgorithm = 'ecdsa-with-SHA512';
      }
      if (!signatureAlgorithm && c.signer.tag !== 'EC') signatureAlgorithm = c.signer.alg.sigOid;
      if (!signatureAlgorithm) throw new Error('signature algorithm OID is required');
      const signerDigestParams =
        'digestParams' in c.signer.alg && c.signer.alg.digestParams
          ? c.signer.alg.digestParams()
          : undefined;
      const digestParams = cfg.digestAlgorithmParams
        ? cfg.digestAlgorithmParams === 'null'
          ? ASN1_NULL_TLV
          : undefined
        : digestAlgorithm === defaultDigestAlgorithm
          ? signerDigestParams
          : undefined;
      checkEdDigestParams(
        c.signer.tag === 'Ed25519' || c.signer.tag === 'Ed448' ? c.signer.tag : undefined,
        { algorithm: digestAlgorithm, params: digestParams },
        'SignerInfo'
      );
      const sigMeta = CMS_ALG_BY_SIG_OID[signatureAlgorithm as CmsAlg['sigOid']];
      if (c.signer.tag === 'EC') {
        // RFC 5754 section 3.3 couples ECDSA-with-SHA2 signature OIDs to the
        // same hash family used by SignerInfo.digestAlgorithm.
        if (!sigMeta || !('ec' in sigMeta))
          throw new Error(`unsupported EC signatureAlgorithm OID ${signatureAlgorithm}`);
        if (hashOid(sigMeta.hash) !== digestAlgorithm)
          throw new Error(
            'ECDSA signatureAlgorithm must match digestAlgorithm by RFC 5754 section 3.3'
          );
        ecCurve(c.signer.curve).Signature.fromBytes(sig, 'der');
      } else {
        if (signatureAlgorithm !== c.signer.alg.sigOid)
          throw new Error(
            `${c.signer.tag} signatureAlgorithm must match signer key by RFC 8419 section 3.1`
          );
        const expected = c.signer.tag === 'Ed25519' ? 64 : 114;
        if (sig.length !== expected)
          throw new Error(
            `invalid ${c.signer.tag} signature length: expected ${expected}, got ${sig.length}`
          );
      }
      const chain = (() => {
        if (!chainPem) return [];
        const blocks = pemBlocks(chainPem).filter((i) => i.tag === 'CERTIFICATE');
        if (!blocks.length) throw new Error('no CERTIFICATE PEM blocks found');
        return blocks.map((b) => certItem(b.der));
      })();
      return cmsBuild(
        c.data,
        c.leaf,
        chain,
        c.attrs,
        signature,
        digestAlgorithm,
        signatureAlgorithm,
        digestParams
      );
    },
  },
});
/** CMS SignedData helpers for X.509 certificates. */
export const CMS: TRet<CMSApi> = CMSApiImpl as unknown as TRet<CMSApi>;
// Narrow explicit test-only hook surface for focused review artifacts; keep this
// list intentional so helper exposure does not silently widen the public API.
export const __TEST: {
  IPv4: typeof IPv4;
  IPv6: typeof IPv6;
  X509Time: typeof X509Time;
  CMSCertificateChoices: typeof CMSCertificateChoices;
  CMSRevocationInfoChoice: typeof CMSRevocationInfoChoice;
  CMSSignedData: typeof CMSSignedData;
  keyCurve: (privateKeyPem: string) => CertCurve | EdKind;
} = /* @__PURE__ */ (() =>
  deepFreeze({
    IPv4: IPv4,
    IPv6: IPv6,
    X509Time: X509Time,
    CMSCertificateChoices: CMSCertificateChoices,
    CMSRevocationInfoChoice: CMSRevocationInfoChoice,
    CMSSignedData: CMSSignedData,
    keyCurve: (privateKeyPem: string) => {
      const block = onePem(privateKeyPem, 'PRIVATE KEY');
      const parsed = pkcs8SignKey(pkcs8FromPem(privateKeyPem, block.der).key);
      return parsed.kind === 'EC' ? parsed.curve : parsed.kind;
    },
  }))();

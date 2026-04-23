/*! micro-key-producer - MIT License (c) 2024 Paul Miller (paulmillr.com) */
/**
 * x509 certificates. Conforms to parts of RFC 3820, RFC 5280, RFC 5652, RFC 5754, RFC 5912, RFC 7633.
 * @module
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { ed448 } from '@noble/curves/ed448.js';
import { brainpoolP256r1, brainpoolP384r1, brainpoolP512r1 } from '@noble/curves/misc.js';
import { p256, p384, p521 } from '@noble/curves/nist.js';
import { asciiToBytes, equalBytes } from '@noble/curves/utils.js';
import { sha224, sha256, sha384, sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils.js';
import { base64, hex } from '@scure/base';
import * as P from 'micro-packed';
import type {
  ECParams as DERECParams,
  PKCS8Key as DERPKCS8Key,
  SPKIKey as DERSPKIKey,
} from './convert.ts';
import { CurveOID, DERUtils, curveOID } from './convert.ts';

type KnownCurve = keyof typeof CurveOID;
/** Supported signing or key-agreement curve name. */
export type CertCurve = KnownCurve | `OID:${string}`;
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
type RSAPrivateKey = P.UnwrapCoder<typeof DERUtils.RSAPrivateKey>;
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
  // Default behavior omits this attribute (OpenSSL `-nosmimecap` style); pass values here to include it.
  // Values can be capability names from SMIME_CAPS or raw capability OIDs.
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
  subjectDirectoryAttributes?: {
    list: { type: string; typeName?: string; values: CertAny[] }[];
  };
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
  qcStatements?: {
    list: { statementId: string; statementName?: string; statementInfo?: CertAny }[];
  };
  /** Subject Information Access extension. */
  subjectInfoAccess?: { list: { method: string; location: CertGeneralName }[] };
  /** Microsoft certificate type extension. */
  msCertType?: CertAny;
};
/** Parsed GeneralName value. */
export type CertGeneralName =
  | { TAG: 'otherName'; data: { type: string; value: TLVNode } }
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
  | { TAG: 'nameRelativeToCRLIssuer'; data: Array<{ oid: string; value: NameValue }> };
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
        noticeRef?: { organization: CertText; numbers: number[] };
        explicitText?: CertText;
      };
    }
  | { TAG: 'unknown'; data: { oid: string; value: TLVNode } };
/** Generic ASN.1 tree node used for unsupported extension payloads. */
export type TLVNode = {
  /** Raw ASN.1 tag number. */
  tag: number;
  /** Nested child nodes for constructed values. */
  children?: TLVNode[];
  /** Hex-encoded payload for primitive values. */
  valueHex?: string;
};
/** Decoded text value from certificate fields. */
export type CertText = {
  /** Underlying ASN.1 string tag used by the source field. */
  tag: 'utf8' | 'ia5' | 'visible' | 'bmp';
  /** Decoded text content. */
  text: string;
};
/** Best-effort decoded arbitrary ASN.1 value. */
export type CertAny =
  | { TAG: 'text'; data: NameValue }
  | { TAG: 'oid'; data: { oid: string; name?: string } }
  | { TAG: 'int'; data: bigint }
  | { TAG: 'bool'; data: boolean }
  | { TAG: 'time'; data: { TAG: 'utc' | 'generalized'; data: string } }
  | { TAG: 'octet'; data: Uint8Array }
  | { TAG: 'raw'; data: TLVNode };
const pemRE = /-----BEGIN ([^-]+)-----([\s\S]*?)-----END \1-----/g;
const hashOid = (h: { oid?: Uint8Array }) => {
  if (!h.oid) throw new Error('hash.oid is missing');
  return DERUtils.ASN1.OID.decode(h.oid);
};
const OID_NAME_RE = /^[0-9]+(?:\.[0-9]+)+$/;
const oidName = (m: Record<string, string>, oid: string): string => m[oid] || `OID:${oid}`;
const oidValue = (m: Record<string, string>, v: string, what: string): string => {
  if (m[v]) return m[v];
  if (v.startsWith('OID:')) return v.slice(4);
  if (OID_NAME_RE.test(v)) return v;
  throw new Error(`unknown ${what} ${v}`);
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
export const pemBlocks = (text: string): PemBlock[] => {
  const out: PemBlock[] = [];
  for (const m of text.matchAll(pemRE)) {
    const tag = m[1].trim();
    const b64 = m[2].trim();
    if (!tag || !b64) continue;
    out.push({ tag, b64, der: base64.decode(b64.replace(/\s+/g, '')) });
  }
  return out;
};

const onePem = (text: string, tag?: string) => {
  const all = pemBlocks(text);
  if (!all.length) throw new Error('no PEM blocks found');
  if (!tag) return all[0];
  const hit = all.find((i) => i.tag === tag);
  if (!hit) throw new Error(`no PEM block with tag=${tag}`);
  return hit;
};

const bytesNum = (bytes: Uint8Array): bigint => BigInt(`0x${bytesToHex(bytes) || '0'}`);
const explicitCurve = (
  data: unknown
):
  | {
      fieldId: { info: { TAG: 'primeField'; data: bigint } };
      curve: { a: Uint8Array; b: Uint8Array };
      base: Uint8Array;
      order: bigint;
      cofactor?: bigint;
    }
  | undefined => {
  if (!data || typeof data !== 'object') return;
  const d = data as Record<string, unknown>;
  const fieldId = d.fieldId as Record<string, unknown> | undefined;
  const info = fieldId?.info as Record<string, unknown> | undefined;
  const curve = d.curve as Record<string, unknown> | undefined;
  if (info?.TAG !== 'primeField' || typeof info.data !== 'bigint') return;
  if (!(curve?.a instanceof Uint8Array) || !(curve?.b instanceof Uint8Array)) return;
  if (!(d.base instanceof Uint8Array) || typeof d.order !== 'bigint') return;
  if (d.cofactor !== undefined && typeof d.cofactor !== 'bigint') return;
  return {
    fieldId: { info: { TAG: 'primeField', data: info.data } },
    curve: { a: curve.a, b: curve.b },
    base: d.base,
    order: d.order,
    cofactor: d.cofactor as bigint | undefined,
  };
};
const explicitCurveName = (data: unknown): Curve | undefined => {
  const d = explicitCurve(data);
  if (!d) return;
  // OpenSSL can serialize a standard EC key with explicit domain parameters while the
  // matching cert/SPKI keeps the named-curve OID, so normalize equivalent parameters here.
  for (const curve in CurveOID) {
    const name = curve as Curve;
    const known = CMS_ALG[name].ec.Point.CURVE();
    if (d.fieldId.info.data !== known.p) continue;
    if (bytesNum(d.curve.a) !== known.a || bytesNum(d.curve.b) !== known.b) continue;
    if (d.order !== known.n) continue;
    if (d.cofactor !== undefined && d.cofactor !== known.h) continue;
    const base = CMS_ALG[name].ec.Point.BASE;
    if (!equalBytes(d.base, base.toBytes(false)) && !equalBytes(d.base, base.toBytes(true)))
      continue;
    return name;
  }
  return;
};
const ecParamCurve = (d: DERECParams): CertCurve => {
  if (d.TAG === 'namedCurve') return curveOID(d.data) as CertCurve;
  if (d.TAG === 'implicitCurve') return 'OID:implicitCurve';
  return explicitCurveName(d.data) || 'OID:specifiedCurve';
};
const spkiCurve = (k: DERSPKIKey): CertCurve => {
  if (k.algorithm.info.TAG !== 'EC')
    throw new Error(`expected EC SPKI key, got ${k.algorithm.info.TAG}`);
  return ecParamCurve(k.algorithm.info.data);
};
// treeshake: these shared X.509 helpers survive through property reads unless the declaration itself is pure.
const SpkiKey = /* @__PURE__ */ (() => DERUtils.SPKI as P.CoderType<DERSPKIKey>)();
/** Supported certificate/key curves. */
export type Curve =
  | 'P-256'
  | 'P-384'
  | 'P-521'
  | 'brainpoolP256r1'
  | 'brainpoolP384r1'
  | 'brainpoolP512r1';
type EdKind = 'Ed25519' | 'Ed448';
type HashAlg = ((m: Uint8Array) => Uint8Array) & { oid?: Uint8Array };
type EcAlg = {
  ec: {
    sign: (m: Uint8Array, sk: Uint8Array, o?: any) => Uint8Array;
    verify: (sig: Uint8Array, m: Uint8Array, pk: Uint8Array, o?: any) => boolean;
    getPublicKey: (sk: Uint8Array, compressed?: boolean) => Uint8Array;
    lengths: { signature?: number };
    Point: {
      CURVE: () => { p: bigint; n: bigint; h: bigint; a: bigint; b: bigint };
      BASE: { toBytes: (compressed?: boolean) => Uint8Array };
    };
  };
  sigOid: string;
  hash: HashAlg;
};
type EdAlg = {
  ed: {
    sign: (m: Uint8Array, sk: Uint8Array) => Uint8Array;
    verify: (sig: Uint8Array, m: Uint8Array, pk: Uint8Array) => boolean;
    getPublicKey: (sk: Uint8Array) => Uint8Array;
  };
  sigOid: string;
  hash: HashAlg;
};
type CmsAlg = EcAlg | EdAlg;
const CMS_ALG = {
  'P-256': { ec: p256, sigOid: '1.2.840.10045.4.3.2', hash: sha256 },
  'P-384': { ec: p384, sigOid: '1.2.840.10045.4.3.3', hash: sha384 },
  'P-521': { ec: p521, sigOid: '1.2.840.10045.4.3.4', hash: sha512 },
  brainpoolP256r1: {
    ec: brainpoolP256r1,
    sigOid: '1.2.840.10045.4.3.2',
    hash: sha256,
  },
  brainpoolP384r1: {
    ec: brainpoolP384r1,
    sigOid: '1.2.840.10045.4.3.3',
    hash: sha384,
  },
  brainpoolP512r1: {
    ec: brainpoolP512r1,
    sigOid: '1.2.840.10045.4.3.4',
    hash: sha512,
  },
  Ed25519: {
    ed: ed25519,
    sigOid: '1.3.101.112',
    hash: sha512,
  },
  Ed448: {
    ed: ed448,
    sigOid: '1.3.101.113',
    hash: sha512,
  },
} as const satisfies Record<Curve, EcAlg> & Record<EdKind, EdAlg>;
type AlgKey = Curve | EdKind;
// RFC 5754 section 2: this absent-or-NULL parameters rule applies to SHA-2
// AlgorithmIdentifiers specifically, so this set is intentionally SHA2-only
// (not a generic all-hashes OID table).
const SHA2_OID = {
  '2.16.840.1.101.3.4.2.4': true,
  '2.16.840.1.101.3.4.2.1': true,
  '2.16.840.1.101.3.4.2.2': true,
  '2.16.840.1.101.3.4.2.3': true,
} as const;
const ASN1_NULL = /* @__PURE__ */ Uint8Array.from([0x05, 0x00]);
const digestAlgParamsOk = (a: AlgorithmIdentifierCodec): boolean => {
  const oid = algOID(a.algorithm);
  if (!(oid in SHA2_OID)) return true;
  const p = a.params ? TLVNodeCodec.encode(a.params) : undefined;
  return !p || equalBytes(p, ASN1_NULL);
};
const digestAlgEqual = (a: AlgorithmIdentifierCodec, b: AlgorithmIdentifierCodec): boolean => {
  const aOid = algOID(a.algorithm);
  const bOid = algOID(b.algorithm);
  if (aOid !== bOid) return false;
  if (!digestAlgParamsOk(a) || !digestAlgParamsOk(b)) return false;
  const aParams = a.params ? TLVNodeCodec.encode(a.params) : undefined;
  const bParams = b.params ? TLVNodeCodec.encode(b.params) : undefined;
  if (aOid in SHA2_OID) return true;
  if (!aParams || !bParams) return !aParams && !bParams;
  return equalBytes(aParams, bParams);
};
const ecCurve = (curve: Curve) => CMS_ALG[curve].ec;
const isSignCurve = (curve: CertCurve): curve is Curve =>
  curve in CMS_ALG && 'ec' in CMS_ALG[curve as AlgKey];
const CMS_ALG_BY_SIG_OID = /* @__PURE__ */ (() =>
  Object.fromEntries(Object.values(CMS_ALG).map((v) => [v.sigOid, v])) as Record<
    CmsAlg['sigOid'],
    CmsAlg
  >)();
const CMS_HASH_BY_OID = /* @__PURE__ */ (() =>
  Object.fromEntries([sha256, sha384, sha512].map((h) => [hashOid(h), h])) as Record<
    string,
    typeof sha256
  >)();
const HASH_NAME_TO_OID = /* @__PURE__ */ Object.fromEntries(
  /* @__PURE__ */ Object.entries({ sha224, sha256, sha384, sha512 }).map(([name, h]) => [
    name,
    hashOid(h),
  ])
) as Record<string, string>;
const ALG_NAME_TO_OID = /* @__PURE__ */ (() =>
  ({
    ecPublicKey: '1.2.840.10045.2.1',
    'ecdsa-with-SHA256': CMS_ALG['P-256'].sigOid,
    'ecdsa-with-SHA384': CMS_ALG['P-384'].sigOid,
    'ecdsa-with-SHA512': CMS_ALG['P-521'].sigOid,
    Ed25519: CMS_ALG.Ed25519.sigOid,
    Ed448: CMS_ALG.Ed448.sigOid,
    ...HASH_NAME_TO_OID,
  }) as const)();
const ALG_OID_TO_NAME = /* @__PURE__ */ Object.fromEntries(
  /* @__PURE__ */ Object.entries(ALG_NAME_TO_OID).map(([k, v]) => [v, k])
) as Record<string, string>;
const algOID = (v: string): string =>
  oidValue(ALG_NAME_TO_OID as Record<string, string>, v, 'algorithm');
const pkcs8Attrs = (k: DERPKCS8Key): Pkcs8Attr[] | undefined =>
  k.attributes?.map((raw) => PKCS8Attr.decode(raw));
const pkcs8FromPem = (pem: string, der: Uint8Array): PrivateKey => {
  const key = DERUtils.PKCS8.decode(der);
  const t = key.algorithm.info.TAG;
  if (t === 'rsaEncryption') {
    if (key.privateKey.TAG !== 'raw')
      throw new Error('RSA PKCS#8: expected raw private key payload');
    return {
      pem,
      der,
      attributes: pkcs8Attrs(key),
      key,
      rsa: DERUtils.RSAPrivateKey.decode(key.privateKey.data),
    };
  }
  return { pem, der, attributes: pkcs8Attrs(key), key };
};
const pkcs8SignKey = (
  k: DERPKCS8Key
):
  | { kind: 'EC'; curve: CertCurve; secretKey: Uint8Array; publicKey?: Uint8Array }
  | { kind: EdKind; secretKey: Uint8Array; publicKey: Uint8Array } => {
  const tag = k.algorithm.info.TAG;
  if (tag === 'EC') {
    const curve = ecParamCurve(k.algorithm.info.data);
    if (k.privateKey.TAG !== 'struct')
      throw new Error('EC PKCS#8: expected structured ECPrivateKey payload');
    const s = k.privateKey.data;
    if (s.parameters && ecParamCurve(s.parameters) !== curve)
      throw new Error('EC PKCS#8: algorithm and key parameters mismatch');
    return { kind: 'EC', curve, secretKey: s.privateKey, publicKey: k.publicKey || s.publicKey };
  }
  if (tag === 'Ed25519' || tag === 'Ed448') {
    if (k.privateKey.TAG !== 'raw')
      throw new Error(`${tag} PKCS#8: expected raw private key payload`);
    return {
      kind: tag,
      secretKey: k.privateKey.data,
      publicKey: k.publicKey || CMS_ALG[tag].ed.getPublicKey(k.privateKey.data),
    };
  }
  throw new Error(`expected EC/Ed PKCS#8 key, got ${tag}`);
};

const certItem = (der: Uint8Array, opts: BEROpts = {}): Cert =>
  X509C.Certificate.decode(berView(der, opts).der);
const certSpkiKey = (spki: TBSCertificateCodec['spki']): DERSPKIKey =>
  SpkiKey.decode(X509SPKI.encode(spki));

const matchCertKey = (cert: Cert, key: PrivateKey): boolean => {
  const k = certSpkiKey(cert.tbs.spki);
  const tag = k.algorithm.info.TAG;
  if (tag === 'EC') {
    if (key.key.algorithm.info.TAG !== 'EC') return false;
    const curve = spkiCurve(k);
    if (!isSignCurve(curve)) return false;
    const kk = pkcs8SignKey(key.key);
    if (kk.kind !== 'EC' || curve !== kk.curve) return false;
    const cmp = ecCurve(curve).getPublicKey(kk.secretKey, false);
    const cmpC = ecCurve(curve).getPublicKey(kk.secretKey, true);
    return equalBytes(k.publicKey, cmp) || equalBytes(k.publicKey, cmpC);
  }
  if (tag === 'Ed25519' || tag === 'Ed448') {
    if (key.key.algorithm.info.TAG !== tag) return false;
    const kk = pkcs8SignKey(key.key);
    if (kk.kind !== tag) return false;
    return (
      equalBytes(k.publicKey, kk.publicKey) ||
      equalBytes(k.publicKey, CMS_ALG[tag].ed.getPublicKey(kk.secretKey))
    );
  }
  throw new Error('matchCertKey supports EC/Ed keys only');
};

type BERDoc = ReturnType<typeof DERUtils.BER.decode>;
type BEROpts = { allowBER?: boolean };
const berView = (src: Uint8Array, opts: BEROpts = {}): BERDoc =>
  DERUtils.BER.decode(src, { allowBER: !!opts.allowBER });
const ASN1 = /* @__PURE__ */ (() => DERUtils.ASN1)();
const DERLen = P.wrap({
  encodeStream(w, len: number) {
    if (!Number.isSafeInteger(len) || len < 0)
      throw new Error(`expected non-negative length, got ${len}`);
    if (len < 0x80) return w.byte(len);
    const a: number[] = [];
    for (let n = len; n > 0; n >>= 8) a.unshift(n & 0xff);
    w.byte(0x80 | a.length);
    w.bytes(Uint8Array.from(a));
  },
  decodeStream(r): number {
    const a = r.byte();
    if (a < 0x80) return a;
    const n = a & 0x7f;
    if (!n) throw new Error('DER indefinite length is not supported');
    const lb = r.bytes(n);
    let len = 0;
    for (const b of lb) len = (len << 8) | b;
    if (len < 0x80) throw new Error('DER non-minimal length encoding');
    return len;
  },
}) satisfies P.CoderType<number>;
const TLV = P.struct({ tag: P.U8, value: P.bytes(DERLen) });
const TLVNodeCodec = P.wrap({
  encodeStream(w, n: TLVNode) {
    const value = n.children
      ? concatBytes(...n.children.map((i) => TLVNodeCodec.encode(i)))
      : hexToBytes(n.valueHex || '');
    w.bytes(TLV.encode({ tag: n.tag, value }));
  },
  decodeStream(r): TLVNode {
    const t = TLV.decodeStream(r);
    if (t.tag & 0x20) {
      const items: TLVNode[] = [];
      let at = 0;
      while (at < t.value.length) {
        const src = t.value.slice(at);
        if (src.length < 2) throw new Error('constructed TLV child truncated');
        const lb = src[1];
        if (lb < 0x80) {
          const total = 2 + lb;
          items.push(TLVNodeCodec.decode(src.slice(0, total)));
          at += total;
          continue;
        }
        const n = lb & 0x7f;
        if (!n) throw new Error('DER indefinite length is not supported');
        if (src.length < 2 + n) throw new Error('constructed TLV child length truncated');
        let len = 0;
        for (let i = 0; i < n; i++) len = (len << 8) | src[2 + i];
        if (len < 0x80) throw new Error('DER non-minimal length encoding');
        const total = 2 + n + len;
        items.push(TLVNodeCodec.decode(src.slice(0, total)));
        at += total;
      }
      if (at !== t.value.length) throw new Error('constructed TLV child decode mismatch');
      return { tag: t.tag, children: items };
    }
    return { tag: t.tag, valueHex: bytesToHex(t.value) };
  },
});
// Encoded ASN.1 ANY passthrough: consume exactly one TLV from stream and keep its canonical bytes.
// This cannot be `P.bytes(null)` (greedy, would eat the rest of parent structure) and cannot be
// plain schema decode because many ANY values stay unresolved until OID-specific dispatch later.
const RawTLV = /* @__PURE__ */ P.wrap({
  encodeStream(w, v: Uint8Array) {
    const t = TLV.decode(v);
    w.bytes(TLV.encode(t));
  },
  decodeStream(r): Uint8Array {
    return TLV.encode(TLV.decodeStream(r));
  },
});
const ASCII = /* @__PURE__ */ P.apply(/* @__PURE__ */ P.bytes(null), {
  encode: (bytes: Uint8Array): string => {
    let out = '';
    for (let i = 0; i < bytes.length; i++) {
      const c = bytes[i];
      if (c > 0x7f)
        throw new Error(`bytes contain non-ASCII value 0x${c.toString(16)} at position ${i}`);
      out += String.fromCharCode(c);
    }
    return out;
  },
  decode: asciiToBytes,
}) satisfies P.CoderType<string>;
type ASN1Tagged<T> = P.CoderType<T> & {
  tagByte: number;
  tagBytes: number[];
  constructed: number;
  inner: P.CoderType<T>;
};
const tagged = <T>(tag: number, inner: P.CoderType<T>): ASN1Tagged<T> => {
  const coder = P.wrap({
    encodeStream(w, v: T) {
      w.bytes(TLV.encode({ tag, value: inner.encode(v) }));
    },
    decodeStream(r): T {
      const t = TLV.decodeStream(r);
      if (t.tag !== tag)
        throw new Error(`expected tag 0x${tag.toString(16)}, got 0x${t.tag.toString(16)}`);
      return inner.decode(t.value);
    },
  });
  return { tagByte: tag, tagBytes: [tag], constructed: 0, inner, ...coder };
};
const UTCTime: ASN1Tagged<string> = /* @__PURE__ */ tagged(0x17, ASCII);
const GeneralizedTime: ASN1Tagged<string> = /* @__PURE__ */ tagged(0x18, ASCII);
const Time: P.CoderType<{ TAG: 'utc'; data: string } | { TAG: 'generalized'; data: string }> =
  /* @__PURE__ */ ASN1.choice({ utc: UTCTime, generalized: GeneralizedTime });
// RFC 5280 section 4.1.2.5.1 and 4.1.2.5.2: cert validity uses Zulu time and fixed second precision.
const TimeRE = /^(\d{2}|\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/;
const X509Time: { decode: (der: Uint8Array) => number; encode: (ts: number) => Uint8Array } = {
  decode: (der: Uint8Array): number => {
    const t = Time.decode(der);
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
    const ms = Date.UTC(y, mo - 1, d, h, mi, s);
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
  encode: (ts: number): Uint8Array => {
    if (!Number.isFinite(ts)) throw new Error(`expected finite timestamp, got ${ts}`);
    const d = new Date(Math.floor(ts) * 1000);
    const pad2 = (n: number): string => `${n}`.padStart(2, '0');
    const pad4 = (n: number): string => `${n}`.padStart(4, '0');
    const y = d.getUTCFullYear();
    const text =
      y >= 1950 && y <= 2049
        ? `${pad2(y % 100)}${pad2(d.getUTCMonth() + 1)}${pad2(d.getUTCDate())}${pad2(d.getUTCHours())}${pad2(d.getUTCMinutes())}${pad2(d.getUTCSeconds())}Z`
        : `${pad4(y)}${pad2(d.getUTCMonth() + 1)}${pad2(d.getUTCDate())}${pad2(d.getUTCHours())}${pad2(d.getUTCMinutes())}${pad2(d.getUTCSeconds())}Z`;
    return (y >= 1950 && y <= 2049 ? UTCTime : GeneralizedTime).encode(text);
  },
} as const;
const timeEpoch = (time: P.UnwrapCoder<typeof Time>): number => X509Time.decode(Time.encode(time));
const PKCS8Attr = /* @__PURE__ */ (() =>
  ASN1.sequence({ oid: ASN1.OID, values: ASN1.set(RawTLV) }))();
type NameValue =
  | { TAG: 'utf8'; data: string }
  | { TAG: 'printable'; data: string }
  | { TAG: 'teletex'; data: string }
  | { TAG: 'ia5'; data: string }
  | { TAG: 'bmp'; data: string }
  | { TAG: 'visible'; data: string }
  | { TAG: 'numeric'; data: string };
type NameCodec = { rdns: Array<Array<{ oid: string; value: NameValue }>> };
type ValidityCodec = {
  notBefore: P.UnwrapCoder<typeof Time>;
  notAfter: P.UnwrapCoder<typeof Time>;
};
type ExtCodec = { oid: string; rest: Uint8Array };
type AlgorithmIdentifierCodec = { algorithm: string; params: TLVNode | undefined };
type TBSCertificateCodec = {
  version: bigint | undefined;
  serial: bigint;
  signature: AlgorithmIdentifierCodec;
  issuer: NameCodec;
  validity: ValidityCodec;
  subject: NameCodec;
  spki: { algorithm: AlgorithmIdentifierCodec; publicKey: Uint8Array };
  issuerUniqueID: Uint8Array | undefined;
  subjectUniqueID: Uint8Array | undefined;
  extensions: { list: ExtCodec[] } | undefined;
};
type CertificateCodec = {
  tbs: TBSCertificateCodec;
  sigAlg: AlgorithmIdentifierCodec;
  sig: Uint8Array;
};
// RFC 5280 section 4.1.1.2 and RFC 5652 sections 10.1.1/10.1.2: AlgorithmIdentifier parameters are OPTIONAL.
// `params` keeps parsed ASN.1 ANY TLV when present; `undefined` means absent.
const HasTail = /* @__PURE__ */ P.wrap({
  encodeStream() {},
  decodeStream(r): boolean {
    return !!r.leftBytes;
  },
}) satisfies P.CoderType<boolean>;
const AlgorithmIdentifier = /* @__PURE__ */ (() =>
  P.apply(
    /* @__PURE__ */ ASN1.sequence({
      algorithm: ASN1.OID,
      params: /* @__PURE__ */ P.optional(HasTail, TLVNodeCodec),
    }),
    {
      encode: (x: {
        algorithm: string;
        params: TLVNode | undefined;
      }): AlgorithmIdentifierCodec => ({
        algorithm: oidName(ALG_OID_TO_NAME, x.algorithm),
        params: x.params,
      }),
      decode: (
        x: AlgorithmIdentifierCodec
      ): { algorithm: string; params: TLVNode | undefined } => ({
        algorithm: algOID(x.algorithm),
        params: x.params,
      }),
    }
  ))() satisfies P.CoderType<AlgorithmIdentifierCodec>;
const IA5 = /* @__PURE__ */ tagged(0x16, ASCII);
const UTF8_DECODER = /* @__PURE__ */ new TextDecoder('utf-8', { fatal: true });
const UTF8_ENCODER = /* @__PURE__ */ new TextEncoder();
const UTF8String = /* @__PURE__ */ tagged(
  0x0c,
  /* @__PURE__ */ P.apply(/* @__PURE__ */ P.bytes(null), {
    // X.509 UTF8String must be valid UTF-8; reject malformed byte sequences.
    encode: (b: Uint8Array): string => UTF8_DECODER.decode(b),
    decode: (s: string): Uint8Array => UTF8_ENCODER.encode(s),
  }) satisfies P.CoderType<string>
);
const PrintableString: ASN1Tagged<string> = /* @__PURE__ */ tagged(
  0x13,
  /* @__PURE__ */ P.validate(ASCII, (s: string) => {
    if (!/^[A-Za-z0-9 '()+,./:=?-]*$/.test(s))
      throw new Error(`invalid PrintableString: ${JSON.stringify(s)}`);
    return s;
  })
);
// TeletexString (T61String) is treated as a byte-preserving 0x00..0xff mapping for interoperability.
// Strict T.61 character-set semantics are intentionally not enforced here.
const TeletexString: ASN1Tagged<string> = /* @__PURE__ */ tagged(
  0x14,
  /* @__PURE__ */ P.apply(/* @__PURE__ */ P.bytes(null), {
    encode: (b: Uint8Array): string => {
      let out = '';
      for (let i = 0; i < b.length; i++) out += String.fromCharCode(b[i]);
      return out;
    },
    decode: (s: string): Uint8Array => {
      const out = new Uint8Array(s.length);
      for (let i = 0; i < s.length; i++) {
        const c = s.charCodeAt(i);
        if (c > 0xff)
          throw new Error(`expected latin1 character, got U+${c.toString(16).toUpperCase()}`);
        out[i] = c;
      }
      return out;
    },
  }) satisfies P.CoderType<string>
);
const VisibleString = /* @__PURE__ */ tagged(0x1a, ASCII);
const NumericString: ASN1Tagged<string> = /* @__PURE__ */ tagged(
  0x12,
  /* @__PURE__ */ P.validate(ASCII, (s: string) => {
    if (!/^[0-9 ]*$/.test(s)) throw new Error(`invalid NumericString: ${JSON.stringify(s)}`);
    return s;
  })
);
const BMPString = /* @__PURE__ */ tagged(
  0x1e,
  /* @__PURE__ */ P.apply(/* @__PURE__ */ P.bytes(null), {
    encode: (b: Uint8Array): string => {
      if (b.length % 2) throw new Error('BMPString length must be even');
      let out = '';
      for (let i = 0; i < b.length; i += 2) out += String.fromCharCode((b[i] << 8) | b[i + 1]);
      return out;
    },
    decode: (s: string): Uint8Array => {
      const out = new Uint8Array(s.length * 2);
      for (let i = 0; i < s.length; i++) {
        const c = s.charCodeAt(i);
        out[i * 2] = c >>> 8;
        out[i * 2 + 1] = c & 0xff;
      }
      return out;
    },
  }) satisfies P.CoderType<string>
);
const NameString = /* @__PURE__ */ ASN1.choice({
  utf8: UTF8String,
  printable: PrintableString,
  teletex: TeletexString,
  ia5: IA5,
  bmp: BMPString,
  visible: VisibleString,
  numeric: NumericString,
});
const ATTR_NAME_OID: Record<string, string> = {
  '2.5.4.3': 'commonName',
  '2.5.4.7': 'localityName',
  '2.5.4.32': 'owner',
  '2.5.4.42': 'givenName',
  '2.5.4.106': 'otherName',
};
const QC_STATEMENT_OID: Record<string, string> = {
  '0.4.0.1862.1.1': 'etsiQcCompliance',
};
const CERT_ANY_TAG = {
  bool: 0x01,
  int: 0x02,
  oid: 0x06,
  octet: 0x04,
  utc: 0x17,
  generalized: 0x18,
} as const;
const CertAnyCodec = /* @__PURE__ */ P.apply(TLVNodeCodec, {
  encode: (n: TLVNode): CertAny => {
    const der = TLVNodeCodec.encode(n);
    if (n.tag === CERT_ANY_TAG.bool) return { TAG: 'bool', data: ASN1Bool.decode(der) };
    if (n.tag === CERT_ANY_TAG.int) return { TAG: 'int', data: ASN1.Integer.decode(der) };
    if (n.tag === CERT_ANY_TAG.oid) {
      const oid = ASN1.OID.decode(der);
      return { TAG: 'oid', data: { oid, name: ATTR_NAME_OID[oid] } };
    }
    if (n.tag === CERT_ANY_TAG.octet) return { TAG: 'octet', data: ASN1.OctetString.decode(der) };
    if (n.tag === CERT_ANY_TAG.utc || n.tag === CERT_ANY_TAG.generalized)
      return { TAG: 'time', data: Time.decode(der) };
    if (
      n.tag === UTF8String.tagByte ||
      n.tag === PrintableString.tagByte ||
      n.tag === TeletexString.tagByte ||
      n.tag === IA5.tagByte ||
      n.tag === BMPString.tagByte ||
      n.tag === VisibleString.tagByte ||
      n.tag === NumericString.tagByte
    )
      return { TAG: 'text', data: NameString.decode(der) };
    return { TAG: 'raw', data: n };
  },
  decode: (x: CertAny): TLVNode => {
    if (x.TAG === 'raw') return x.data;
    if (x.TAG === 'text') return TLVNodeCodec.decode(NameString.encode(x.data));
    if (x.TAG === 'oid') return TLVNodeCodec.decode(ASN1.OID.encode(x.data.oid));
    if (x.TAG === 'int') return TLVNodeCodec.decode(ASN1.Integer.encode(x.data));
    if (x.TAG === 'bool') return TLVNodeCodec.decode(ASN1Bool.encode(x.data));
    if (x.TAG === 'time') return TLVNodeCodec.decode(Time.encode(x.data));
    return TLVNodeCodec.decode(ASN1.OctetString.encode(x.data));
  },
}) satisfies P.CoderType<CertAny>;
const NameAttr = /* @__PURE__ */ (() => ASN1.sequence({ oid: ASN1.OID, value: NameString }))();
const X509Name = /* @__PURE__ */ ASN1.sequence({
  rdns: /* @__PURE__ */ P.array(null, /* @__PURE__ */ ASN1.set(NameAttr)),
});
const X509Validity = /* @__PURE__ */ ASN1.sequence({ notBefore: Time, notAfter: Time });
// RFC 5912 (PKIX1Explicit-2009): Extension.
const X509Ext = /* @__PURE__ */ (() =>
  ASN1.sequence({ oid: ASN1.OID, rest: /* @__PURE__ */ P.bytes(null) }))();
// RFC 5912 (PKIX1Explicit-2009): SubjectPublicKeyInfo.
const X509SPKI = /* @__PURE__ */ (() =>
  ASN1.sequence({
    algorithm: AlgorithmIdentifier,
    publicKey: ASN1.BitString,
  }))();
// RFC 5912 (PKIX1Explicit-2009): TBSCertificate.
const X509TBSCertificate = /* @__PURE__ */ (() =>
  ASN1.sequence({
    version: /* @__PURE__ */ ASN1.optional(/* @__PURE__ */ ASN1.explicit(0, ASN1.Integer)),
    serial: ASN1.Integer,
    signature: AlgorithmIdentifier,
    issuer: X509Name,
    validity: X509Validity,
    subject: X509Name,
    spki: X509SPKI,
    issuerUniqueID: /* @__PURE__ */ ASN1.optional(/* @__PURE__ */ ASN1.implicit(1, ASN1.BitString)),
    subjectUniqueID: /* @__PURE__ */ ASN1.optional(
      /* @__PURE__ */ ASN1.implicit(2, ASN1.BitString)
    ),
    extensions: /* @__PURE__ */ ASN1.optional(
      /* @__PURE__ */ ASN1.explicit(
        3,
        /* @__PURE__ */ ASN1.sequence({ list: /* @__PURE__ */ P.array(null, X509Ext) })
      )
    ),
  }))();
// RFC 5912 (PKIX1Explicit-2009): Certificate.
const X509Certificate = /* @__PURE__ */ (() =>
  ASN1.sequence({
    tbs: X509TBSCertificate,
    sigAlg: AlgorithmIdentifier,
    sig: ASN1.BitString,
  }))();
const X509C: {
  Name: P.CoderType<NameCodec>;
  TBSCertificate: P.CoderType<TBSCertificateCodec>;
  Certificate: P.CoderType<CertificateCodec>;
} = /* @__PURE__ */ (() => ({
  Name: X509Name,
  TBSCertificate: X509TBSCertificate,
  Certificate: X509Certificate,
}))();
type AttributeCodec = { oid: string; values: Uint8Array[] };
type SignerIdentifierCodec =
  | { TAG: 'issuerSerial'; data: { issuer: NameCodec; serial: bigint } }
  | { TAG: 'subjectKeyIdentifier'; data: Uint8Array };
type SignerInfoCodec = {
  version: bigint;
  sid: SignerIdentifierCodec;
  digestAlg: AlgorithmIdentifierCodec;
  signedAttrs: AttributeCodec[] | undefined;
  signatureAlg: AlgorithmIdentifierCodec;
  signature: Uint8Array;
  unsignedAttrs: AttributeCodec[] | undefined;
};
type SignedDataCodec = {
  version: bigint;
  digestAlgorithms: AlgorithmIdentifierCodec[];
  encapContentInfo: { eContentType: string; eContent: Uint8Array | undefined };
  certificates: CMSCertificateChoiceCodec[] | undefined;
  crls: CMSRevocationInfoChoiceCodec[] | undefined;
  signerInfos: SignerInfoCodec[];
};
type ContentInfoCodec = { contentType: string; content: Uint8Array };
type CMSCertificateChoiceCodec =
  | { TAG: 'certificate'; data: P.UnwrapCoder<typeof X509C.Certificate> }
  | { TAG: 'extendedCertificate'; data: Uint8Array }
  | { TAG: 'v1AttrCert'; data: Uint8Array }
  | { TAG: 'v2AttrCert'; data: Uint8Array }
  | { TAG: 'other'; data: Uint8Array };
type CMSRevocationInfoChoiceCodec =
  | {
      TAG: 'crl';
      data: {
        tbsCertList: Uint8Array;
        signatureAlgorithm: AlgorithmIdentifierCodec;
        signatureValue: Uint8Array;
      };
    }
  | { TAG: 'other'; data: { format: string; info: Uint8Array } };
// RFC 5652 section 10.2.2: CertificateChoices.
const CMSCertificateChoices: P.CoderType<CMSCertificateChoiceCodec> = /* @__PURE__ */ (() =>
  ASN1.choice({
    certificate: X509C.Certificate,
    extendedCertificate: tagged(0xa0, P.bytes(null)),
    // RFC 5652 section 12.2: ACv1 module; parsed as opaque branch and not consumed by signer-cert selection.
    v1AttrCert: tagged(0xa1, P.bytes(null)),
    v2AttrCert: tagged(0xa2, P.bytes(null)),
    other: tagged(0xa3, P.bytes(null)),
  }))();
// RFC 5652 section 10.2.1: RevocationInfoChoice and OtherRevocationInfoFormat.
const CMSCertificateList = /* @__PURE__ */ (() =>
  ASN1.sequence({
    tbsCertList: RawTLV,
    signatureAlgorithm: AlgorithmIdentifier,
    signatureValue: ASN1.BitString,
  }))();
const CMSOtherRevocationInfoFormat = /* @__PURE__ */ (() =>
  ASN1.sequence({ format: ASN1.OID, info: RawTLV }))();
const CMSRevocationInfoChoice: P.CoderType<CMSRevocationInfoChoiceCodec> = /* @__PURE__ */ (() =>
  ASN1.choice({
    crl: CMSCertificateList,
    other: ASN1.implicit(1, CMSOtherRevocationInfoFormat),
  }))();
// RFC 5652 sections 10.1.1 and 10.1.2: DigestAlgorithmIdentifier/SignatureAlgorithmIdentifier ::= AlgorithmIdentifier.
// RFC 5652 section 5.3: Attribute ::= SEQUENCE { attrType OBJECT IDENTIFIER, attrValues SET OF AttributeValue }.
const CMSAttribute = /* @__PURE__ */ (() =>
  P.validate(ASN1.sequence({ oid: ASN1.OID, values: ASN1.set(RawTLV) }), (a) => {
    // RFC 5652 section 11.1: content-type attrValues is SET SIZE (1) OF AttributeValue.
    // RFC 5652 section 11.2: message-digest attrValues is SET SIZE (1) OF AttributeValue.
    // RFC 5652 section 11.3: signing-time attrValues is SET SIZE (1) OF AttributeValue.
    const name = CMS_SIGNED_ATTR_NAME[a.oid as keyof typeof CMS_SIGNED_ATTR_NAME] || '';
    if (name && a.values.length !== 1)
      throw new Error(`${name} attribute must have exactly one value, got ${a.values.length}`);
    return a;
  }))() satisfies P.CoderType<AttributeCodec>;
// RFC 5652 section 10.2.4 (used by section 5.3 SignerIdentifier): IssuerAndSerialNumber.
const CMSIssuerAndSerial = /* @__PURE__ */ (() =>
  ASN1.sequence({
    issuer: X509C.Name,
    serial: ASN1.Integer,
  }))();
// RFC 5652 section 5.3: SignerIdentifier (IssuerAndSerialNumber / SubjectKeyIdentifier).
const CMSSignerIdentifier = /* @__PURE__ */ (() =>
  ASN1.choice({
    issuerSerial: CMSIssuerAndSerial,
    subjectKeyIdentifier: ASN1.implicit(0, ASN1.OctetString),
  }))();
// RFC 5652 section 5.3: SignerInfo.
const CMSSignerInfo = /* @__PURE__ */ (() =>
  ASN1.sequence({
    version: ASN1.Integer,
    sid: CMSSignerIdentifier,
    digestAlg: AlgorithmIdentifier,
    signedAttrs: ASN1.optional(ASN1.implicit(0, ASN1.set(CMSAttribute))),
    signatureAlg: AlgorithmIdentifier,
    signature: ASN1.OctetString,
    unsignedAttrs: ASN1.optional(ASN1.implicit(1, ASN1.set(CMSAttribute))),
  }))();
// RFC 5652 section 5.2: EncapsulatedContentInfo.
const CMSEncapContentInfo = /* @__PURE__ */ (() =>
  ASN1.sequence({
    eContentType: ASN1.OID,
    eContent: ASN1.optional(ASN1.explicit(0, ASN1.OctetString)),
  }))();
// RFC 5652 section 5.1: SignedData.
const CMSSignedData: P.CoderType<SignedDataCodec> = /* @__PURE__ */ (() =>
  ASN1.sequence({
    version: ASN1.Integer,
    digestAlgorithms: ASN1.set(AlgorithmIdentifier),
    encapContentInfo: CMSEncapContentInfo,
    // RFC 5652 section 10.2.3: CertificateSet ::= SET OF CertificateChoices.
    certificates: ASN1.optional(ASN1.implicit(0, ASN1.set(CMSCertificateChoices))),
    crls: ASN1.optional(ASN1.implicit(1, ASN1.set(CMSRevocationInfoChoice))),
    signerInfos: ASN1.set(CMSSignerInfo),
  }))();
const CMS_CONTENT_TYPE_NAME_TO_OID = {
  data: '1.2.840.113549.1.7.1',
  signedData: '1.2.840.113549.1.7.2',
  envelopedData: '1.2.840.113549.1.7.3',
} as const;
const CMS_CONTENT_TYPE_OID_TO_NAME = /* @__PURE__ */ (() =>
  Object.fromEntries(
    Object.entries(CMS_CONTENT_TYPE_NAME_TO_OID).map(([k, v]) => [v, k])
  ) as Record<string, string>)();
const cmsContentTypeOID = (v: string): string =>
  oidValue(CMS_CONTENT_TYPE_NAME_TO_OID as Record<string, string>, v, 'CMS contentType');
// RFC 5652 section 3: ContentInfo.
const CMSContentInfo = /* @__PURE__ */ (() =>
  P.apply(
    ASN1.sequence({
      contentType: ASN1.OID,
      content: ASN1.explicit(0, RawTLV),
    }),
    {
      encode: (x: { contentType: string; content: Uint8Array }): ContentInfoCodec => ({
        contentType: oidName(CMS_CONTENT_TYPE_OID_TO_NAME, x.contentType),
        content: x.content,
      }),
      decode: (x: ContentInfoCodec): { contentType: string; content: Uint8Array } => ({
        contentType: cmsContentTypeOID(x.contentType),
        content: x.content,
      }),
    }
  ))();
const CMSX: {
  AlgorithmIdentifier: P.CoderType<AlgorithmIdentifierCodec>;
  Attribute: P.CoderType<AttributeCodec>;
  SignerInfo: P.CoderType<SignerInfoCodec>;
  SignedData: P.CoderType<SignedDataCodec>;
  ContentInfo: P.CoderType<ContentInfoCodec>;
} = /* @__PURE__ */ (() => ({
  AlgorithmIdentifier: AlgorithmIdentifier,
  Attribute: CMSAttribute,
  SignerInfo: CMSSignerInfo,
  SignedData: CMSSignedData,
  ContentInfo: CMSContentInfo,
}))();
// micro-packed coders for full X.509 cert decode/encode, same exposure style as DERUtils in convert.ts
/**
 * Low-level X.509 coders used by the higher-level APIs.
 * @example
 * Use the low-level coders when you need to encode or decode individual X.509 structures.
 * ```ts
 * import { CERTUtils } from 'micro-key-producer/x509.js';
 * CERTUtils.Name.encode({
 *   rdns: [[{ oid: '2.5.4.3', value: { TAG: 'utf8', data: 'example.com' } }]],
 * });
 * ```
 */
export const CERTUtils: {
  Name: typeof X509C.Name;
  TBSCertificate: typeof X509C.TBSCertificate;
  Certificate: typeof X509C.Certificate;
} = /* @__PURE__ */ (() => ({
  Name: X509C.Name,
  TBSCertificate: X509C.TBSCertificate,
  Certificate: X509C.Certificate,
}))();

const ASN1BoolInner = /* @__PURE__ */ P.wrap({
  encodeStream(w, v: boolean) {
    w.byte(v ? 0xff : 0x00);
  },
  decodeStream(r): boolean {
    const b = r.byte();
    if (!r.isEnd()) throw new Error('BOOLEAN length must be 1');
    return b !== 0;
  },
});
const ASN1Bool = /* @__PURE__ */ (() => ({
  tagByte: 0x01,
  tagBytes: [0x01],
  constructed: 0,
  inner: ASN1BoolInner,
  ...P.wrap({
    encodeStream(w, v: boolean) {
      w.bytes(Uint8Array.from([0x01, 0x01, v ? 0xff : 0x00]));
    },
    decodeStream(r): boolean {
      const t = RawTLV.decodeStream(r);
      if (t.length !== 3 || t[0] !== 0x01 || t[1] !== 0x01)
        throw new Error('DER BOOLEAN must be 01 01 xx');
      return t[2] !== 0;
    },
  }),
}))();
const ASN1BitStringInner = /* @__PURE__ */ P.struct({
  unused: P.U8,
  bytes: /* @__PURE__ */ P.bytes(null),
});
const ASN1BitStringRaw = /* @__PURE__ */ (() => ({
  tagByte: 0x03,
  tagBytes: [0x03],
  constructed: 0,
  inner: ASN1BitStringInner,
  ...P.wrap({
    encodeStream(w, v: { unused: number; bytes: Uint8Array }) {
      w.bytes(TLV.encode({ tag: 0x03, value: ASN1BitStringInner.encode(v) }));
    },
    decodeStream(r): { unused: number; bytes: Uint8Array } {
      const t = TLV.decodeStream(r);
      if (t.tag !== 0x03) throw new Error('expected BIT STRING');
      const d = ASN1BitStringInner.decode(t.value);
      if (d.unused > 7) throw new Error(`BIT STRING invalid unused bits: ${d.unused}`);
      return d;
    },
  }),
}))();
// Generic IP coders (not ASN.1-specific): bytes <-> textual address.
const IPv4: P.CoderType<string> = /* @__PURE__ */ P.apply(/* @__PURE__ */ P.bytes(4), {
  encode: (b: Uint8Array): string => `${b[0]}.${b[1]}.${b[2]}.${b[3]}`,
  decode: (s: string): Uint8Array => {
    const p = s.split('.');
    if (p.length !== 4) throw new Error(`invalid IPv4 address ${s}`);
    const out = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
      if (!/^[0-9]+$/.test(p[i])) throw new Error(`invalid IPv4 address ${s}`);
      const n = Number(p[i]);
      if (!Number.isInteger(n) || n < 0 || n > 255) throw new Error(`invalid IPv4 address ${s}`);
      out[i] = n;
    }
    return out;
  },
}) satisfies P.CoderType<string>;
// Generic IP coders (not ASN.1-specific): bytes <-> textual address.
const IPv6: P.CoderType<string> = /* @__PURE__ */ P.apply(/* @__PURE__ */ P.bytes(16), {
  encode: (b: Uint8Array): string => {
    const w = new Array<number>(8);
    for (let i = 0; i < 8; i++) w[i] = (b[i * 2] << 8) | b[i * 2 + 1];
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
  decode: (s: string): Uint8Array => {
    if (s.includes(':::')) throw new Error(`invalid IPv6 address ${s}`);
    if ((s.match(/::/g) || []).length > 1) throw new Error(`invalid IPv6 address ${s}`);
    const [l, r] = s.split('::');
    const lp = l ? l.split(':').filter((i) => i.length) : [];
    const rp = r !== undefined && r ? r.split(':').filter((i) => i.length) : [];
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
    return out;
  },
}) satisfies P.CoderType<string>;
const IPAddress = /* @__PURE__ */ tagged(
  0x87,
  /* @__PURE__ */ P.apply(/* @__PURE__ */ P.bytes(null), {
    encode: (b: Uint8Array): string => {
      if (b.length === 4) return IPv4.decode(b);
      if (b.length === 16) return IPv6.decode(b);
      return `hex:${bytesToHex(b)}`;
    },
    decode: (s: string): Uint8Array => {
      if (s.startsWith('hex:')) return hexToBytes(s.slice(4));
      if (s.includes('.')) return IPv4.encode(s);
      if (s.includes(':')) return IPv6.encode(s);
      throw new Error(`invalid SAN iPAddress ${s}`);
    },
  }) satisfies P.CoderType<string>
);
const ExtOtherName = /* @__PURE__ */ (() =>
  ASN1.sequence({
    type: ASN1.OID,
    value: /* @__PURE__ */ ASN1.explicit(0, TLVNodeCodec),
  }))();
// RFC 5280 section 4.2.1.6: GeneralName.
const ExtGeneralName = /* @__PURE__ */ (() =>
  ASN1.choice({
    otherName: /* @__PURE__ */ ASN1.implicit(0, ExtOtherName),
    rfc822Name: /* @__PURE__ */ ASN1.implicit(1, IA5),
    dNSName: /* @__PURE__ */ ASN1.implicit(2, IA5),
    x400Address: /* @__PURE__ */ ASN1.implicit(3, ASN1.OctetString),
    directoryName: /* @__PURE__ */ ASN1.explicit(4, X509Name),
    ediPartyName: /* @__PURE__ */ ASN1.implicit(5, ASN1.OctetString),
    uniformResourceIdentifier: /* @__PURE__ */ ASN1.implicit(6, IA5),
    iPAddress: IPAddress,
    registeredID: /* @__PURE__ */ ASN1.implicit(8, ASN1.OID),
  }))();
const extNonEmpty = <T extends { list: unknown[] }>(
  coder: P.CoderType<T>,
  name: string,
  item: string
): P.CoderType<T> =>
  P.validate(coder, (x) => {
    if (!x.list.length) throw new Error(`${name} must contain at least one ${item}`);
    return x;
  });
const ExtGeneralNames = /* @__PURE__ */ ASN1.sequence({
  list: /* @__PURE__ */ P.array(null, ExtGeneralName),
});
// RFC 5280 section 4.2.1.6: subjectAltName uses GeneralNames SIZE (1..MAX).
const ExtSAN = /* @__PURE__ */ extNonEmpty(ExtGeneralNames, 'subjectAltName', 'GeneralName');
// RFC 5280 section 4.2.1.7: issuerAltName uses GeneralNames SIZE (1..MAX).
const ExtIAN = /* @__PURE__ */ extNonEmpty(ExtGeneralNames, 'issuerAltName', 'GeneralName');
// RFC 5280 section 4.2.1.1: AuthorityKeyIdentifier.
const ExtAKI = /* @__PURE__ */ (() =>
  ASN1.sequence({
    keyIdentifier: ASN1.optional(ASN1.implicit(0, ASN1.OctetString)),
    authorityCertIssuer: ASN1.optional(ASN1.implicit(1, ExtGeneralNames)),
    authorityCertSerialNumber: ASN1.optional(ASN1.implicit(2, ASN1.Integer)),
  }))();
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
const OctetsHex = /* @__PURE__ */ tagged(
  0x04,
  /* @__PURE__ */ P.apply(/* @__PURE__ */ P.bytes(null), hex)
);
const PROXY_POLICY_INHERIT_ALL = '1.3.6.1.5.5.7.21.1';
const PROXY_POLICY_INDEPENDENT = '1.3.6.1.5.5.7.21.2';
const ExtProxyCertInfo = /* @__PURE__ */ (() =>
  ASN1.sequence({
    pathLen: ASN1.optional(ASN1.Integer),
    policy: ASN1.sequence({ language: ASN1.OID, policy: ASN1.optional(OctetsHex) }),
  }))();
const ExtProxyCertInfoChecked = /* @__PURE__ */ P.validate(ExtProxyCertInfo, (x) => {
  // RFC 3820 section 3.8.1: pCPathLenConstraint is INTEGER (0..MAX) when present.
  if (x.pathLen !== undefined && x.pathLen < 0n)
    throw new Error('proxyCertInfo pCPathLenConstraint must be >= 0');
  // RFC 3820 section 3.8.2: inheritAll/independent MUST NOT carry policy bytes.
  if (
    (x.policy.language === PROXY_POLICY_INHERIT_ALL ||
      x.policy.language === PROXY_POLICY_INDEPENDENT) &&
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
      if (f < 0n || f > 65535n) throw new Error(`tlsFeature value must be in 0..65535, got ${f}`);
    }
    return x;
  }))() satisfies P.CoderType<{ list: bigint[] }>;
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
const SCTListInner = /* @__PURE__ */ (() =>
  P.validate(
    P.apply(P.bytes(null), {
      encode: (b: Uint8Array): P.UnwrapCoder<typeof SCTItem>[] =>
        // RFC 6962 section 3.3: X.509 extension carries SignedCertificateTimestampList inside ASN.1 OCTET STRING.
        P.prefix(P.U16BE, P.array(null, P.prefix(P.U16BE, SCTItem))).decode(
          b.length && b[0] === 0x04 ? ASN1.OctetString.decode(b) : b
        ),
      decode: (v: P.UnwrapCoder<typeof SCTItem>[]): Uint8Array =>
        P.prefix(P.U16BE, P.array(null, P.prefix(P.U16BE, SCTItem))).encode(v),
    }),
    (x) => {
      // RFC 6962 section 3.3: SignedCertificateTimestampList.sct_list is <1..2^16-1>.
      if (!x.length) throw new Error('sct list must contain at least one SerializedSCT');
      // RFC 6962 section 3.2: sct_version for v1 is 0.
      for (const sct of x) {
        if (sct.version !== 0) throw new Error(`sct_version must be v1 (0), got ${sct.version}`);
      }
      return x;
    }
  ))() satisfies P.CoderType<P.UnwrapCoder<typeof SCTItem>[]>;
// RFC 5280 section 4.2.1.13: DistributionPointName.
const ExtDistributionPointName = /* @__PURE__ */ (() =>
  ASN1.choice({
    fullName: ASN1.implicit(0, ExtGeneralNames),
    nameRelativeToCRLIssuer: ASN1.implicit(1, ASN1.set(NameAttr)),
  }))();
// RFC 5280 section 4.2.1.13: DistributionPoint and CRLDistributionPoints.
const ExtCRLDP = /* @__PURE__ */ (() =>
  P.validate(
    ASN1.sequence({
      list: P.array(
        null,
        ASN1.sequence({
          distributionPoint: ASN1.optional(ASN1.explicit(0, ExtDistributionPointName)),
          reasons: ASN1.optional(ASN1.implicit(1, ASN1BitStringRaw)),
          cRLIssuer: ASN1.optional(ASN1.implicit(2, ExtGeneralNames)),
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
      }
      return x;
    }
  ))() satisfies P.CoderType<{
  list: {
    distributionPoint: P.UnwrapCoder<typeof ExtDistributionPointName> | undefined;
    reasons: P.UnwrapCoder<typeof ASN1BitStringRaw> | undefined;
    cRLIssuer: P.UnwrapCoder<typeof ExtGeneralNames> | undefined;
  }[];
}>;
const oidSet = <T extends Record<string, readonly [string, unknown]>>(map: T): Set<string> =>
  new Set((Object.values(map) as ReadonlyArray<readonly [string, unknown]>).map((v) => v[0]));
const oidDecode = <T>(
  coder: P.CoderType<T>,
  set: Set<string>
): ((id: string, val: Uint8Array) => T | undefined) => {
  return (id, val) =>
    set.has(id) ? coder.decode(concatBytes(ASN1.OID.encode(id), val)) : undefined;
};
const DisplayText = /* @__PURE__ */ ASN1.choice({
  utf8: UTF8String,
  ia5: IA5,
  visible: VisibleString,
  bmp: BMPString,
});
const PolicyNoticeRef = /* @__PURE__ */ (() =>
  ASN1.sequence({
    organization: DisplayText,
    numbers: /* @__PURE__ */ ASN1.sequence({ list: /* @__PURE__ */ P.array(null, ASN1.Integer) }),
  }))();
type PolicyUserNotice = Extract<CertPolicyQualifier, { TAG: 'userNotice' }>['data'];
const PolicyQualifierInfoRaw = /* @__PURE__ */ (() =>
  ASN1.sequence({ oid: ASN1.OID, value: RawTLV }))();
const PolicyQualifierUserNotice = /* @__PURE__ */ P.apply(
  /* @__PURE__ */ ASN1.sequence({
    noticeRef: /* @__PURE__ */ ASN1.optional(PolicyNoticeRef),
    explicitText: /* @__PURE__ */ P.optional(HasTail, DisplayText),
  }),
  {
    encode: (n): PolicyUserNotice => ({
      noticeRef: n.noticeRef
        ? {
            organization: {
              tag: n.noticeRef.organization.TAG,
              text: n.noticeRef.organization.data,
            },
            numbers: n.noticeRef.numbers.list.map((v) => Number(v)),
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
            } as P.UnwrapCoder<typeof DisplayText>,
            numbers: { list: d.noticeRef.numbers.map((n) => BigInt(n)) },
          }
        : undefined,
      explicitText: d.explicitText
        ? ({ TAG: d.explicitText.tag, data: d.explicitText.text } as P.UnwrapCoder<
            typeof DisplayText
          >)
        : undefined,
    }),
  }
) satisfies P.CoderType<PolicyUserNotice>;
const PolicyQualifierKnownMap = {
  cps: ['1.3.6.1.5.5.7.2.1', IA5],
  userNotice: ['1.3.6.1.5.5.7.2.2', PolicyQualifierUserNotice],
} as const;
const PolicyQualifierByOID = /* @__PURE__ */ (() =>
  ({
    [PolicyQualifierKnownMap.cps[0]]: { TAG: 'cps', coder: PolicyQualifierKnownMap.cps[1] },
    [PolicyQualifierKnownMap.userNotice[0]]: {
      TAG: 'userNotice',
      coder: PolicyQualifierKnownMap.userNotice[1],
    },
  }) as const)();
const ExtPolicyQualifierInfo = /* @__PURE__ */ P.apply(PolicyQualifierInfoRaw, {
  encode: (x: P.UnwrapCoder<typeof PolicyQualifierInfoRaw>): CertPolicyQualifier => {
    const d = PolicyQualifierByOID[x.oid as keyof typeof PolicyQualifierByOID];
    if (d) return { TAG: d.TAG, data: d.coder.decode(x.value) } as CertPolicyQualifier;
    return { TAG: 'unknown', data: { oid: x.oid, value: TLVNodeCodec.decode(x.value) } };
  },
  decode: (q: CertPolicyQualifier): P.UnwrapCoder<typeof PolicyQualifierInfoRaw> => {
    if (q.TAG === 'unknown') return { oid: q.data.oid, value: TLVNodeCodec.encode(q.data.value) };
    if (q.TAG === 'cps')
      return {
        oid: PolicyQualifierKnownMap.cps[0],
        value: PolicyQualifierKnownMap.cps[1].encode(q.data),
      };
    return {
      oid: PolicyQualifierKnownMap.userNotice[0],
      value: PolicyQualifierKnownMap.userNotice[1].encode(q.data),
    };
  },
}) satisfies P.CoderType<CertPolicyQualifier>;
// RFC 5280 section 4.2.1.4: CertificatePolicies.
const ExtPolicies = /* @__PURE__ */ (() =>
  P.validate(
    ASN1.sequence({
      list: P.array(
        null,
        ASN1.sequence({
          policy: ASN1.OID,
          qualifiers: ASN1.optional(ASN1.sequence({ list: P.array(null, ExtPolicyQualifierInfo) })),
        })
      ),
    }),
    (x) => {
      // RFC 5280 section 4.2.1.4: certificatePolicies and policyQualifiers are SIZE (1..MAX).
      if (!x.list.length)
        throw new Error('certificatePolicies must contain at least one PolicyInformation');
      for (const p of x.list) {
        if (p.qualifiers && !p.qualifiers.list.length)
          throw new Error(
            'policyQualifiers must contain at least one PolicyQualifierInfo when present'
          );
      }
      return x;
    }
  ))() satisfies P.CoderType<{
  list: {
    policy: string;
    qualifiers: { list: CertPolicyQualifier[] } | undefined;
  }[];
}>;
const ExtGeneralSubtree = /* @__PURE__ */ (() =>
  ASN1.sequence({
    base: ExtGeneralName,
    minimum: /* @__PURE__ */ ASN1.optional(/* @__PURE__ */ ASN1.implicit(0, ASN1.Integer)),
    maximum: /* @__PURE__ */ ASN1.optional(/* @__PURE__ */ ASN1.implicit(1, ASN1.Integer)),
  }))();
// RFC 5280 section 4.2.1.10: NameConstraints.
const ExtNameConstraints = /* @__PURE__ */ (() =>
  P.validate(
    ASN1.sequence({
      permitted: ASN1.optional(
        ASN1.explicit(0, ASN1.sequence({ list: P.array(null, ExtGeneralSubtree) }))
      ),
      excluded: ASN1.optional(
        ASN1.explicit(1, ASN1.sequence({ list: P.array(null, ExtGeneralSubtree) }))
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
        if (g.minimum !== undefined && g.minimum !== 0n)
          throw new Error('nameConstraints GeneralSubtree.minimum must be 0 in this profile');
      }
      return x;
    }
  ))() satisfies P.CoderType<{
  permitted: { list: P.UnwrapCoder<typeof ExtGeneralSubtree>[] } | undefined;
  excluded: { list: P.UnwrapCoder<typeof ExtGeneralSubtree>[] } | undefined;
}>;
const ExtSubjectDirectoryAttributes = /* @__PURE__ */ (() =>
  P.apply(
    P.validate(
      ASN1.sequence({
        list: P.array(null, ASN1.sequence({ type: ASN1.OID, values: ASN1.set(CertAnyCodec) })),
      }),
      (x) => {
        // RFC 5280 section 4.2.1.8: SubjectDirectoryAttributes is SEQUENCE SIZE (1..MAX) OF Attribute.
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
    ),
    {
      encode: (x) => ({
        list: x.list.map((i) => ({
          type: i.type,
          typeName: ATTR_NAME_OID[i.type],
          values: i.values,
        })),
      }),
      decode: (x: { list: { type: string; typeName?: string; values: CertAny[] }[] }) => ({
        list: x.list.map((i) => ({ type: i.type, values: i.values })),
      }),
    }
  ))() satisfies P.CoderType<{ list: { type: string; typeName?: string; values: CertAny[] }[] }>;
const ExtPrivateKeyUsagePeriod = /* @__PURE__ */ (() =>
  ASN1.sequence({
    notBefore: ASN1.optional(ASN1.implicit(0, GeneralizedTime)),
    notAfter: ASN1.optional(ASN1.implicit(1, GeneralizedTime)),
  }))();
const ExtIssuingDistributionPoint = /* @__PURE__ */ (() =>
  ASN1.sequence({
    distributionPoint: ASN1.optional(ASN1.explicit(0, ExtDistributionPointName)),
    onlyContainsUserCerts: ASN1.optional(ASN1.implicit(1, ASN1Bool)),
    onlyContainsCACerts: ASN1.optional(ASN1.implicit(2, ASN1Bool)),
    onlySomeReasons: ASN1.optional(ASN1.implicit(3, ASN1BitStringRaw)),
    indirectCRL: ASN1.optional(ASN1.implicit(4, ASN1Bool)),
    onlyContainsAttributeCerts: ASN1.optional(ASN1.implicit(5, ASN1Bool)),
  }))();
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
const POLICY_ANY = '2.5.29.32.0';
const ExtPolicyMappingsChecked = /* @__PURE__ */ (() =>
  P.validate(ExtPolicyMappings, (x) => {
    // RFC 5280 section 4.2.1.5: policyMappings is SIZE (1..MAX), and either side MUST NOT be anyPolicy.
    if (!x.list.length) throw new Error('policyMappings must contain at least one mapping');
    for (const m of x.list) {
      if (m.issuerDomainPolicy === POLICY_ANY || m.subjectDomainPolicy === POLICY_ANY)
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
      if (x.requireExplicitPolicy !== undefined && x.requireExplicitPolicy < 0n)
        throw new Error('policyConstraints requireExplicitPolicy must be >= 0');
      // RFC 5280 section 4.2.1.11 / ASN.1: both fields are SkipCerts ::= INTEGER (0..MAX).
      if (x.inhibitPolicyMapping !== undefined && x.inhibitPolicyMapping < 0n)
        throw new Error('policyConstraints inhibitPolicyMapping must be >= 0');
      return x;
    }
  ))() satisfies P.CoderType<{
  requireExplicitPolicy: bigint | undefined;
  inhibitPolicyMapping: bigint | undefined;
}>;
const ExtQCStatements = /* @__PURE__ */ (() =>
  P.apply(
    ASN1.sequence({
      list: P.array(
        null,
        ASN1.sequence({
          statementId: ASN1.OID,
          statementInfo: P.optional(HasTail, CertAnyCodec),
        })
      ),
    }),
    {
      encode: (x) => ({
        list: x.list.map((i) => ({
          statementId: i.statementId,
          statementName: QC_STATEMENT_OID[i.statementId],
          statementInfo: i.statementInfo,
        })),
      }),
      decode: (x: {
        list: { statementId: string; statementName?: string; statementInfo?: CertAny }[];
      }) => ({
        list: x.list.map((i) => ({ statementId: i.statementId, statementInfo: i.statementInfo })),
      }),
    }
  ))() satisfies P.CoderType<{
  list: { statementId: string; statementName?: string; statementInfo?: CertAny }[];
}>;
const ExtBody = /* @__PURE__ */ (() =>
  ASN1.sequence({ critical: ASN1.optional(ASN1Bool), extnValue: ASN1.OctetString }))();
const ExtBasic = /* @__PURE__ */ (() =>
  P.validate(
    /* @__PURE__ */ ASN1.sequence({
      ca: /* @__PURE__ */ ASN1.optional(ASN1Bool),
      pathLen: /* @__PURE__ */ ASN1.optional(ASN1.Integer),
    }),
    (x) => {
      // RFC 5280 section 4.2.1.9: pathLenConstraint MUST be >= 0 and only meaningful with cA asserted.
      if (x.pathLen !== undefined && x.pathLen < 0n)
        throw new Error('basicConstraints pathLenConstraint must be >= 0');
      // RFC 5280 section 4.2.1.9: CAs MUST NOT include pathLenConstraint unless cA is asserted.
      if (x.pathLen !== undefined && !x.ca)
        throw new Error('basicConstraints pathLenConstraint requires cA=true');
      return x;
    }
  ))() satisfies P.CoderType<{ ca: boolean | undefined; pathLen: bigint | undefined }>;
const EKU_OID_TO_NAME: Record<string, string> = {
  '2.5.29.37.0': 'anyExtendedKeyUsage',
  '1.3.6.1.5.5.7.3.4': 'emailProtection',
  '1.3.6.1.5.5.7.3.3': 'codeSigning',
};
const EKU_NAME_TO_OID = /* @__PURE__ */ Object.fromEntries(
  /* @__PURE__ */ Object.entries(EKU_OID_TO_NAME).map(([oid, name]) => [name, oid])
) as Record<string, string>;
const ExtEKU = /* @__PURE__ */ (() =>
  P.apply(/* @__PURE__ */ ASN1.sequence({ list: /* @__PURE__ */ P.array(null, ASN1.OID) }), {
    encode: (x) => ({ list: x.list.map((oid) => EKU_OID_TO_NAME[oid] || `OID:${oid}`) }),
    decode: (x: { list: string[] }) => ({
      list: x.list.map((name) => {
        if (EKU_NAME_TO_OID[name]) return EKU_NAME_TO_OID[name];
        if (name.startsWith('OID:')) return name.slice(4);
        if (/^[0-9]+(?:\.[0-9]+)+$/.test(name)) return name;
        throw new Error(`unknown EKU name ${name}`);
      }),
    }),
  }))() satisfies P.CoderType<{ list: string[] }>;
const ExtKnownMap: Record<string, [string, P.CoderType<any>]> = /* @__PURE__ */ (() => ({
  ski: ['2.5.29.14', ASN1.OctetString],
  basic: ['2.5.29.19', ExtBasic],
  keyUsage: ['2.5.29.15', ASN1BitStringRaw],
  eku: ['2.5.29.37', ExtEKU],
  san: ['2.5.29.17', ExtSAN],
  aki: ['2.5.29.35', ExtAKI],
  aia: ['1.3.6.1.5.5.7.1.1', ExtAIA],
  proxyCertInfo: ['1.3.6.1.5.5.7.1.14', ExtProxyCertInfoChecked],
  tlsFeature: ['1.3.6.1.5.5.7.1.24', ExtTLSFeature],
  sct: ['1.3.6.1.4.1.11129.2.4.2', SCTListInner],
  crlDistributionPoints: ['2.5.29.31', ExtCRLDP],
  policies: ['2.5.29.32', ExtPolicies],
  nameConstraints: ['2.5.29.30', ExtNameConstraints],
  subjectDirectoryAttributes: ['2.5.29.9', ExtSubjectDirectoryAttributes],
  privateKeyUsagePeriod: ['2.5.29.16', ExtPrivateKeyUsagePeriod],
  issuerAltName: ['2.5.29.18', ExtIAN],
  issuingDistributionPoint: ['2.5.29.28', ExtIssuingDistributionPoint],
  certificateIssuer: ['2.5.29.29', ExtGeneralNames],
  policyMappings: ['2.5.29.33', ExtPolicyMappingsChecked],
  policyConstraints: ['2.5.29.36', ExtPolicyConstraints],
  freshestCRL: ['2.5.29.46', ExtCRLDP],
  inhibitAnyPolicy: ['2.5.29.54', ASN1.Integer],
  qcStatements: ['1.3.6.1.5.5.7.1.3', ExtQCStatements],
  subjectInfoAccess: ['1.3.6.1.5.5.7.1.11', ExtSIA],
  msCertType: ['1.3.6.1.4.1.311.21.1', CertAnyCodec],
}))();
const bitFlags = <T extends Record<string, number>>(
  bs: { unused: number; bytes: Uint8Array },
  ix: T,
  name: string
): { [K in keyof T]: boolean } => {
  if (bs.unused > 7) throw new Error(`${name} BIT STRING invalid unused bits: ${bs.unused}`);
  const bits = P.array(bs.bytes.length * 8, P.bits(1)).decode(bs.bytes);
  const used = bits.length - bs.unused;
  const get = (i: number): boolean => (i < used ? !!bits[i] : false);
  const out: Partial<{ [K in keyof T]: boolean }> = {};
  for (const k in ix) out[k] = get(ix[k]);
  return out as { [K in keyof T]: boolean };
};
const keyUsageBits = (bs: {
  unused: number;
  bytes: Uint8Array;
}): {
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
const ExtValueByOID = /* @__PURE__ */ (() => P.mappedTag(ASN1.OID, ExtKnownMap))();
const extValueDecode = /* @__PURE__ */ (() => oidDecode(ExtValueByOID, oidSet(ExtKnownMap)))();

export const X509: {
  decode: (der: Uint8Array, opts?: BEROpts) => Cert;
  encode: (cert: Cert) => Uint8Array;
  extensions: (cert: Cert) => CertExt[];
} = /* @__PURE__ */ (() =>
  ({
    decode: (der: Uint8Array, opts: BEROpts = {}): Cert =>
      X509C.Certificate.decode(berView(der, opts).der),
    encode: (cert: Cert): Uint8Array => X509C.Certificate.encode(cert),
    extensions: (cert: Cert): CertExt[] => {
      const out: CertExt[] = [];
      for (const e of cert.tbs.extensions?.list || []) {
        const body = ExtBody.inner.decode(e.rest);
        const d: CertExt = { oid: e.oid, critical: !!body.critical };
        const k = extValueDecode(e.oid, body.extnValue);
        if (k) (d as Record<string, unknown>)[k.TAG] = k.data;
        out.push(d);
      }
      return out;
    },
  }) as const)();
const knownCritical = /* @__PURE__ */ (() => oidSet(ExtKnownMap))();
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
const subjectDer = (cert: Cert): Uint8Array => X509C.Name.encode(cert.tbs.subject);
const ensureCritical = (c: Cert): void => {
  // RFC 5280 section 4.2: unrecognized critical extensions require certificate rejection.
  for (const oid of certInfo(c).critical) {
    if (!knownCritical.has(oid)) throw new Error(`unknown critical extension ${oid}`);
  }
};
const ECDSASig = /* @__PURE__ */ (() => ASN1.sequence({ r: ASN1.Integer, s: ASN1.Integer }))();

const cmsSignedData = (
  src: Uint8Array
): {
  contentInfo: P.UnwrapCoder<typeof CMSX.ContentInfo>;
  signedData: P.UnwrapCoder<typeof CMSX.SignedData>;
} => {
  const contentInfo = CMSX.ContentInfo.decode(src);
  // RFC 5652 section 3: contentType identifies the associated [0] EXPLICIT content payload type.
  // RFC 5652 sections 10.2.6 (UserKeyingMaterial/UKM) and 10.2.7 (OtherKeyAttribute)
  // apply to recipient/key-management flows under EnvelopedData, which are intentionally
  // unsupported in this signed-data-only API.
  if (cmsContentTypeOID(contentInfo.contentType) !== CMSOID.signedData)
    throw new Error(`expected SignedData contentType, got ${contentInfo.contentType}`);
  // RFC 5652 section 5.2.1: PKCS #7 compatibility fallback to `content ANY` is MAY, not MUST.
  // This implementation is strict CMS-only and intentionally does not attempt PKCS #7 ANY fallback decode.
  const signedData = CMSX.SignedData.decode(contentInfo.content);
  // RFC 5652 section 10.2.5: CMSVersion ::= INTEGER { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }.
  const badSignedVersion = signedData.version < 0n || signedData.version > 5n;
  if (badSignedVersion)
    throw new Error(`SignedData.version CMSVersion must be in v0..v5, got ${signedData.version}`);
  for (const si of signedData.signerInfos) {
    if (si.version < 0n || si.version > 5n)
      throw new Error(`SignerInfo.version CMSVersion must be in v0..v5, got ${si.version}`);
  }
  // RFC 5652 section 5.1: SignedData.version depends on cert/crl choices, signer versions, and eContentType.
  const signedDataVersion = (() => {
    const certs = signedData.certificates || [];
    const crls = signedData.crls || [];
    if (certs.some((i) => i.TAG === 'other') || crls.some((i) => i.TAG === 'other')) return 5n;
    if (certs.some((i) => i.TAG === 'v2AttrCert')) return 4n;
    if (
      certs.some((i) => i.TAG === 'v1AttrCert') ||
      signedData.signerInfos.some((i) => i.version === 3n) ||
      signedData.encapContentInfo.eContentType !== CMSOID.data
    )
      return 3n;
    return 1n;
  })();
  if (signedData.version !== signedDataVersion)
    throw new Error(`SignedData.version must be ${signedDataVersion}, got ${signedData.version}`);
  // RFC 5652 section 5.3: signedAttrs MUST be present when encapContentInfo.eContentType is not id-data.
  if (signedData.encapContentInfo.eContentType !== CMSOID.data) {
    for (const signerInfo of signedData.signerInfos) {
      if (!signerInfo.signedAttrs)
        throw new Error('SignerInfo.signedAttrs must be present when eContentType is not id-data');
    }
  }
  // RFC 5652 section 5.1: digestAlgorithms is the collection of digest algorithm identifiers for SignerInfos.
  for (const signerInfo of signedData.signerInfos) {
    const hasDigest = signedData.digestAlgorithms.some((d) =>
      digestAlgEqual(d, signerInfo.digestAlg)
    );
    if (!hasDigest)
      throw new Error('SignedData.digestAlgorithms must include each SignerInfo.digestAlgorithm');
  }
  // RFC 5652 section 5.2: degenerate SignedData (no signers) MUST be id-data with omitted eContent.
  if (
    signedData.signerInfos.length === 0 &&
    (signedData.encapContentInfo.eContentType !== CMSOID.data ||
      signedData.encapContentInfo.eContent)
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
  // RFC 5652 section 5.1 makes CertificateSet optional; this API profile requires certs in SignedData.
  if (!certs.length) throw new Error('SignedData.certificates missing');
  return certs;
};
const cmsSignerInfo = (
  signedData: P.UnwrapCoder<typeof CMSX.SignedData>
): P.UnwrapCoder<typeof CMSX.SignerInfo> => {
  // RFC 5652 section 5.1 allows SET OF SignerInfo; this API profile is single-signer only.
  if (signedData.signerInfos.length !== 1)
    throw new Error(
      `this API supports exactly one SignerInfo, got ${signedData.signerInfos.length}`
    );
  // RFC 5652 section 5.3: SignerInfo.version is coupled to SignerIdentifier choice.
  // issuerAndSerialNumber => version 1, subjectKeyIdentifier => version 3.
  const signerInfo = signedData.signerInfos[0];
  if (!signerInfo) throw new Error('SignerInfo[0] missing');
  // RFC 5652 section 12.1: SignedAttributes/UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute.
  if (signerInfo.signedAttrs && signerInfo.signedAttrs.length === 0)
    throw new Error('SignedAttributes present but empty');
  if (signerInfo.unsignedAttrs && signerInfo.unsignedAttrs.length === 0)
    throw new Error('UnsignedAttributes present but empty');
  if (signerInfo.sid.TAG === 'issuerSerial' && signerInfo.version !== 1n)
    throw new Error(`SignerInfo.version must be 1 for issuerSerial SID, got ${signerInfo.version}`);
  if (signerInfo.sid.TAG === 'subjectKeyIdentifier') {
    if (!signerInfo.sid.data.length)
      throw new Error('SignerInfo.sid subjectKeyIdentifier must be non-empty');
    if (signerInfo.version !== 3n)
      throw new Error(
        `SignerInfo.version must be 3 for subjectKeyIdentifier SID, got ${signerInfo.version}`
      );
  }
  return signerInfo;
};
const cmsVerifyEc = (der: Uint8Array, opts: CmsVerifyOpts = {}): CmsVerify => {
  // RFC 5280 section 6 support profile in this verifier:
  // - implemented subset: validity windows, issuer chaining, basic constraints, key usage, AKI/SKI linkage,
  //   critical-extension handling, and (when checkSignatures=true) certificate-signature continuity checks.
  // - not implemented: full policy-tree processing and full name-constraints path processing.
  //   those controls are fail-closed when present (see checkCoreCertFields).
  const verifyIssuedCert = (child: Cert, issuer: Cert): void => {
    // RFC 5280 section 6.1.3(a)(1): verify each cert signature with issuer public key.
    const key = certSpkiKey(issuer.tbs.spki);
    const msg = X509C.TBSCertificate.encode(child.tbs);
    const sigOid = algOID(child.sigAlg.algorithm);
    const alg = CMS_ALG_BY_SIG_OID[sigOid as CmsAlg['sigOid']];
    if (!alg) throw new Error(`unsupported certificate signatureAlgorithm OID ${sigOid}`);
    if (key.algorithm.info.TAG === 'EC') {
      if (!('ec' in alg))
        throw new Error(
          `certificate signatureAlgorithm OID ${sigOid} is not compatible with EC issuer key`
        );
      if (child.sigAlg.params && sigOid.startsWith('1.2.840.10045.4.3.'))
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
    const v = cert.tbs.version === undefined ? 0n : cert.tbs.version;
    if (v < 0n || v > 2n) throw new Error(`${where}: certificate version must be 0..2, got ${v}`);
    // RFC 5280 section 4.1.2.8: issuer/subject unique identifiers MUST NOT appear in v1 certificates.
    if (v === 0n && (cert.tbs.issuerUniqueID || cert.tbs.subjectUniqueID))
      throw new Error(`${where}: certificate unique identifiers require version v2 or v3`);
    // RFC 5280 section 4.1 / 4.1.2.1: TBSCertificate.extensions [3] is only valid for v3 certificates.
    if (v < 2n && cert.tbs.extensions)
      throw new Error(`${where}: certificate extensions require version v3`);
    // RFC 5280 section 4.1.2.2: certificate serialNumber MUST be a positive INTEGER.
    if (cert.tbs.serial <= 0n)
      throw new Error(`${where}: certificate serialNumber must be positive`);
    // RFC 5280 section 4.1.2.2: conforming CAs MUST NOT use serialNumber values longer than 20 octets.
    const serialBytes = TLV.decode(ASN1.Integer.encode(cert.tbs.serial)).value.length;
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
        AlgorithmIdentifier.encode(cert.tbs.signature),
        AlgorithmIdentifier.encode(cert.sigAlg)
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
    const iap = exts.find((e) => e.oid === '2.5.29.54');
    if (iap && !iap.critical)
      throw new Error(`${where}: inhibitAnyPolicy extension must be critical`);
    // RFC 5280 section 6 policy/name processing (policy tree + name constraints checks) is not implemented in this verifier.
    const pm = exts.find((e) => e.policyMappings);
    if (nc || pc || iap || pm)
      throw new Error(
        `${where}: nameConstraints/policyMappings/policyConstraints/inhibitAnyPolicy present but RFC 5280 section 6 processing is not implemented`
      );
  };
  const { checkSignatures = true } = opts;
  const { signedData } = cmsSignedData(berView(der, opts).der);
  const certs = cmsCerts(signedData);
  const signerInfo = cmsSignerInfo(signedData);
  const oneMatch = (
    test: (c: Cert) => boolean,
    msg:
      | 'SignerInfo.sid issuerSerial matched multiple certificates'
      | 'SignerInfo.sid subjectKeyIdentifier matched multiple certificates'
  ): Cert | undefined => {
    const matches = certs.filter(test);
    if (matches.length > 1) throw new Error(msg);
    return matches[0];
  };
  const signerCert = (() => {
    const sid = signerInfo.sid;
    if (sid.TAG === 'issuerSerial') {
      const sIssuer = X509C.Name.encode(sid.data.issuer);
      return oneMatch((c) => {
        const m = { issuer: X509C.Name.encode(c.tbs.issuer), serial: c.tbs.serial };
        return equalBytes(sIssuer, m.issuer) && sid.data.serial === m.serial;
      }, 'SignerInfo.sid issuerSerial matched multiple certificates');
    }
    return oneMatch((c) => {
      const ski = X509.extensions(c).find((e) => e.ski)?.ski;
      return ski ? equalBytes(ski, sid.data) : false;
    }, 'SignerInfo.sid subjectKeyIdentifier matched multiple certificates');
  })();
  if (!signerCert) throw new Error('SignerInfo cert not found in certificate set');
  const signer = X509.decode(X509C.Certificate.encode(signerCert), opts);
  checkCoreCertFields(signer, 'signer');
  const nowMs = opts.time === undefined ? Date.now() : opts.time;
  if (!Number.isSafeInteger(nowMs))
    throw new Error(`expected safe integer time in milliseconds, got ${nowMs}`);
  const now = Math.floor(nowMs / 1000);
  if (
    now < timeEpoch(signer.tbs.validity.notBefore) ||
    now > timeEpoch(signer.tbs.validity.notAfter)
  )
    // RFC 5280 section 6.1.3(a)(2): certificate validity period must include validation time.
    throw new Error('signer certificate outside validity window');
  const signerCertInfo = certInfo(signer);
  // This API profile requires an end-entity signer certificate (not a CA certificate).
  if (signerCertInfo.isCA) throw new Error('signer certificate must not be a CA certificate');
  // RFC 5280 section 4.2.1.3: signer key usage must allow digitalSignature for CMS signature validation.
  if (signerCertInfo.keyUsage && !signerCertInfo.keyUsage.digitalSignature)
    throw new Error('signer keyUsage missing digitalSignature');
  const purpose = opts.purpose || 'any';
  const eku = signerCertInfo.eku;
  // RFC 5280 section 4.2.1.12: if EKU is present, certificate use is constrained to listed purposes
  // (except anyExtendedKeyUsage).
  if (eku && purpose !== 'any' && !eku.has('anyExtendedKeyUsage')) {
    if (purpose === 'smime' && !eku.has('emailProtection'))
      throw new Error('EKU missing emailProtection');
    if (purpose === 'codeSigning' && !eku.has('codeSigning'))
      throw new Error('EKU missing codeSigning');
  }
  ensureCritical(signer);
  const chainSrc = opts.chain || [];
  const chainItems = chainSrc.map((c) => {
    if (typeof c === 'string') return X509.decode(onePem(c, 'CERTIFICATE').der, opts);
    if (c instanceof Uint8Array) return X509.decode(c, opts);
    return X509.decode(X509C.Certificate.encode(c), opts);
  });
  const pool = [
    ...certs.map((c) => X509.decode(X509C.Certificate.encode(c), opts)),
    ...chainItems,
  ].filter(
    (c) => !(equalBytes(subjectDer(c), subjectDer(signer)) && c.tbs.serial === signer.tbs.serial)
  );
  for (const c of pool) ensureCritical(c);
  const seen = new Set<string>();
  const chain: Cert[] = [signer];
  let cur = signer;
  while (true) {
    const id = `${base64.encode(subjectDer(cur))}:${cur.tbs.serial.toString(16)}`;
    if (seen.has(id)) throw new Error('certificate chain loop detected');
    seen.add(id);
    const curIssuer = X509C.Name.encode(cur.tbs.issuer);
    const curSubject = subjectDer(cur);
    if (equalBytes(curIssuer, curSubject)) break;
    if (now < timeEpoch(cur.tbs.validity.notBefore) || now > timeEpoch(cur.tbs.validity.notAfter))
      // RFC 5280 section 6.1.3(a)(2): each certificate in the path must be valid at validation time.
      throw new Error(`certificate not valid at time: ${base64.encode(curSubject)}`);
    const curAki = X509.extensions(cur).find((e) => e.aki)?.aki;
    const candidatesAll = pool.filter((i) => equalBytes(curIssuer, subjectDer(i)));
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
      if (!checkSignatures || !chainItems.length) break;
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
          authorityCertIssuerOk = names.some((n) =>
            equalBytes(X509C.Name.encode(n.data), subjectDer(issuer))
          );
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
    // RFC 5280 section 4.2.1.3: CA cert used to issue certs must allow keyCertSign.
    if (issuerInfo.keyUsage && !issuerInfo.keyUsage.keyCertSign)
      throw new Error('issuer keyUsage missing keyCertSign');
    // RFC 5280 section 4.2.1.9 and section 6.1.4(m): pathLenConstraint limits only
    // non-self-issued CA certs below this issuer in the candidate path.
    const pathLenUsed = chain.reduce((acc, c) => {
      const isCA = certInfo(c).isCA;
      const selfIssued = equalBytes(X509C.Name.encode(c.tbs.issuer), subjectDer(c));
      return isCA && !selfIssued ? acc + 1n : acc;
    }, 0n);
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
    signatureOid: algOID(signerInfo.signatureAlg.algorithm),
    signer,
    signedAttrs: !!signerInfo.signedAttrs,
    chain,
  };
  const key = certSpkiKey(out.signer.tbs.spki);
  const attrs = signerInfo.signedAttrs;
  const content = signedData.encapContentInfo.eContent;
  const digestHash = CMS_HASH_BY_OID[algOID(signerInfo.digestAlg.algorithm)];
  const checkDigestParams = (): void => {
    const da = signerInfo.digestAlg;
    // RFC 5754 section 2: for SHA-2 digest OIDs, params MUST be accepted as absent or NULL.
    if (!digestAlgParamsOk(da))
      throw new Error('SHA-2 digestAlgorithm params must be absent or NULL');
  };
  const checkDigestAlg = (a: CmsAlg): void => {
    const da = signerInfo.digestAlg;
    const expected = hashOid(a.hash);
    checkDigestParams();
    const got = algOID(da.algorithm);
    if (got !== expected)
      throw new Error(`digestAlgorithm OID mismatch: expected ${expected}, got ${got}`);
  };
  const checkSignedAttrs = (hash?: (m: Uint8Array) => Uint8Array): void => {
    const unsigned = signerInfo.unsignedAttrs || [];
    // RFC 5652 sections 11.1/11.2/11.3: these attributes MUST be signed/authenticated, not unsigned.
    for (const oid in CMS_SIGNED_ATTR_NAME) {
      if (unsigned.some((a) => a.oid === oid))
        throw new Error(
          `${CMS_SIGNED_ATTR_NAME[oid as keyof typeof CMS_SIGNED_ATTR_NAME]} attribute MUST NOT be unsigned`
        );
    }
    // RFC 5652 section 11.4: countersignature MUST be unsigned; this API does not implement it.
    if (unsigned.some((a) => a.oid === CMSOID.attrCountersignature))
      throw new Error('countersignature is unsupported by this API');
    if (!attrs) return;
    if (attrs.some((a) => a.oid === CMSOID.attrCountersignature))
      throw new Error('countersignature MUST NOT be a signed attribute');
    const getAttrs = (oid: string) => attrs.filter((a) => a.oid === oid);
    const attrOne = (oid: string, name: string): AttributeCodec => {
      const all = getAttrs(oid);
      if (all.length !== 1)
        throw new Error(
          `signedAttrs MUST include exactly one ${name} attribute, got ${all.length}`
        );
      return all[0];
    };
    const attrZeroOrOne = (oid: string, name: string): AttributeCodec | undefined => {
      const all = getAttrs(oid);
      if (all.length > 1)
        throw new Error(
          `signedAttrs MUST NOT include multiple ${name} attributes, got ${all.length}`
        );
      return all[0];
    };
    // RFC 5652 section 5.6: when signedAttrs exists, content-type attr MUST match encapContentInfo.eContentType.
    const ctAttr = attrOne(CMSOID.attrContentType, 'content-type');
    const ct = ASN1.OID.decode(ctAttr.values[0]);
    if (ct !== signedData.encapContentInfo.eContentType)
      throw new Error('content-type attribute does not match encapContentInfo.eContentType');
    const mdAttr = attrOne(CMSOID.attrMessageDigest, 'messageDigest');
    ASN1.OctetString.decode(mdAttr.values[0]);
    const st = attrZeroOrOne(CMSOID.attrSigningTime, 'signingTime');
    if (st) X509Time.decode(st.values[0]);
    // RFC 5652 section 5.4: digest input starts from eContent OCTET STRING value bytes (no tag/len).
    // Detached verification provides content externally via CMS.verifyDetached; plain CMS.verify
    // without signature checks may still be used for detached structure/path validation.
    if (content === undefined || !hash) return;
    const got = ASN1.OctetString.decode(mdAttr.values[0]);
    const exp = hash(content);
    if (!equalBytes(got, exp)) throw new Error('messageDigest attribute does not match eContent');
  };
  const verifyInputs = (a: CmsAlg, verifyOne: (data: Uint8Array) => boolean): CmsVerify => {
    checkDigestAlg(a);
    checkSignedAttrs(a.hash);
    if (signedData.encapContentInfo.eContent === undefined)
      throw new Error(
        'CMS.verify({checkSignatures:true}) requires attached eContent; use CMS.verifyDetached'
      );
    for (const data of inputs) if (verifyOne(data)) return out;
    throw new Error('CMS signature invalid');
  };
  const inputs: Uint8Array[] = attrs
    ? [
        ASN1.set(CMSX.Attribute).encode(attrs),
        ASN1.implicit(0, ASN1.set(CMSX.Attribute)).encode(attrs),
      ]
    : content
      ? [content]
      : [];
  const tag = key.algorithm.info.TAG;
  if (!checkSignatures) {
    checkDigestParams();
    checkSignedAttrs(digestHash);
    return out;
  }
  const sigOid = algOID(signerInfo.signatureAlg.algorithm) as CmsAlg['sigOid'];
  const sig = CMS_ALG_BY_SIG_OID[sigOid];
  if (!sig) throw new Error(`unsupported signatureAlgorithm OID ${sigOid}`);
  if (tag === 'EC') {
    const curve = spkiCurve(key);
    if (!isSignCurve(curve))
      throw new Error(`CMS.verify({checkSignatures:true}) unsupported signer curve ${curve}`);
    if (!('ec' in sig)) throw new Error(`unsupported signatureAlgorithm OID ${sigOid}`);
    // RFC 5754 section 3.3: ECDSA-with-SHA2 AlgorithmIdentifier parameters MUST be absent.
    if (signerInfo.signatureAlg.params && sigOid.startsWith('1.2.840.10045.4.3.'))
      throw new Error('ECDSA signatureAlgorithm params must be absent');
    return verifyInputs(sig, (data) =>
      ecdsaVerifyDer(curve, signerInfo.signature, sig.hash(data), key.publicKey)
    );
  }
  if (tag === 'Ed25519' || tag === 'Ed448') {
    if (!('ed' in sig)) throw new Error(`unsupported signatureAlgorithm OID ${sigOid}`);
    if (CMS_ALG[tag].sigOid !== sigOid)
      throw new Error(`unsupported signatureAlgorithm OID ${signerInfo.signatureAlg.algorithm}`);
    return verifyInputs(sig, (data) =>
      CMS_ALG[tag].ed.verify(signerInfo.signature, data, key.publicKey)
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
const CMSOID = {
  // RFC 5652 section 4: id-data identifies arbitrary octet string content.
  data: '1.2.840.113549.1.7.1',
  signedData: '1.2.840.113549.1.7.2',
  attrContentType: '1.2.840.113549.1.9.3',
  attrSigningTime: '1.2.840.113549.1.9.5',
  attrMessageDigest: '1.2.840.113549.1.9.4',
  attrCountersignature: '1.2.840.113549.1.9.6',
} as const;
const CMS_SIGNED_ATTR_NAME = /* @__PURE__ */ (() =>
  ({
    [CMSOID.attrContentType]: 'content-type',
    [CMSOID.attrMessageDigest]: 'messageDigest',
    [CMSOID.attrSigningTime]: 'signingTime',
  }) as const)();
const SMIME_CAPS = {
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
} as const;
const cmsSmimeCapabilities = (names: string[]): Uint8Array =>
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
      if (n in SMIME_CAPS) return { capabilityID: SMIME_CAPS[n as keyof typeof SMIME_CAPS] };
      if (/^[0-9]+(?:\.[0-9]+)+$/.test(name)) return { capabilityID: name };
      throw new Error(`unknown S/MIME capability ${name}`);
    }),
  });
type CmsSignerType = { tag: 'EC'; curve: Curve; alg: CmsAlg } | { tag: EdKind; alg: CmsAlg };
const cmsAttrs = (
  data: Uint8Array,
  algHash: HashAlg,
  createdTs: number | undefined,
  smimeCapabilities: string[] | undefined,
  messageDigest: Uint8Array | undefined
): AttributeCodec[] => {
  const attrs: AttributeCodec[] = [
    { oid: CMSOID.attrContentType, values: [ASN1.OID.encode(CMSOID.data)] },
  ];
  if (createdTs !== undefined) {
    if (!Number.isSafeInteger(createdTs))
      throw new Error(`expected safe integer createdTs in UNIX milliseconds, got ${createdTs}`);
    attrs.push({
      oid: CMSOID.attrSigningTime,
      values: [X509Time.encode(Math.floor(createdTs / 1000))],
    });
  }
  attrs.push({
    oid: CMSOID.attrMessageDigest,
    values: [ASN1.OctetString.encode(messageDigest || algHash(data))],
  });
  if (smimeCapabilities && smimeCapabilities.length)
    attrs.push({ oid: '1.2.840.113549.1.9.15', values: [cmsSmimeCapabilities(smimeCapabilities)] });
  return attrs;
};
const cmsCertSet = (leaf: Cert, chain: Cert[]) =>
  [
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
    })
    .map((x) => x.v);
const cmsBuild = (
  data: Uint8Array,
  leaf: Cert,
  chain: Cert[],
  attrs: AttributeCodec[],
  signature: Uint8Array,
  digestAlgorithm: string,
  signatureAlgorithm: string,
  digestAlgorithmParams: 'absent' | 'null'
): Uint8Array => {
  const digestParams = digestAlgorithmParams === 'null' ? { tag: 0x05, valueHex: '' } : undefined;
  const signerInfo = {
    // RFC 5652 section 5.3: issuerAndSerialNumber SID => version 1.
    version: 1n,
    sid: {
      TAG: 'issuerSerial' as const,
      data: { issuer: leaf.tbs.issuer, serial: leaf.tbs.serial },
    },
    digestAlg: { algorithm: digestAlgorithm, params: digestParams },
    signedAttrs: attrs,
    signatureAlg: { algorithm: signatureAlgorithm, params: undefined },
    signature: signature,
    unsignedAttrs: undefined,
  };
  const signedData = {
    version: 1n,
    digestAlgorithms: [{ algorithm: digestAlgorithm, params: digestParams }],
    // RFC 5652 section 4: encapsulated content type is id-data for octet payload.
    encapContentInfo: { eContentType: CMSOID.data, eContent: data },
    certificates: cmsCertSet(leaf, chain),
    crls: undefined,
    signerInfos: [signerInfo],
  };
  const contentInfo = {
    contentType: CMSOID.signedData,
    content: CMSX.SignedData.encode(signedData),
  };
  return CMSX.ContentInfo.encode(contentInfo);
};
const ecdsaVerifyDer = (
  curve: Curve,
  signature: Uint8Array,
  msgHash: Uint8Array,
  publicKey: Uint8Array
): boolean => {
  ECDSASig.decode(signature);
  return ecCurve(curve).verify(signature, msgHash, publicKey, {
    format: 'der',
    lowS: false,
    prehash: false,
  });
};
const cmsSignCtx = (
  content: string | Uint8Array,
  signingCertPem: string,
  createdTs: number | undefined,
  smimeCapabilities: string[] | undefined,
  messageDigest: Uint8Array | undefined,
  digestAlgorithm: string | undefined
): {
  data: Uint8Array;
  leaf: Cert;
  signer: CmsSignerType;
  attrs: AttributeCodec[];
  toSign: Uint8Array;
} => {
  const data =
    typeof content === 'string'
      ? new TextEncoder().encode(content.replace(/\r\n|\r|\n/g, '\r\n'))
      : content;
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
  const digestHash = digestAlgorithm ? CMS_HASH_BY_OID[algOID(digestAlgorithm)] : signer.alg.hash;
  if (!digestHash) throw new Error(`unsupported digestAlgorithm OID ${digestAlgorithm}`);
  const attrs = cmsAttrs(data, digestHash, createdTs, smimeCapabilities, messageDigest);
  const toSign = ASN1.set(CMSX.Attribute).encode(attrs);
  return { data, leaf, signer, attrs, toSign };
};
const cmsCompactSign = (
  signer: CmsSignerType,
  leaf: Cert,
  privateKeyPem: string,
  toSign: Uint8Array,
  extraEntropy: boolean | Uint8Array | undefined
): Uint8Array => {
  const keyBlock = onePem(privateKeyPem);
  if (keyBlock.tag !== 'PRIVATE KEY')
    throw new Error(`expected PKCS#8 PRIVATE KEY PEM, got ${keyBlock.tag}`);
  const key = pkcs8FromPem(privateKeyPem, keyBlock.der);
  if (!matchCertKey(leaf, key)) throw new Error('certificate and private key do not match');
  const keyTag = key.key.algorithm.info.TAG;
  const kk = pkcs8SignKey(key.key);
  if (signer.tag === 'EC') {
    if (keyTag !== 'EC' || kk.kind !== 'EC' || !isSignCurve(kk.curve) || kk.curve !== signer.curve)
      throw new Error('cmsSign key type mismatch');
    return ecCurve(signer.curve).sign(signer.alg.hash(toSign), kk.secretKey, {
      prehash: false,
      format: 'der',
      lowS: false,
      extraEntropy: extraEntropy === undefined ? true : extraEntropy,
    });
  }
  if (keyTag !== signer.tag || kk.kind !== signer.tag) throw new Error('cmsSign key type mismatch');
  return CMS_ALG[signer.tag].ed.sign(toSign, kk.secretKey);
};

export const CMS: CMSApi = /* @__PURE__ */ (() => ({
  decode: (der: Uint8Array, opts: BEROpts = {}) => {
    const ber = berView(der, opts);
    const contentInfo = CMSX.ContentInfo.decode(ber.der) as P.UnwrapCoder<
      typeof CMSX.ContentInfo
    > & {
      ber?: BERDoc;
    };
    contentInfo.ber = ber;
    return contentInfo;
  },
  encode: (contentInfo: P.UnwrapCoder<typeof CMSX.ContentInfo> & { ber?: BERDoc }) => {
    const der = CMSX.ContentInfo.encode(contentInfo);
    const ber = contentInfo.ber;
    if (!ber) return der;
    return DERUtils.BER.encode(ber.nodes, der);
  },
  contentType: (der: Uint8Array, opts: BEROpts = {}) => CMS.decode(der, opts).contentType,
  signed: (der: Uint8Array, opts: BEROpts = {}): P.UnwrapCoder<typeof CMSX.SignedData> => {
    return cmsSignedData(berView(der, opts).der).signedData;
  },
  verify: (der: Uint8Array, opts: CmsVerifyOpts = {}): CmsVerify => cmsVerifyEc(der, opts),
  detach: (der: Uint8Array, opts: BEROpts = {}): CmsDetached => {
    // RFC 5652 section 5.2: detached signatures are represented by absent eContent.
    const { contentInfo, signedData } = cmsSignedData(berView(der, opts).der);
    if (signedData.encapContentInfo.eContent === undefined)
      throw new Error('CMS.detach expects attached CMS with present eContent');
    const content = signedData.encapContentInfo.eContent;
    const certs = cmsCerts(signedData);
    signedData.encapContentInfo.eContent = undefined;
    contentInfo.content = CMSX.SignedData.encode(signedData);
    return {
      content,
      signature: CMSX.ContentInfo.encode(contentInfo),
      certs,
    };
  },
  attach: (signature: Uint8Array, content: Uint8Array, opts: BEROpts = {}): Uint8Array => {
    // RFC 5652 section 5.2: attached form carries eContent as OCTET STRING value bytes.
    const { contentInfo, signedData } = cmsSignedData(berView(signature, opts).der);
    if (signedData.encapContentInfo.eContent !== undefined)
      throw new Error('CMS.attach expects detached signature with absent eContent');
    signedData.encapContentInfo.eContent = content;
    contentInfo.content = CMSX.SignedData.encode(signedData);
    return CMSX.ContentInfo.encode(contentInfo);
  },
  verifyDetached: (
    signature: Uint8Array,
    content: Uint8Array,
    opts: CmsVerifyOpts = {}
  ): CmsVerify => cmsVerifyEc(CMS.attach(signature, content, opts), opts),
  sign: (
    content: string | Uint8Array,
    signingCertPem: string,
    privateKeyPem: string,
    chainPem = '',
    opts: CmsSignOpts = {}
  ): Uint8Array => {
    const compactOpts = {
      createdTs: opts.createdTs,
      smimeCapabilities: opts.smimeCapabilities,
      messageDigest: opts.messageDigest,
      digestAlgorithm: opts.digestAlgorithm,
    };
    const compactBuildOpts = {
      ...compactOpts,
      digestAlgorithmParams: opts.digestAlgorithmParams,
      signatureAlgorithm: opts.signatureAlgorithm,
    };
    return CMS.compact.build(
      content,
      CMS.compact.sign(content, signingCertPem, privateKeyPem, {
        ...compactOpts,
        extraEntropy: opts.extraEntropy,
      }),
      signingCertPem,
      chainPem,
      compactBuildOpts
    );
  },
  signDetached: (
    content: string | Uint8Array,
    signingCertPem: string,
    privateKeyPem: string,
    chainPem = '',
    opts: CmsSignOpts = {}
  ): Uint8Array =>
    CMS.detach(CMS.sign(content, signingCertPem, privateKeyPem, chainPem, opts)).signature,
  compact: {
    sign: (
      content: string | Uint8Array,
      signingCertPem: string,
      privateKeyPem: string,
      opts: Pick<
        CmsSignOpts,
        'createdTs' | 'extraEntropy' | 'smimeCapabilities' | 'messageDigest' | 'digestAlgorithm'
      > = {}
    ): Uint8Array => {
      const c = cmsSignCtx(
        content,
        signingCertPem,
        opts.createdTs,
        opts.smimeCapabilities,
        opts.messageDigest,
        opts.digestAlgorithm
      );
      return cmsCompactSign(c.signer, c.leaf, privateKeyPem, c.toSign, opts.extraEntropy);
    },
    build: (
      content: string | Uint8Array,
      signature: Uint8Array,
      signingCertPem: string,
      chainPem = '',
      opts: CmsCompactBuildOpts = {}
    ): Uint8Array => {
      const c = cmsSignCtx(
        content,
        signingCertPem,
        opts.createdTs,
        opts.smimeCapabilities,
        opts.messageDigest,
        opts.digestAlgorithm
      );
      const digestAlgorithm = opts.digestAlgorithm
        ? algOID(opts.digestAlgorithm)
        : hashOid(c.signer.alg.hash);
      const signatureAlgorithm = opts.signatureAlgorithm
        ? algOID(opts.signatureAlgorithm)
        : c.signer.alg.sigOid;
      if (!signatureAlgorithm) throw new Error('signature algorithm OID is required');
      const digestAlgorithmParams = opts.digestAlgorithmParams || 'absent';
      if (c.signer.tag === 'EC') ecCurve(c.signer.curve).Signature.fromBytes(signature, 'der');
      else {
        const expected = c.signer.tag === 'Ed25519' ? 64 : 114;
        if (signature.length !== expected)
          throw new Error(
            `invalid ${c.signer.tag} signature length: expected ${expected}, got ${signature.length}`
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
        digestAlgorithmParams
      );
    },
  },
}))();
export const __TEST: {
  IPv4: typeof IPv4;
  IPv6: typeof IPv6;
  PrintableString: typeof PrintableString;
  NumericString: typeof NumericString;
  TeletexString: typeof TeletexString;
  X509Time: typeof X509Time;
  CMSCertificateChoices: typeof CMSCertificateChoices;
  CMSRevocationInfoChoice: typeof CMSRevocationInfoChoice;
  CMSSignedData: typeof CMSSignedData;
  SMIME_CAPS: typeof SMIME_CAPS;
  keyCurve: (privateKeyPem: string) => CertCurve | EdKind;
} = /* @__PURE__ */ (() => ({
  IPv4: IPv4,
  IPv6: IPv6,
  PrintableString: PrintableString,
  NumericString: NumericString,
  TeletexString: TeletexString,
  X509Time: X509Time,
  CMSCertificateChoices: CMSCertificateChoices,
  CMSRevocationInfoChoice: CMSRevocationInfoChoice,
  CMSSignedData: CMSSignedData,
  SMIME_CAPS: SMIME_CAPS,
  keyCurve: (privateKeyPem: string) => {
    const block = onePem(privateKeyPem, 'PRIVATE KEY');
    const parsed = pkcs8SignKey(pkcs8FromPem(privateKeyPem, block.der).key);
    return parsed.kind === 'EC' ? parsed.curve : parsed.kind;
  },
}))();

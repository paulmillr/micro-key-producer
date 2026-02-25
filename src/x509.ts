import { p256, p384, p521 } from '@noble/curves/nist.js';
import { equalBytes } from '@noble/curves/utils.js';
import { sha256, sha384, sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, concatBytes } from '@noble/hashes/utils.js';
import { CurveOID, DERUtils, curveOID, p256_der, p384_der, p521_der } from './convert.ts';
import { base64 } from '@scure/base';
import * as P from 'micro-packed';

export type Curve = 'P-256' | 'P-384' | 'P-521';
export type CertCurve = Curve | 'brainpoolP256r1' | 'SM2' | `OID:${string}`;
export type PemBlock = { tag: string; b64: string; der: Uint8Array };
export type Pkcs8Attr = { der: Uint8Array; oid: string; values: Uint8Array[] };
export type CertKey =
  | { keyType: 'EC'; curve: CertCurve; publicKey: Uint8Array }
  | { keyType: 'RSA'; publicKey: Uint8Array }
  | { keyType: 'DSA'; publicKey: Uint8Array }
  | { keyType: 'Ed25519'; publicKey: Uint8Array }
  | { keyType: 'Ed448'; publicKey: Uint8Array }
  | { keyType: 'X25519'; publicKey: Uint8Array }
  | { keyType: 'X448'; publicKey: Uint8Array }
  | { keyType: 'Unknown'; algorithm: string; publicKey: Uint8Array };
export type Cert = P.UnwrapCoder<typeof CERTUtils.Certificate>;
type KeyBase = {
  pem: string;
  der: Uint8Array;
  attributes?: Pkcs8Attr[];
};
export type PrivateKey =
  | (KeyBase & { keyType: 'EC'; curve: Curve; secretKey: Uint8Array; publicKey: Uint8Array })
  | (KeyBase & { keyType: 'RSA'; privateKey: Uint8Array });
export type SigningPem = {
  leaf: Cert;
  key: PrivateKey;
  chain: Cert[];
};
export type CmsVerifyOpts = {
  time?: number;
  allowBER?: boolean;
  checkSignatures?: boolean;
  purpose?: 'any' | 'smime' | 'codeSigning';
  chain?: (string | Uint8Array | Cert)[];
};
export type CmsVerify = {
  signatureOid: string;
  signer: Cert;
  signedAttrs: boolean;
  chain: Cert[];
};
export type CmsDetached = {
  content: Uint8Array;
  signature: Uint8Array;
  certs: Cert[];
};
export type CmsSignOpts = BEROpts & {
  createdTs?: number;
  signedAttrs?: boolean;
};
export type CertExt = {
  oid: string;
  critical: boolean;
  ski?: Uint8Array;
  basic?: { ca?: boolean; pathLen?: bigint };
  keyUsage?: { unused: number; bytes: Uint8Array };
  eku?: { list: string[] };
  san?: { list: CertGeneralName[] };
  aki?: {
    keyIdentifier?: Uint8Array;
    authorityCertIssuer?: { list: CertGeneralName[] };
    authorityCertSerialNumber?: bigint;
  };
  aia?: { list: { method: string; location: CertGeneralName }[] };
  proxyCertInfo?: { pathLen?: bigint; policy: { language: string; policy?: string } };
  tlsFeature?: { list: bigint[] };
  sct?: {
    version: number;
    logID: Uint8Array;
    timestamp: bigint;
    extensions: string;
    hash: number;
    signatureAlgorithm: number;
    signature: Uint8Array;
  }[];
  crlDistributionPoints?: {
    list: {
      distributionPoint?: CertDistributionPointName;
      reasons?: { unused: number; bytes: Uint8Array };
      cRLIssuer?: { list: CertGeneralName[] };
    }[];
  };
  policies?: {
    list: {
      policy: string;
      qualifiers?: { list: CertPolicyQualifier[] };
    }[];
  };
  nameConstraints?: {
    permitted?: { list: CertGeneralSubtree[] };
    excluded?: { list: CertGeneralSubtree[] };
  };
};
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
export type CertDistributionPointName =
  | { TAG: 'fullName'; data: { list: CertGeneralName[] } }
  | { TAG: 'nameRelativeToCRLIssuer'; data: Array<{ oid: string; value: NameValue }> };
export type CertReasonFlags = {
  keyCompromise: boolean;
  cACompromise: boolean;
  affiliationChanged: boolean;
  superseded: boolean;
  cessationOfOperation: boolean;
  certificateHold: boolean;
  privilegeWithdrawn: boolean;
  aACompromise: boolean;
};
export type CertGeneralSubtree = {
  base: CertGeneralName;
  minimum?: bigint;
  maximum?: bigint;
};
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
export type TLVNode = { tag: number; children?: TLVNode[]; valueHex?: string };
export type CertText = { tag: 'utf8' | 'ia5' | 'visible' | 'bmp'; text: string };
const pemRE = /-----BEGIN ([^-]+)-----([\s\S]*?)-----END \1-----/g;

const curves = {
  'P-256': {
    der: p256_der,
    hash: sha256,
    sign: (msg: Uint8Array, secretKey: Uint8Array) => p256.sign(msg, secretKey),
    pub: (secretKey: Uint8Array, compressed: boolean) => p256.getPublicKey(secretKey, compressed),
  },
  'P-384': {
    der: p384_der,
    hash: sha384,
    sign: (msg: Uint8Array, secretKey: Uint8Array) => p384.sign(msg, secretKey),
    pub: (secretKey: Uint8Array, compressed: boolean) => p384.getPublicKey(secretKey, compressed),
  },
  'P-521': {
    der: p521_der,
    hash: sha512,
    sign: (msg: Uint8Array, secretKey: Uint8Array) => p521.sign(msg, secretKey),
    pub: (secretKey: Uint8Array, compressed: boolean) => p521.getPublicKey(secretKey, compressed),
  },
} as const;
const EC: Record<Curve, typeof p256> = {
  'P-256': p256,
  'P-384': p384,
  'P-521': p521,
};
const ecCurve = (curve: Curve): typeof p256 => {
  const e = EC[curve];
  if (!e) throw new Error(`unsupported curve ${curve}`);
  return e;
};
const isSignCurve = (curve: CertCurve): curve is Curve =>
  curve === 'P-256' || curve === 'P-384' || curve === 'P-521';

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

const SpkiAny = DERUtils.ASN1.sequence({
  algorithm: DERUtils.ASN1.sequence({ oid: DERUtils.ASN1.OID, params: P.bytes(null) }),
  publicKey: DERUtils.ASN1.BitString,
});
const OID_TO_CURVE: Record<string, CertCurve> = {
  [CurveOID['P-256']]: 'P-256',
  [CurveOID['P-384']]: 'P-384',
  [CurveOID['P-521']]: 'P-521',
  '1.3.36.3.3.2.8.1.1.7': 'brainpoolP256r1',
  '1.2.156.10197.1.301': 'SM2',
};
const SPKI_PARAM_TAG: Record<number, (p: Uint8Array) => CertCurve> = {
  0x06: (p) => {
    const oid = DERUtils.ASN1.OID.decode(p);
    return OID_TO_CURVE[oid] || `OID:${oid}`;
  },
  0x05: () => 'OID:implicitCurve',
  0x30: () => 'OID:specifiedCurve',
};
const spkiCurve = (p: Uint8Array): CertCurve => {
  if (!p.length) return 'OID:no-params';
  const tag = TLV.decode(p).tag;
  const handler = SPKI_PARAM_TAG[tag];
  if (handler) return handler(p);
  return `OID:tag-${tag.toString(16)}`;
};
const SPKI_OID_TO_KEY: Record<string, (d: P.UnwrapCoder<typeof SpkiAny>) => CertKey> = {
  '1.2.840.10045.2.1': (d) => ({
    keyType: 'EC',
    curve: spkiCurve(d.algorithm.params),
    publicKey: d.publicKey,
  }),
  '1.2.840.113549.1.1.1': (d) => ({ keyType: 'RSA', publicKey: d.publicKey }),
  '1.2.840.113549.1.1.10': (d) => ({ keyType: 'RSA', publicKey: d.publicKey }),
  '1.2.840.10040.4.1': (d) => ({ keyType: 'DSA', publicKey: d.publicKey }),
  '1.3.101.112': (d) => ({ keyType: 'Ed25519', publicKey: d.publicKey }),
  '1.3.101.113': (d) => ({ keyType: 'Ed448', publicKey: d.publicKey }),
  '1.3.101.110': (d) => ({ keyType: 'X25519', publicKey: d.publicKey }),
  '1.3.101.111': (d) => ({ keyType: 'X448', publicKey: d.publicKey }),
};
const SPKI_KEY_TO_OID: Record<Exclude<CertKey['keyType'], 'EC' | 'Unknown'>, string> = {
  RSA: '1.2.840.113549.1.1.1',
  DSA: '1.2.840.10040.4.1',
  Ed25519: '1.3.101.112',
  Ed448: '1.3.101.113',
  X25519: '1.3.101.110',
  X448: '1.3.101.111',
};
const CURVE_TO_OID: Record<Exclude<CertCurve, `OID:${string}`>, string> = {
  'P-256': '1.2.840.10045.3.1.7',
  'P-384': '1.3.132.0.34',
  'P-521': '1.3.132.0.35',
  brainpoolP256r1: '1.3.36.3.3.2.8.1.1.7',
  SM2: '1.2.156.10197.1.301',
};
const curveToOID = (curve: CertCurve): string =>
  curve.startsWith('OID:')
    ? curve.slice(4)
    : CURVE_TO_OID[curve as Exclude<CertCurve, `OID:${string}`>];
const SpkiKey = P.apply(SpkiAny, {
  encode: (d): CertKey => {
    const fn = SPKI_OID_TO_KEY[d.algorithm.oid];
    if (fn) return fn(d);
    return { keyType: 'Unknown', algorithm: d.algorithm.oid, publicKey: d.publicKey };
  },
  decode: (k: CertKey) => {
    if (k.keyType === 'EC') {
      const oid = curveToOID(k.curve);
      return {
        algorithm: { oid: '1.2.840.10045.2.1', params: DERUtils.ASN1.OID.encode(oid) },
        publicKey: k.publicKey,
      };
    }
    if (k.keyType !== 'Unknown')
      return {
        algorithm: { oid: SPKI_KEY_TO_OID[k.keyType], params: new Uint8Array() },
        publicKey: k.publicKey,
      };
    return { algorithm: { oid: k.algorithm, params: new Uint8Array() }, publicKey: k.publicKey };
  },
}) satisfies P.CoderType<CertKey>;
const PKCS8Top = DERUtils.ASN1.sequence({
  version: DERUtils.ASN1.Integer,
  algorithm: DERUtils.ASN1.sequence({ oid: DERUtils.ASN1.OID, params: P.bytes(null) }),
  privateKey: DERUtils.ASN1.OctetString,
  attributes: DERUtils.ASN1.optional(DERUtils.ASN1.implicit(0, DERUtils.ASN1.set(P.bytes(null)))),
  publicKey: DERUtils.ASN1.optional(DERUtils.ASN1.implicit(1, DERUtils.ASN1.BitString)),
});
type PKCS8SecretStructData = Extract<
  P.UnwrapCoder<typeof DERUtils.PKCS8SecretKey>,
  { TAG: 'struct' }
>['data'];
const PKCS8SecretStruct = P.apply(DERUtils.PKCS8SecretKey, {
  encode: (k): PKCS8SecretStructData => {
    const s = ({ struct: k.data as PKCS8SecretStructData, raw: undefined } as const)[
      k.TAG as 'struct' | 'raw'
    ];
    if (!s) throw new Error('EC PKCS#8: expected structured ECPrivateKey payload');
    return s;
  },
  decode: (s: PKCS8SecretStructData) => ({ TAG: 'struct' as const, data: s }),
}) satisfies P.CoderType<PKCS8SecretStructData>;

const Pkcs8Key = P.apply(PKCS8Top, {
  encode: (
    top
  ):
    | {
        keyType: 'EC';
        curve: Curve;
        secretKey: Uint8Array;
        publicKey: Uint8Array;
        attributes?: Pkcs8Attr[];
      }
    | { keyType: 'RSA'; privateKey: Uint8Array; attributes?: Pkcs8Attr[] } => {
    const PKCS8_OID_KIND = {
      '1.2.840.113549.1.1.1': 'RSA',
      '1.2.840.10045.2.1': 'EC',
    } as const;
    const attrs = top.attributes?.length
      ? top.attributes.map((raw) => {
          const a = PKCS8Attr.decode(raw);
          return { der: raw, oid: a.oid, values: a.values };
        })
      : undefined;
    const kind = PKCS8_OID_KIND[top.algorithm.oid as keyof typeof PKCS8_OID_KIND];
    if (!kind) throw new Error(`unsupported PKCS#8 key algorithm OID ${top.algorithm.oid}`);
    if (kind === 'RSA') return { keyType: 'RSA', privateKey: top.privateKey, attributes: attrs };
    const curve = curveOID(DERUtils.ASN1.OID.decode(top.algorithm.params));
    const key = PKCS8SecretStruct.decode(top.privateKey);
    const secretKey = key.privateKey;
    const publicKey = top.publicKey || key.publicKey || curves[curve].pub(secretKey, false);
    return { keyType: 'EC', curve, secretKey, publicKey, attributes: attrs };
  },
  decode: (k) => {
    if (k.keyType === 'RSA')
      return {
        version: 0n,
        algorithm: { oid: '1.2.840.113549.1.1.1', params: new Uint8Array() },
        privateKey: k.privateKey,
        attributes: k.attributes?.map((a) => a.der),
        publicKey: undefined,
      };
    return {
      version: 0n,
      algorithm: { oid: '1.2.840.10045.2.1', params: DERUtils.ASN1.OID.encode(CurveOID[k.curve]) },
      privateKey: DERUtils.PKCS8SecretKey.encode({
        TAG: 'struct',
        data: { version: 1n, privateKey: k.secretKey, publicKey: k.publicKey },
      }),
      attributes: k.attributes?.map((a) => a.der),
      publicKey: k.publicKey,
    };
  },
}) satisfies P.CoderType<
  | {
      keyType: 'EC';
      curve: Curve;
      secretKey: Uint8Array;
      publicKey: Uint8Array;
      attributes?: Pkcs8Attr[];
    }
  | { keyType: 'RSA'; privateKey: Uint8Array; attributes?: Pkcs8Attr[] }
>;

const certMeta = (cert: Cert): { issuer: Uint8Array; serial: bigint } => ({
  issuer: X509C.Name.encode(cert.tbs.issuer),
  serial: cert.tbs.serial,
});
const certItem = (der: Uint8Array, opts: BEROpts = {}): Cert =>
  X509C.Certificate.decode(berView(der, opts).der);
const certPem = (pem: string): Cert => {
  const block = onePem(pem, 'CERTIFICATE');
  return certItem(block.der);
};

const certChainPem = (pem: string): Cert[] => {
  const blocks = pemBlocks(pem).filter((i) => i.tag === 'CERTIFICATE');
  if (!blocks.length) throw new Error('no CERTIFICATE PEM blocks found');
  return blocks.map((b) => certItem(b.der));
};

const keyPem = (pem: string): PrivateKey => {
  const block = onePem(pem);
  if (block.tag !== 'PRIVATE KEY')
    throw new Error(`expected PKCS#8 PRIVATE KEY PEM, got ${block.tag}`);
  const k = Pkcs8Key.decode(block.der);
  const ext = k.attributes ? { attributes: k.attributes } : {};
  if (k.keyType === 'RSA')
    return {
      pem,
      der: block.der,
      ...ext,
      keyType: 'RSA',
      privateKey: k.privateKey,
    };
  return {
    pem,
    der: block.der,
    ...ext,
    keyType: 'EC',
    curve: k.curve,
    secretKey: k.secretKey,
    publicKey: k.publicKey,
  };
};

const matchCertKey = (cert: Cert, key: PrivateKey): boolean => {
  const k = SpkiKey.decode(cert.tbs.spki);
  if (k.keyType !== 'EC' || key.keyType !== 'EC') throw new Error('matchCertKey supports EC only');
  if (!isSignCurve(k.curve)) return false;
  if (k.curve !== key.curve) return false;
  const cmp = curves[k.curve].pub(key.secretKey, false);
  const cmpC = curves[k.curve].pub(key.secretKey, true);
  return equalBytes(k.publicKey, cmp) || equalBytes(k.publicKey, cmpC);
};

const loadSigningPem = (
  signingCertPem: string,
  privateKeyPem: string,
  chainPem = ''
): SigningPem => {
  const leaf = certPem(signingCertPem);
  const key = keyPem(privateKeyPem);
  if (!matchCertKey(leaf, key)) throw new Error('certificate and private key do not match');
  const chain = chainPem ? certChainPem(chainPem) : [];
  return { leaf: leaf, key: key, chain: chain };
};

type BERDoc = ReturnType<typeof DERUtils.BER.decode>;
type BEROpts = { allowBER?: boolean };
const berView = (src: Uint8Array, opts: BEROpts = {}): BERDoc =>
  DERUtils.BER.decode(src, { allowBER: !!opts.allowBER });

const timeSec = (x: number | undefined): number =>
  x === undefined ? Math.floor(Date.now() / 1000) : Math.floor(x);
const ASN1 = DERUtils.ASN1;
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
        const c = TLV.decode(t.value.slice(at));
        const d = TLV.encode(c);
        items.push(TLVNodeCodec.decode(d));
        at += d.length;
      }
      if (at !== t.value.length) throw new Error('constructed TLV child decode mismatch');
      return { tag: t.tag, children: items };
    }
    return { tag: t.tag, valueHex: bytesToHex(t.value) };
  },
});
const HexBytes = P.apply(P.bytes(null), {
  encode: (b: Uint8Array): string => bytesToHex(b),
  decode: (s: string): Uint8Array => hexToBytes(s),
}) satisfies P.CoderType<string>;
const RawTLV = P.wrap({
  encodeStream(w, v: Uint8Array) {
    const t = TLV.decode(v);
    w.bytes(TLV.encode(t));
  },
  decodeStream(r): Uint8Array {
    return TLV.encode(TLV.decodeStream(r));
  },
});
const ASCII = P.apply(P.bytes(null), {
  encode: (b: Uint8Array): string => String.fromCharCode(...b),
  decode: (s: string): Uint8Array => Uint8Array.from(Array.from(s).map((c) => c.charCodeAt(0))),
}) satisfies P.CoderType<string>;
const tagged = <T>(tag: number, inner: P.CoderType<T>) =>
  ({
    tagByte: tag,
    constructed: 0,
    inner,
    ...P.wrap({
      encodeStream(w, v: T) {
        w.bytes(TLV.encode({ tag, value: inner.encode(v) }));
      },
      decodeStream(r): T {
        const t = TLV.decodeStream(r);
        if (t.tag !== tag)
          throw new Error(`expected tag 0x${tag.toString(16)}, got 0x${t.tag.toString(16)}`);
        return inner.decode(t.value);
      },
    }),
  }) as P.CoderType<T> & { tagByte: number; constructed: number; inner: P.CoderType<T> };
const UTCTime = tagged(0x17, ASCII);
const GeneralizedTime = tagged(0x18, ASCII);
const Time = ASN1.choice({ utc: UTCTime, generalized: GeneralizedTime });
const D2 = P.apply(P.array(2, P.U8), {
  encode: (v: number[]): number => {
    const [a, b] = v;
    if (a < 0x30 || a > 0x39 || b < 0x30 || b > 0x39) throw new Error('expected decimal digits');
    return (a - 0x30) * 10 + (b - 0x30);
  },
  decode: (n: number): number[] => {
    if (!Number.isInteger(n) || n < 0 || n > 99)
      throw new Error(`expected decimal 0..99, got ${n}`);
    return [0x30 + Math.floor(n / 10), 0x30 + (n % 10)];
  },
}) satisfies P.CoderType<number>;
const D4 = P.apply(P.array(4, P.U8), {
  encode: (v: number[]): number => {
    const [a, b, c, d] = v;
    for (const x of v) if (x < 0x30 || x > 0x39) throw new Error('expected decimal digits');
    return (a - 0x30) * 1000 + (b - 0x30) * 100 + (c - 0x30) * 10 + (d - 0x30);
  },
  decode: (n: number): number[] => {
    if (!Number.isInteger(n) || n < 0 || n > 9999)
      throw new Error(`expected decimal 0..9999, got ${n}`);
    return [
      0x30 + Math.floor(n / 1000),
      0x30 + Math.floor((n % 1000) / 100),
      0x30 + Math.floor((n % 100) / 10),
      0x30 + (n % 10),
    ];
  },
}) satisfies P.CoderType<number>;
// RFC 5280 section 4.1.2.5.1 and 4.1.2.5.2: UTCTime / GeneralizedTime in certificates.
const TimeUtcSuffix = P.magic(P.U8, 0x5a);
const UTCTimeFields = P.struct({ yy: D2, mo: D2, d: D2, h: D2, mi: D2, s: D2, z: TimeUtcSuffix });
const GeneralizedTimeFields = P.struct({
  y: D4,
  mo: D2,
  d: D2,
  h: D2,
  mi: D2,
  s: D2,
  z: TimeUtcSuffix,
});
const timeEpoch = (der: Uint8Array): number => {
  const t = Time.decode(der);
  if (t.TAG === 'utc') {
    const p = UTCTimeFields.decode(ASCII.encode(t.data));
    const y = p.yy >= 50 ? 1900 + p.yy : 2000 + p.yy;
    return Math.floor(Date.UTC(y, p.mo - 1, p.d, p.h, p.mi, p.s) / 1000);
  }
  const p = GeneralizedTimeFields.decode(ASCII.encode(t.data));
  return Math.floor(Date.UTC(p.y, p.mo - 1, p.d, p.h, p.mi, p.s) / 1000);
};
const PKCS8Attr = ASN1.sequence({ oid: ASN1.OID, values: ASN1.set(RawTLV) });
type NameValue =
  | { TAG: 'utf8'; data: string }
  | { TAG: 'printable'; data: string }
  | { TAG: 'teletex'; data: string }
  | { TAG: 'ia5'; data: string }
  | { TAG: 'bmp'; data: string }
  | { TAG: 'visible'; data: string }
  | { TAG: 'numeric'; data: string };
type NameCodec = { rdns: Array<Array<{ oid: string; value: NameValue }>> };
type ValidityCodec = { notBefore: Uint8Array; notAfter: Uint8Array };
type ExtCodec = { oid: string; rest: Uint8Array };
type AlgorithmIdentifierCodec = { algorithm: string; params: Uint8Array | undefined };
type TBSCertificateCodec = {
  version: bigint | undefined;
  serial: bigint;
  signature: AlgorithmIdentifierCodec;
  issuer: NameCodec;
  validity: ValidityCodec;
  subject: NameCodec;
  spki: Uint8Array;
  issuerUniqueID: Uint8Array | undefined;
  subjectUniqueID: Uint8Array | undefined;
  extensions: { list: ExtCodec[] } | undefined;
};
type CertificateCodec = {
  tbs: TBSCertificateCodec;
  sigAlg: AlgorithmIdentifierCodec;
  sig: Uint8Array;
};
const A = ASN1;
// RFC 5280 section 4.1.1.2 (AlgorithmIdentifier import): parameters are OPTIONAL.
const AlgorithmIdentifier = P.apply(A.sequence({ algorithm: A.OID, paramsRaw: P.bytes(null) }), {
  encode: (x: { algorithm: string; paramsRaw: Uint8Array }): AlgorithmIdentifierCodec => ({
    algorithm: x.algorithm,
    params: x.paramsRaw.length ? x.paramsRaw : undefined,
  }),
  decode: (x: AlgorithmIdentifierCodec) => ({
    algorithm: x.algorithm,
    paramsRaw: x.params || new Uint8Array(),
  }),
}) satisfies P.CoderType<AlgorithmIdentifierCodec>;
const IA5 = tagged(0x16, ASCII);
const Latin1 = P.apply(P.bytes(null), {
  encode: (b: Uint8Array): string => {
    let out = '';
    for (let i = 0; i < b.length; i++) out += String.fromCharCode(b[i]);
    return out;
  },
  decode: (s: string): Uint8Array => {
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
    return out;
  },
}) satisfies P.CoderType<string>;
const UTF8 = Latin1;
const BMP = P.apply(P.bytes(null), {
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
}) satisfies P.CoderType<string>;
const UTF8String = tagged(0x0c, UTF8);
const PrintableString = tagged(0x13, ASCII);
const TeletexString = tagged(0x14, Latin1);
const VisibleString = tagged(0x1a, ASCII);
const NumericString = tagged(0x12, ASCII);
const BMPString = tagged(0x1e, BMP);
const NameString = ASN1.choice({
  utf8: UTF8String,
  printable: PrintableString,
  teletex: TeletexString,
  ia5: IA5,
  bmp: BMPString,
  visible: VisibleString,
  numeric: NumericString,
});
const NameAttr = A.sequence({ oid: A.OID, value: NameString });
const X509Name = A.sequence({ rdns: P.array(null, A.set(NameAttr)) });
const X509Validity = A.sequence({ notBefore: RawTLV, notAfter: RawTLV });
const X509Ext = A.sequence({ oid: A.OID, rest: P.bytes(null) });
const X509TBSCertificate = A.sequence({
  version: A.optional(A.explicit(0, A.Integer)),
  serial: A.Integer,
  signature: AlgorithmIdentifier,
  issuer: X509Name,
  validity: X509Validity,
  subject: X509Name,
  spki: RawTLV,
  issuerUniqueID: A.optional(A.implicit(1, A.BitString)),
  subjectUniqueID: A.optional(A.implicit(2, A.BitString)),
  extensions: A.optional(A.explicit(3, A.sequence({ list: P.array(null, X509Ext) }))),
});
const X509Certificate = A.sequence({
  tbs: X509TBSCertificate,
  sigAlg: AlgorithmIdentifier,
  sig: A.BitString,
});
const X509C: {
  Name: P.CoderType<NameCodec>;
  TBSCertificate: P.CoderType<TBSCertificateCodec>;
  Certificate: P.CoderType<CertificateCodec>;
} = {
  Name: X509Name,
  TBSCertificate: X509TBSCertificate,
  Certificate: X509Certificate,
};
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
  crls: Uint8Array[] | undefined;
  signerInfos: SignerInfoCodec[];
};
type ContentInfoCodec = { contentType: string; content: Uint8Array };
type CMSCertificateChoiceCodec =
  | { TAG: 'certificate'; data: P.UnwrapCoder<typeof X509C.Certificate> }
  | { TAG: 'extendedCertificate'; data: Uint8Array }
  | { TAG: 'v1AttrCert'; data: Uint8Array }
  | { TAG: 'v2AttrCert'; data: Uint8Array }
  | { TAG: 'other'; data: Uint8Array };
// RFC 5652 section 10.2.2: CertificateChoices.
const CMSCertificateChoices = ASN1.choice({
  certificate: X509C.Certificate,
  extendedCertificate: tagged(0xa0, P.bytes(null)),
  v1AttrCert: tagged(0xa1, P.bytes(null)),
  v2AttrCert: tagged(0xa2, P.bytes(null)),
  other: tagged(0xa3, P.bytes(null)),
});
// RFC 5652 sections 10.1.1 and 10.1.2: DigestAlgorithmIdentifier/SignatureAlgorithmIdentifier ::= AlgorithmIdentifier.
// RFC 5652 section 5.3: Attribute ::= SEQUENCE { attrType OBJECT IDENTIFIER, attrValues SET OF AttributeValue }.
const CMSAttribute = A.sequence({ oid: A.OID, values: A.set(RawTLV) });
// RFC 5652 section 5.3: SignerIdentifier issuerAndSerialNumber branch.
const CMSIssuerAndSerial = A.sequence({ issuer: X509C.Name, serial: A.Integer });
// RFC 5652 section 5.3: SignerIdentifier (IssuerAndSerialNumber / SubjectKeyIdentifier).
const CMSSignerIdentifier = A.choice({
  issuerSerial: CMSIssuerAndSerial,
  subjectKeyIdentifier: A.implicit(0, A.OctetString),
});
// RFC 5652 section 5.3: SignerInfo.
const CMSSignerInfo = A.sequence({
  version: A.Integer,
  sid: CMSSignerIdentifier,
  digestAlg: AlgorithmIdentifier,
  signedAttrs: A.optional(A.implicit(0, A.set(CMSAttribute))),
  signatureAlg: AlgorithmIdentifier,
  signature: A.OctetString,
  unsignedAttrs: A.optional(A.implicit(1, A.set(CMSAttribute))),
});
// RFC 5652 section 5.2: EncapsulatedContentInfo.
const CMSEncapContentInfo = A.sequence({
  eContentType: A.OID,
  eContent: A.optional(A.explicit(0, A.OctetString)),
});
// RFC 5652 section 5.1: SignedData.
const CMSSignedData = A.sequence({
  version: A.Integer,
  digestAlgorithms: A.set(AlgorithmIdentifier),
  encapContentInfo: CMSEncapContentInfo,
  // RFC 5652 section 10.2.3: CertificateSet ::= SET OF CertificateChoices.
  certificates: A.optional(A.implicit(0, A.set(CMSCertificateChoices))),
  crls: A.optional(A.implicit(1, A.set(RawTLV))),
  signerInfos: A.set(CMSSignerInfo),
});
// RFC 5652 section 3: ContentInfo.
const CMSContentInfo = A.sequence({
  contentType: A.OID,
  content: A.explicit(0, RawTLV),
});
const CMSX: {
  AlgorithmIdentifier: P.CoderType<AlgorithmIdentifierCodec>;
  Attribute: P.CoderType<AttributeCodec>;
  SignerInfo: P.CoderType<SignerInfoCodec>;
  SignedData: P.CoderType<SignedDataCodec>;
  ContentInfo: P.CoderType<ContentInfoCodec>;
} = {
  AlgorithmIdentifier: AlgorithmIdentifier,
  Attribute: CMSAttribute,
  SignerInfo: CMSSignerInfo,
  SignedData: CMSSignedData,
  ContentInfo: CMSContentInfo,
};
// micro-packed coders for full X.509 cert decode/encode, same exposure style as DERUtils in convert.ts
export const CERTUtils: {
  Name: typeof X509C.Name;
  TBSCertificate: typeof X509C.TBSCertificate;
  Certificate: typeof X509C.Certificate;
} = /* @__PURE__ */ {
  Name: X509C.Name,
  TBSCertificate: X509C.TBSCertificate,
  Certificate: X509C.Certificate,
};

const Big = P.apply(P.bytes(null), {
  encode: (b: Uint8Array): bigint => {
    let n = 0n;
    for (const x of b) n = (n << 8n) | BigInt(x);
    return n;
  },
  decode: (n: bigint): Uint8Array => {
    if (n < 0n) throw new Error('expected non-negative INTEGER');
    if (n === 0n) return Uint8Array.from([0]);
    const a: number[] = [];
    for (let x = n; x > 0n; x >>= 8n) a.unshift(Number(x & 0xffn));
    return Uint8Array.from(a);
  },
}) satisfies P.CoderType<bigint>;
const ASN1BoolInner = P.wrap({
  encodeStream(w, v: boolean) {
    w.byte(v ? 0xff : 0x00);
  },
  decodeStream(r): boolean {
    const b = r.byte();
    if (!r.isEnd()) throw new Error('BOOLEAN length must be 1');
    return b !== 0;
  },
});
const ASN1Bool = {
  tagByte: 0x01,
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
};
const ASN1BitStringInner = P.struct({ unused: P.U8, bytes: P.bytes(null) });
const ASN1BitStringRaw = {
  tagByte: 0x03,
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
};
const ipv4Decode = (b: Uint8Array): string => {
  if (b.length !== 4) throw new Error('IPv4 SAN must be 4 bytes');
  return `${b[0]}.${b[1]}.${b[2]}.${b[3]}`;
};
const ipv4Encode = (s: string): Uint8Array | undefined => {
  const p = s.split('.');
  if (p.length !== 4) return undefined;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    if (!/^[0-9]+$/.test(p[i])) return undefined;
    const n = Number(p[i]);
    if (!Number.isInteger(n) || n < 0 || n > 255) return undefined;
    out[i] = n;
  }
  return out;
};
const ipv6Decode = (b: Uint8Array): string => {
  if (b.length !== 16) throw new Error('IPv6 SAN must be 16 bytes');
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
};
const ipv6Encode = (s: string): Uint8Array | undefined => {
  if (!s.includes(':')) return undefined;
  if ((s.match(/::/g) || []).length > 1) return undefined;
  const [l, r] = s.split('::');
  const lp = l ? l.split(':').filter((i) => i.length) : [];
  const rp = r !== undefined && r ? r.split(':').filter((i) => i.length) : [];
  if (!lp.every((i) => /^[0-9a-fA-F]{1,4}$/.test(i))) return undefined;
  if (!rp.every((i) => /^[0-9a-fA-F]{1,4}$/.test(i))) return undefined;
  const total = lp.length + rp.length;
  if (s.includes('::')) {
    if (total > 8) return undefined;
  } else if (total !== 8) return undefined;
  const mid = s.includes('::') ? new Array<string>(8 - total).fill('0') : [];
  const words = [...lp, ...mid, ...rp];
  if (words.length !== 8) return undefined;
  const out = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    const n = Number.parseInt(words[i], 16);
    if (!Number.isFinite(n) || n < 0 || n > 0xffff) return undefined;
    out[i * 2] = n >>> 8;
    out[i * 2 + 1] = n & 0xff;
  }
  return out;
};
const IPAddress = tagged(
  0x87,
  P.apply(P.bytes(null), {
    encode: (b: Uint8Array): string => {
      if (b.length === 4) return ipv4Decode(b);
      if (b.length === 16) return ipv6Decode(b);
      return `hex:${bytesToHex(b)}`;
    },
    decode: (s: string): Uint8Array => {
      if (s.startsWith('hex:')) return hexToBytes(s.slice(4));
      const v4 = ipv4Encode(s);
      if (v4) return v4;
      const v6 = ipv6Encode(s);
      if (v6) return v6;
      throw new Error(`invalid SAN iPAddress ${s}`);
    },
  })
);
const ExtOtherName = ASN1.sequence({ type: ASN1.OID, value: ASN1.explicit(0, TLVNodeCodec) });
// RFC 5280 section 4.2.1.6: GeneralName.
const ExtGeneralName = ASN1.choice({
  otherName: ASN1.implicit(0, ExtOtherName),
  rfc822Name: ASN1.implicit(1, IA5),
  dNSName: ASN1.implicit(2, IA5),
  x400Address: ASN1.implicit(3, ASN1.OctetString),
  directoryName: ASN1.explicit(4, X509Name),
  ediPartyName: ASN1.implicit(5, ASN1.OctetString),
  uniformResourceIdentifier: ASN1.implicit(6, IA5),
  iPAddress: IPAddress,
  registeredID: ASN1.implicit(8, ASN1.OID),
});
const ExtGeneralNames = ASN1.sequence({ list: P.array(null, ExtGeneralName) });
// RFC 5280 section 4.2.1.1: AuthorityKeyIdentifier.
const ExtAKI = ASN1.sequence({
  keyIdentifier: ASN1.optional(ASN1.implicit(0, ASN1.OctetString)),
  authorityCertIssuer: ASN1.optional(ASN1.implicit(1, ExtGeneralNames)),
  authorityCertSerialNumber: ASN1.optional(ASN1.implicit(2, ASN1.Integer)),
});
// RFC 5280 section 4.2.2.1: AuthorityInfoAccessSyntax.
const ExtAIA = ASN1.sequence({
  list: P.array(null, ASN1.sequence({ method: ASN1.OID, location: ExtGeneralName })),
});
// RFC 3820 section 3.8: ProxyCertInfo extension.
const OctetsHex = tagged(0x04, HexBytes);
const ExtProxyCertInfo = ASN1.sequence({
  pathLen: ASN1.optional(ASN1.Integer),
  policy: ASN1.sequence({ language: ASN1.OID, policy: ASN1.optional(OctetsHex) }),
});
// RFC 7633 section 4: TLS Feature extension syntax.
const ExtTLSFeature = ASN1.sequence({ list: P.array(null, ASN1.Integer) });
const SCTItem = P.struct({
  version: P.U8,
  logID: P.bytes(32),
  timestamp: P.U64BE,
  extensions: P.apply(P.bytes(P.U16BE), {
    encode: (b: Uint8Array): string => bytesToHex(b),
    decode: (s: string): Uint8Array => hexToBytes(s),
  }),
  hash: P.U8,
  signatureAlgorithm: P.U8,
  signature: P.bytes(P.U16BE),
});
const SCTListInner = P.apply(P.bytes(null), {
  encode: (b: Uint8Array): P.UnwrapCoder<typeof SCTItem>[] =>
    P.prefix(P.U16BE, P.array(null, P.prefix(P.U16BE, SCTItem))).decode(
      b.length && b[0] === 0x04 ? ASN1.OctetString.decode(b) : b
    ),
  decode: (v: P.UnwrapCoder<typeof SCTItem>[]): Uint8Array =>
    P.prefix(P.U16BE, P.array(null, P.prefix(P.U16BE, SCTItem))).encode(v),
}) satisfies P.CoderType<P.UnwrapCoder<typeof SCTItem>[]>;
// RFC 5280 section 4.2.1.13: DistributionPointName.
const ExtDistributionPointName = ASN1.choice({
  fullName: ASN1.implicit(0, ExtGeneralNames),
  nameRelativeToCRLIssuer: ASN1.implicit(1, ASN1.set(NameAttr)),
});
// RFC 5280 section 4.2.1.13: DistributionPoint and CRLDistributionPoints.
const ExtCRLDP = ASN1.sequence({
  list: P.array(
    null,
    ASN1.sequence({
      distributionPoint: ASN1.optional(ASN1.explicit(0, ExtDistributionPointName)),
      reasons: ASN1.optional(ASN1.explicit(1, ASN1BitStringRaw)),
      cRLIssuer: ASN1.optional(ASN1.explicit(2, ExtGeneralNames)),
    })
  ),
});
const oidSet = <T extends Record<string, readonly [string, unknown]>>(map: T): Set<string> =>
  new Set((Object.values(map) as ReadonlyArray<readonly [string, unknown]>).map((v) => v[0]));
const oidDecode = <T>(
  coder: P.CoderType<T>,
  set: Set<string>
): ((id: string, val: Uint8Array) => T | undefined) => {
  return (id, val) =>
    set.has(id) ? coder.decode(concatBytes(ASN1.OID.encode(id), val)) : undefined;
};
const PolicyNoticeRef = ASN1.sequence({
  organization: RawTLV,
  numbers: ASN1.sequence({ list: P.array(null, ASN1.Integer) }),
});
const DisplayText = ASN1.choice({
  utf8: UTF8String,
  ia5: IA5,
  visible: VisibleString,
  bmp: BMPString,
});
const textDecode = (der: Uint8Array): CertText => {
  const d = DisplayText.decode(der);
  return { tag: d.TAG, text: d.data };
};
const textEncode = (v: CertText): Uint8Array => {
  if (v.tag === 'utf8') return UTF8String.encode(v.text);
  if (v.tag === 'ia5') return IA5.encode(v.text);
  if (v.tag === 'visible') return VisibleString.encode(v.text);
  return BMPString.encode(v.text);
};
const userNoticeDecode = (
  v: Uint8Array
): Extract<CertPolicyQualifier, { TAG: 'userNotice' }>['data'] => {
  const t = TLV.decode(v);
  if (t.tag !== 0x30) throw new Error('PolicyQualifierInfo.userNotice must be SEQUENCE');
  const items = P.array(null, RawTLV).decode(t.value);
  const out: Extract<CertPolicyQualifier, { TAG: 'userNotice' }>['data'] = {};
  for (const i of items) {
    const c = TLV.decode(i);
    if (c.tag === 0x30 && !out.noticeRef) {
      const n = PolicyNoticeRef.decode(i);
      out.noticeRef = {
        organization: textDecode(n.organization),
        numbers: n.numbers.list.map((x) => Number(x)),
      };
      continue;
    }
    if (!out.explicitText) out.explicitText = textDecode(i);
  }
  return out;
};
const userNoticeEncode = (
  u: Extract<CertPolicyQualifier, { TAG: 'userNotice' }>['data']
): Uint8Array =>
  ASN1.sequence({
    list: P.array(null, RawTLV),
  }).encode({
    list: [
      ...(u.noticeRef
        ? [
            PolicyNoticeRef.encode({
              organization: textEncode(u.noticeRef.organization),
              numbers: { list: u.noticeRef.numbers.map((n) => BigInt(n)) },
            }),
          ]
        : []),
      ...(u.explicitText ? [textEncode(u.explicitText)] : []),
    ],
  });
const PolicyQualifierInfoRaw = ASN1.sequence({ oid: ASN1.OID, value: RawTLV });
const ExtPolicyQualifierInfo = P.apply(PolicyQualifierInfoRaw, {
  encode: (x: P.UnwrapCoder<typeof PolicyQualifierInfoRaw>): CertPolicyQualifier => {
    if (x.oid === '1.3.6.1.5.5.7.2.1') return { TAG: 'cps', data: IA5.decode(x.value) };
    if (x.oid === '1.3.6.1.5.5.7.2.2')
      return { TAG: 'userNotice', data: userNoticeDecode(x.value) };
    return { TAG: 'unknown', data: { oid: x.oid, value: TLVNodeCodec.decode(x.value) } };
  },
  decode: (q: CertPolicyQualifier): P.UnwrapCoder<typeof PolicyQualifierInfoRaw> => {
    if (q.TAG === 'unknown') return { oid: q.data.oid, value: TLVNodeCodec.encode(q.data.value) };
    if (q.TAG === 'cps') return { oid: '1.3.6.1.5.5.7.2.1', value: IA5.encode(q.data) };
    return { oid: '1.3.6.1.5.5.7.2.2', value: userNoticeEncode(q.data) };
  },
}) satisfies P.CoderType<CertPolicyQualifier>;
// RFC 5280 section 4.2.1.4: CertificatePolicies.
const ExtPolicies = ASN1.sequence({
  list: P.array(
    null,
    ASN1.sequence({
      policy: ASN1.OID,
      qualifiers: ASN1.optional(ASN1.sequence({ list: P.array(null, ExtPolicyQualifierInfo) })),
    })
  ),
});
const ExtGeneralSubtree = ASN1.sequence({
  base: ExtGeneralName,
  minimum: ASN1.optional(ASN1.implicit(0, ASN1.Integer)),
  maximum: ASN1.optional(ASN1.implicit(1, ASN1.Integer)),
});
// RFC 5280 section 4.2.1.10: NameConstraints.
const ExtNameConstraints = ASN1.sequence({
  permitted: ASN1.optional(
    ASN1.explicit(0, ASN1.sequence({ list: P.array(null, ExtGeneralSubtree) }))
  ),
  excluded: ASN1.optional(
    ASN1.explicit(1, ASN1.sequence({ list: P.array(null, ExtGeneralSubtree) }))
  ),
});
const ExtBody = ASN1.sequence({ critical: ASN1.optional(ASN1Bool), extnValue: ASN1.OctetString });
const ExtBasic = ASN1.sequence({
  ca: ASN1.optional(ASN1Bool),
  pathLen: ASN1.optional(ASN1.Integer),
});
const ExtEKU = ASN1.sequence({ list: P.array(null, ASN1.OID) });
const ExtKnownMap = {
  ski: ['2.5.29.14', ASN1.OctetString],
  basic: ['2.5.29.19', ExtBasic],
  keyUsage: ['2.5.29.15', ASN1BitStringRaw],
  eku: ['2.5.29.37', ExtEKU],
  san: ['2.5.29.17', ExtGeneralNames],
  aki: ['2.5.29.35', ExtAKI],
  aia: ['1.3.6.1.5.5.7.1.1', ExtAIA],
  proxyCertInfo: ['1.3.6.1.5.5.7.1.14', ExtProxyCertInfo],
  tlsFeature: ['1.3.6.1.5.5.7.1.24', ExtTLSFeature],
  sct: ['1.3.6.1.4.1.11129.2.4.2', SCTListInner],
  crlDistributionPoints: ['2.5.29.31', ExtCRLDP],
  policies: ['2.5.29.32', ExtPolicies],
  nameConstraints: ['2.5.29.30', ExtNameConstraints],
} as const;
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
const ExtValueByOID = P.mappedTag(ASN1.OID, {
  ski: ['2.5.29.14', ASN1.OctetString],
  basic: ['2.5.29.19', ExtBasic],
  keyUsage: ['2.5.29.15', ASN1BitStringRaw],
  eku: ['2.5.29.37', ExtEKU],
  san: ['2.5.29.17', ExtGeneralNames],
  aki: ['2.5.29.35', ExtAKI],
  aia: ['1.3.6.1.5.5.7.1.1', ExtAIA],
  proxyCertInfo: ['1.3.6.1.5.5.7.1.14', ExtProxyCertInfo],
  tlsFeature: ['1.3.6.1.5.5.7.1.24', ExtTLSFeature],
  sct: ['1.3.6.1.4.1.11129.2.4.2', SCTListInner],
  crlDistributionPoints: ['2.5.29.31', ExtCRLDP],
  policies: ['2.5.29.32', ExtPolicies],
  nameConstraints: ['2.5.29.30', ExtNameConstraints],
} as const);
const extValueDecode = oidDecode(ExtValueByOID, oidSet(ExtKnownMap));
export const X509 = {
  decode: (der: Uint8Array, opts: BEROpts = {}): Cert =>
    X509C.Certificate.decode(berView(der, opts).der),
  encode: (cert: Cert): Uint8Array => X509C.Certificate.encode(cert),
} as const;
const knownCritical = new Set([
  '2.5.29.14',
  '2.5.29.15',
  '2.5.29.17',
  '2.5.29.19',
  '2.5.29.30',
  '2.5.29.31',
  '2.5.29.32',
  '2.5.29.35',
  '2.5.29.36',
  '2.5.29.37',
  '2.5.29.54',
]);
const certExts = (cert: Cert): CertExt[] => {
  const out: CertExt[] = [];
  for (const e of cert.tbs.extensions?.list || []) {
    const body = ExtBody.inner.decode(e.rest);
    const d: CertExt = { oid: e.oid, critical: !!body.critical };
    const k = extValueDecode(e.oid, body.extnValue);
    if (k) {
      (
        ({
          ski: (v: Uint8Array) => {
            d.ski = v;
          },
          basic: (v: P.UnwrapCoder<typeof ExtBasic>) => {
            d.basic = v;
          },
          keyUsage: (v: P.UnwrapCoder<typeof ASN1BitStringRaw>) => {
            d.keyUsage = v;
          },
          eku: (v: P.UnwrapCoder<typeof ExtEKU>) => {
            d.eku = v;
          },
          san: (v: P.UnwrapCoder<typeof ExtGeneralNames>) => {
            d.san = v;
          },
          aki: (v: P.UnwrapCoder<typeof ExtAKI>) => {
            d.aki = v;
          },
          aia: (v: P.UnwrapCoder<typeof ExtAIA>) => {
            d.aia = v;
          },
          proxyCertInfo: (v: P.UnwrapCoder<typeof ExtProxyCertInfo>) => {
            d.proxyCertInfo = v;
          },
          tlsFeature: (v: P.UnwrapCoder<typeof ExtTLSFeature>) => {
            d.tlsFeature = v;
          },
          sct: (v: P.UnwrapCoder<typeof SCTListInner>) => {
            d.sct = v;
          },
          crlDistributionPoints: (v: P.UnwrapCoder<typeof ExtCRLDP>) => {
            d.crlDistributionPoints = v;
          },
          policies: (v: P.UnwrapCoder<typeof ExtPolicies>) => {
            d.policies = v;
          },
          nameConstraints: (v: P.UnwrapCoder<typeof ExtNameConstraints>) => {
            d.nameConstraints = v;
          },
        }) as const
      )[k.TAG](k.data as never);
    }
    out.push(d);
  }
  return out;
};
const certInfo = (
  cert: Cert
): {
  isCA: boolean;
  pathLen?: bigint;
  keyUsage?: ReturnType<typeof keyUsageBits>;
  eku?: string[];
  critical: string[];
} => {
  let isCA = false;
  let pathLen: bigint | undefined;
  let keyUsage: ReturnType<typeof keyUsageBits> | undefined;
  let eku: string[] | undefined;
  const critical: string[] = [];
  for (const e of certExts(cert)) {
    if (e.critical) critical.push(e.oid);
    if (e.basic) {
      isCA = !!e.basic.ca;
      pathLen = e.basic.pathLen;
    }
    if (e.keyUsage) keyUsage = keyUsageBits(e.keyUsage);
    if (e.eku) eku = e.eku.list;
  }
  return { isCA, pathLen, keyUsage, eku, critical };
};
const subjectDer = (cert: Cert): Uint8Array => X509C.Name.encode(cert.tbs.subject);
const issuerDer = (cert: Cert): Uint8Array => X509C.Name.encode(cert.tbs.issuer);
const certEq = (a: Cert, b: Cert): boolean =>
  equalBytes(subjectDer(a), subjectDer(b)) && a.tbs.serial === b.tbs.serial;
const loadCert = (x: string | Uint8Array | Cert, opts: BEROpts = {}): Cert => {
  if (typeof x === 'string') return X509.decode(onePem(x, 'CERTIFICATE').der, opts);
  if (x instanceof Uint8Array) return X509.decode(x, opts);
  return X509.decode(X509C.Certificate.encode(x), opts);
};
const ensureCritical = (c: Cert): void => {
  for (const oid of certInfo(c).critical)
    if (!knownCritical.has(oid)) throw new Error(`unknown critical extension ${oid}`);
};
const ensurePurpose = (c: Cert, purpose: 'any' | 'smime' | 'codeSigning'): void => {
  const eku = certInfo(c).eku;
  if (!eku || purpose === 'any') return;
  if (eku.includes('2.5.29.37.0')) return;
  if (purpose === 'smime' && !eku.includes('1.3.6.1.5.5.7.3.4'))
    throw new Error('EKU missing emailProtection');
  if (purpose === 'codeSigning' && !eku.includes('1.3.6.1.5.5.7.3.3'))
    throw new Error('EKU missing codeSigning');
};
const ECDSASig = ASN1.sequence({ r: ASN1.Integer, s: ASN1.Integer });
const sigCompact = (curve: Curve, sig: Uint8Array): Uint8Array => {
  const n = ECDSASig.decode(sig);
  const sigBytes = ecCurve(curve).lengths.signature;
  if (!sigBytes) throw new Error(`curve signature length missing for ${curve}`);
  const nlen = sigBytes >>> 1;
  const r = Big.encode(n.r);
  const s = Big.encode(n.s);
  if (r.length > nlen || s.length > nlen)
    throw new Error('invalid ECDSA DER signature integer length');
  return concatBytes(new Uint8Array(nlen - r.length), r, new Uint8Array(nlen - s.length), s);
};
// RFC 5754 section 3: ECDSA-with-SHA2 CMS signature algorithm OIDs.
const algByOid = (oid: string): { dOid: string; hash: (b: Uint8Array) => Uint8Array } => {
  const res = (
    {
      '1.2.840.10045.4.3.2': { dOid: '2.16.840.1.101.3.4.2.1', hash: sha256 },
      '1.2.840.10045.4.3.3': { dOid: '2.16.840.1.101.3.4.2.2', hash: sha384 },
      '1.2.840.10045.4.3.4': { dOid: '2.16.840.1.101.3.4.2.3', hash: sha512 },
    } as const
  )[oid];
  if (!res) throw new Error(`unsupported signatureAlgorithm OID ${oid}`);
  return res;
};

const cmsSigner = (v: CmsState): Cert | undefined =>
  v.certs.find((c) => {
    const m = certMeta(c);
    return equalBytes(v.sIssuer, m.issuer) && v.sSerial === m.serial;
  });

type CmsState = {
  ci: P.UnwrapCoder<typeof CMSX.ContentInfo>;
  sd: P.UnwrapCoder<typeof CMSX.SignedData>;
  si: P.UnwrapCoder<typeof CMSX.SignerInfo>;
  sa: AttributeCodec[] | undefined;
  saSet: Uint8Array | undefined;
  saImplicit: Uint8Array | undefined;
  content: Uint8Array;
  certs: Cert[];
  sIssuer: Uint8Array;
  sSerial: bigint;
  sigAlg: string;
  digestAlg: string;
  sigVal: Uint8Array;
  eType: string;
};
const CMSState = P.apply(P.bytes(null), {
  encode: (src): CmsState => {
    const ci = CMSX.ContentInfo.decode(src);
    if (ci.contentType !== '1.2.840.113549.1.7.2')
      throw new Error(`expected SignedData contentType, got ${ci.contentType}`);
    const sd = CMSX.SignedData.decode(ci.content);
    const eType = sd.encapContentInfo.eContentType;
    const content = sd.encapContentInfo.eContent || new Uint8Array();
    const certPick = {
      certificate: (
        i: Extract<P.UnwrapCoder<typeof CMSCertificateChoices>, { TAG: 'certificate' }>
      ) => [i.data as Cert],
      extendedCertificate: () => [] as Cert[],
      v1AttrCert: () => [] as Cert[],
      v2AttrCert: () => [] as Cert[],
      other: () => [] as Cert[],
    } as const;
    const certs: Cert[] = [];
    for (const i of sd.certificates || []) certs.push(...certPick[i.TAG](i as never));
    if (!certs.length) throw new Error('SignedData.certificates missing');
    const si = sd.signerInfos[0];
    if (!si) throw new Error('SignerInfo[0] missing');
    const sid = cmsIssuerSerial(si.sid);
    const sa = si.signedAttrs;
    return {
      ci,
      sd,
      si,
      sa,
      saSet: sa ? ASN1.set(CMSX.Attribute).encode(sa) : undefined,
      saImplicit: sa ? ASN1.implicit(0, ASN1.set(CMSX.Attribute)).encode(sa) : undefined,
      content,
      certs,
      sIssuer: X509C.Name.encode(sid.issuer),
      sSerial: sid.serial,
      sigAlg: si.signatureAlg.algorithm,
      digestAlg: si.digestAlg.algorithm,
      sigVal: si.signature,
      eType,
    };
  },
  decode: () => {
    throw new Error('CMSState.encode unsupported');
  },
}) satisfies P.CoderType<CmsState>;
type CMSSignerIssuerSerial = Extract<
  P.UnwrapCoder<typeof CMSSignerIdentifier>,
  { TAG: 'issuerSerial' }
>['data'];
const cmsIssuerSerial = (sid: P.UnwrapCoder<typeof CMSSignerIdentifier>): CMSSignerIssuerSerial => {
  if (sid.TAG !== 'issuerSerial')
    throw new Error('SignerInfo.sid subjectKeyIdentifier is not supported');
  return sid.data;
};
const cmsValidateView = (v: CmsState, opts: CmsVerifyOpts = {}): CmsVerify => {
  const signerCert = cmsSigner(v);
  if (!signerCert) throw new Error('SignerInfo cert not found in certificate set');
  const signer = X509.decode(X509C.Certificate.encode(signerCert), opts);
  const now = timeSec(opts.time);
  if (
    now < timeEpoch(signer.tbs.validity.notBefore) ||
    now > timeEpoch(signer.tbs.validity.notAfter)
  )
    throw new Error('signer certificate outside validity window');
  const signerInfo = certInfo(signer);
  if (signerInfo.isCA) throw new Error('signer certificate must not be a CA certificate');
  if (signerInfo.keyUsage && !signerInfo.keyUsage.digitalSignature)
    throw new Error('signer keyUsage missing digitalSignature');
  ensurePurpose(signer, opts.purpose || 'any');
  ensureCritical(signer);
  const pool = [
    ...v.certs.map((c) => X509.decode(X509C.Certificate.encode(c), opts)),
    ...(opts.chain || []).map((c) => loadCert(c, opts)),
  ].filter((c) => !certEq(c, signer));
  for (const c of pool) ensureCritical(c);
  return {
    signatureOid: v.sigAlg,
    signer,
    signedAttrs: !!v.sa,
    chain: buildChain(signer, pool, now),
  };
};

const cmsSigOk = (v: CmsState, signer: Cert): boolean => {
  const key = SpkiKey.decode(signer.tbs.spki);
  if (key.keyType !== 'EC')
    throw new Error('CMS.verify({checkSignatures:true}) supports EC signer certificates only');
  if (!isSignCurve(key.curve))
    throw new Error(`CMS.verify({checkSignatures:true}) unsupported signer curve ${key.curve}`);
  const a = algByOid(v.sigAlg);
  const sig = sigCompact(key.curve, v.sigVal);
  const inputs = v.sa ? [v.saSet!, v.saImplicit!] : [v.content];
  // CMS implementations vary on attrs canonicalization and digest feed; accept either if valid.
  let okSig = false;
  for (const data of inputs) {
    const verified = ecCurve(key.curve).verify(sig, a.hash(data), key.publicKey, {
      lowS: false,
      prehash: false,
    });
    if (verified) okSig = true;
    if (okSig) break;
  }
  return okSig;
};
const derCmp = (a: Uint8Array, b: Uint8Array): number => {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = a[i] - b[i];
    if (d) return d;
  }
  return a.length - b.length;
};
const sortSetOfDer = <T>(items: T[], enc: (x: T) => Uint8Array): T[] =>
  [...items]
    .map((v) => ({ v, der: enc(v) }))
    .sort((x, y) => derCmp(x.der, y.der))
    .map((x) => x.v);
const timeToDer = (ts: number): Uint8Array => {
  const d = new Date(Math.floor(ts) * 1000);
  const pad2 = (n: number): string => `${n}`.padStart(2, '0');
  const pad4 = (n: number): string => `${n}`.padStart(4, '0');
  const y = d.getUTCFullYear();
  const s =
    y >= 1950 && y <= 2049
      ? `${pad2(y % 100)}${pad2(d.getUTCMonth() + 1)}${pad2(d.getUTCDate())}${pad2(d.getUTCHours())}${pad2(
          d.getUTCMinutes()
        )}${pad2(d.getUTCSeconds())}Z`
      : `${pad4(y)}${pad2(d.getUTCMonth() + 1)}${pad2(d.getUTCDate())}${pad2(d.getUTCHours())}${pad2(
          d.getUTCMinutes()
        )}${pad2(d.getUTCSeconds())}Z`;
  return (y >= 1950 && y <= 2049 ? UTCTime : GeneralizedTime).encode(s);
};
const certId = (c: Cert): string => `${base64.encode(subjectDer(c))}:${c.tbs.serial.toString(16)}`;
const buildChain = (leaf: Cert, pool: Cert[], now: number): Cert[] => {
  const seen = new Set<string>();
  const chain: Cert[] = [leaf];
  let cur = leaf;
  while (true) {
    const id = certId(cur);
    if (seen.has(id)) throw new Error('certificate chain loop detected');
    seen.add(id);
    const curIssuer = issuerDer(cur);
    const curSubject = subjectDer(cur);
    if (equalBytes(curIssuer, curSubject)) return chain;
    if (now < timeEpoch(cur.tbs.validity.notBefore) || now > timeEpoch(cur.tbs.validity.notAfter))
      throw new Error(`certificate not valid at time: ${base64.encode(curSubject)}`);
    const issuer = pool.find((i) => equalBytes(curIssuer, subjectDer(i)));
    if (!issuer) {
      if (chain.length === 1) throw new Error('no issuer found for signer in chain');
      return chain;
    }
    const issuerInfo = certInfo(issuer);
    if (!issuerInfo.isCA) throw new Error('issuer certificate is not CA');
    if (issuerInfo.keyUsage && !issuerInfo.keyUsage.keyCertSign)
      throw new Error('issuer keyUsage missing keyCertSign');
    if (issuerInfo.pathLen !== undefined && BigInt(chain.length - 1) > issuerInfo.pathLen)
      throw new Error('issuer pathLenConstraint exceeded');
    chain.push(issuer);
    cur = issuer;
  }
};
const cmsVerifyEc = (der: Uint8Array, opts: CmsVerifyOpts = {}): CmsVerify => {
  const { checkSignatures = true } = opts;
  const v = CMSState.decode(berView(der, opts).der);
  const out = cmsValidateView(v, opts);
  if (!checkSignatures) return out;
  if (cmsSigOk(v, out.signer)) return out;
  throw new Error('CMS signature invalid');
};

const algByCurve = (
  curve: Curve
): {
  sigOid: '1.2.840.10045.4.3.2' | '1.2.840.10045.4.3.3' | '1.2.840.10045.4.3.4';
  dOid: string;
  hash: (b: Uint8Array) => Uint8Array;
} =>
  (
    ({
      'P-256': { sigOid: '1.2.840.10045.4.3.2', dOid: '2.16.840.1.101.3.4.2.1', hash: sha256 },
      'P-384': { sigOid: '1.2.840.10045.4.3.3', dOid: '2.16.840.1.101.3.4.2.2', hash: sha384 },
      'P-521': { sigOid: '1.2.840.10045.4.3.4', dOid: '2.16.840.1.101.3.4.2.3', hash: sha512 },
    }) as const
  )[curve];

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
    content: Uint8Array,
    signingCertPem: string,
    privateKeyPem: string,
    chainPem?: string,
    opts?: CmsSignOpts
  ) => Uint8Array;
};
export const CMS: CMSApi = {
  decode: (der: Uint8Array, opts: BEROpts = {}) => {
    const ber = berView(der, opts);
    const ci = CMSX.ContentInfo.decode(ber.der) as P.UnwrapCoder<typeof CMSX.ContentInfo> & {
      ber?: BERDoc;
    };
    ci.ber = ber;
    return ci;
  },
  encode: (contentInfo: P.UnwrapCoder<typeof CMSX.ContentInfo> & { ber?: BERDoc }) => {
    const der = CMSX.ContentInfo.encode(contentInfo);
    const ber = contentInfo.ber;
    if (!ber) return der;
    return DERUtils.BER.encode(ber.nodes, der);
  },
  contentType: (der: Uint8Array, opts: BEROpts = {}) => CMS.decode(der, opts).contentType,
  signed: (der: Uint8Array, opts: BEROpts = {}): P.UnwrapCoder<typeof CMSX.SignedData> => {
    const ci = CMS.decode(der, opts);
    if (ci.contentType !== '1.2.840.113549.1.7.2')
      throw new Error(`expected SignedData contentType, got ${ci.contentType}`);
    return CMSX.SignedData.decode(ci.content);
  },
  verify: (der: Uint8Array, opts: CmsVerifyOpts = {}): CmsVerify => cmsVerifyEc(der, opts),
  detach: (der: Uint8Array, opts: BEROpts = {}): CmsDetached => {
    const v = CMSState.decode(berView(der, opts).der);
    v.sd.encapContentInfo.eContent = undefined;
    v.ci.content = CMSX.SignedData.encode(v.sd);
    return {
      content: v.content,
      signature: CMSX.ContentInfo.encode(v.ci),
      certs: v.certs,
    };
  },
  attach: (signature: Uint8Array, content: Uint8Array, opts: BEROpts = {}): Uint8Array => {
    const v = CMSState.decode(berView(signature, opts).der);
    v.sd.encapContentInfo.eContent = content;
    v.ci.content = CMSX.SignedData.encode(v.sd);
    return CMSX.ContentInfo.encode(v.ci);
  },
  verifyDetached: (
    signature: Uint8Array,
    content: Uint8Array,
    opts: CmsVerifyOpts = {}
  ): CmsVerify => cmsVerifyEc(CMS.attach(signature, content, opts), opts),
  sign: (
    content: Uint8Array,
    signingCertPem: string,
    privateKeyPem: string,
    chainPem = '',
    opts: CmsSignOpts = {}
  ): Uint8Array => {
    const k = loadSigningPem(signingCertPem, privateKeyPem, chainPem);
    const leafKey = SpkiKey.decode(k.leaf.tbs.spki);
    if (leafKey.keyType !== 'EC' || k.key.keyType !== 'EC')
      throw new Error('cmsSignEc supports EC cert/key only');
    const alg = algByCurve(k.key.curve);
    const attrs: AttributeCodec[] = [
      { oid: '1.2.840.113549.1.9.3', values: [ASN1.OID.encode('1.2.840.113549.1.7.1')] },
      ...(opts.createdTs === undefined
        ? []
        : [{ oid: '1.2.840.113549.1.9.5', values: [timeToDer(opts.createdTs)] }]),
      { oid: '1.2.840.113549.1.9.4', values: [ASN1.OctetString.encode(alg.hash(content))] },
    ];
    const useAttrs = opts.signedAttrs !== false;
    const toSign = useAttrs ? ASN1.set(CMSX.Attribute).encode(attrs) : content;
    const sig = ecCurve(k.key.curve).sign(alg.hash(toSign), k.key.secretKey, {
      prehash: false,
      format: 'der',
      lowS: false,
    });
    const si = {
      version: 1n,
      sid: {
        TAG: 'issuerSerial' as const,
        data: { issuer: k.leaf.tbs.issuer, serial: k.leaf.tbs.serial },
      },
      digestAlg: { algorithm: alg.dOid, params: new Uint8Array() },
      signedAttrs: useAttrs ? attrs : undefined,
      signatureAlg: { algorithm: alg.sigOid, params: new Uint8Array() },
      signature: sig,
      unsignedAttrs: undefined,
    };
    const certs = sortSetOfDer(
      [
        { TAG: 'certificate' as const, data: k.leaf },
        ...k.chain.map((c) => ({
          TAG: 'certificate' as const,
          data: c,
        })),
      ],
      (x) => CMSCertificateChoices.encode(x)
    );
    const sd = {
      version: 1n,
      digestAlgorithms: [{ algorithm: alg.dOid, params: new Uint8Array() }],
      encapContentInfo: { eContentType: '1.2.840.113549.1.7.1', eContent: content },
      certificates: certs,
      crls: undefined,
      signerInfos: [si],
    };
    const ci = { contentType: '1.2.840.113549.1.7.2', content: CMSX.SignedData.encode(sd) };
    return CMSX.ContentInfo.encode(ci);
  },
};

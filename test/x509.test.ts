import { ed25519 } from '@noble/curves/ed25519.js';
import { ed448 } from '@noble/curves/ed448.js';
import { equalBytes, hexToBytes } from '@noble/curves/utils.js';
import { shake256 } from '@noble/hashes/sha3.js';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { base64 } from '@scure/base';
import * as P from 'micro-packed';
import { deepStrictEqual, throws } from 'node:assert';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DERUtils } from '../src/convert.ts';
import { oid, oidName } from '../src/pgp.ts';
import { CERTUtils, CMS, X509, __TEST, pemBlocks } from '../src/x509.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.join(__dirname, 'vectors', 'certs');
// Test-only: exercise compatibility with callers that still pass raw dotted OID strings.
const rawOid = (name: string): string => oid.decode(oidName.encode(name));

type VectorKind = 'cert' | 'cms' | 'cms-pem' | 'cms-eml';
type Vector = {
  name: string;
  kind: VectorKind;
  rsa: boolean;
  ber?: true;
  error?: true;
  validBefore?: number;
};

const read = (name: string): Uint8Array => new Uint8Array(fs.readFileSync(path.join(ROOT, name)));
const readText = (name: string): string => fs.readFileSync(path.join(ROOT, name), 'utf8');
const certTime = (t: { TAG: 'utc' | 'generalized'; data: string }): number => {
  const txt = t.data;
  if (t.TAG === 'utc') {
    const yy = Number(txt.slice(0, 2));
    const y = yy >= 50 ? 1900 + yy : 2000 + yy;
    return Math.floor(
      Date.UTC(
        y,
        Number(txt.slice(2, 4)) - 1,
        Number(txt.slice(4, 6)),
        Number(txt.slice(6, 8)),
        Number(txt.slice(8, 10)),
        Number(txt.slice(10, 12))
      ) / 1000
    );
  }
  return Math.floor(
    Date.UTC(
      Number(txt.slice(0, 4)),
      Number(txt.slice(4, 6)) - 1,
      Number(txt.slice(6, 8)),
      Number(txt.slice(8, 10)),
      Number(txt.slice(10, 12)),
      Number(txt.slice(12, 14))
    ) / 1000
  );
};
const isText = (data: Uint8Array): boolean => {
  const n = Math.min(data.length, 1024);
  if (!n) return false;
  let bad = 0;
  for (let i = 0; i < n; i++) {
    const b = data[i];
    if (b === 0) return false;
    const printable = (b >= 0x20 && b <= 0x7e) || b === 0x09 || b === 0x0a || b === 0x0d;
    if (!printable) bad++;
  }
  return bad * 20 < n;
};
const readSigFromEml = (name: string): Uint8Array => {
  const t = readText(name);
  const m = t.match(/Content-Description:[^\n]*\r?\n\r?\n([\s\S]*?)\r?\n------=_Part_/);
  if (!m) throw new Error(`S/MIME signature block not found in ${name}`);
  const b64 = m[1].replace(/\s+/g, '');
  return base64.decode(b64);
};
const cmsFromText = (name: string): Uint8Array => {
  const text = readText(name);
  const pem = pemBlocks(text)[0];
  if (pem) return pem.der;
  const p = text.split(/\r?\n\r?\n/, 2);
  if (p.length === 2) {
    const b64 = p[1].replace(/\s+/g, '');
    if (b64.length) return base64.decode(b64);
  }
  throw new Error(`cannot extract CMS bytes from text vector ${name}`);
};

const certFiles = (dir: string): string[] => {
  const base = path.join(ROOT, dir);
  if (!fs.existsSync(base)) return [];
  const out: string[] = [];
  for (const name of fs.readdirSync(base).sort()) {
    if (dir === 'openssl' && name === 'ext-subjectDirectoryAttributes.pem') continue;
    const rel = `${dir}/${name}`;
    const p = path.join(base, name);
    if (!fs.statSync(p).isFile()) continue;
    const lower = name.toLowerCase();
    if (lower.endsWith('.der')) {
      out.push(rel);
      continue;
    }
    if (!lower.endsWith('.pem') && !lower.endsWith('.crt') && !lower.endsWith('.cer')) continue;
    const txt = fs.readFileSync(p, 'utf8');
    if (pemBlocks(txt).some((b) => b.tag === 'CERTIFICATE')) out.push(rel);
  }
  return out;
};

const fileVectors = (
  names: string[],
  kind: VectorKind,
  rsa = false,
  err = false,
  ber = false
): Vector[] =>
  names.map((name) =>
    err
      ? ({ name, kind, rsa, ber: ber ? true : undefined, error: true } as const)
      : ({ name, kind, rsa, ber: ber ? true : undefined } as const)
  );

const VECTORS: Vector[] = [
  { name: 'bearssl/dn-ee.der', kind: 'cert', rsa: false, error: true },
  { name: 'bearssl/dn-ica1.der', kind: 'cert', rsa: false, error: true },
  { name: 'bearssl/dn-ica2.der', kind: 'cert', rsa: false, error: true },
  { name: 'bearssl/dn-root-new.der', kind: 'cert', rsa: false, error: true },
  { name: 'bearssl/dn-root.der', kind: 'cert', rsa: false, error: true },
  { name: 'bearssl/ee-badsig1.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ee-badsig2.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ee-cp1.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ee-cp2.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ee-cp3.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ee-cp4.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ee-dates.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ee-md5.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ee-names.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ee-names2.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ee-names3.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ee-names4.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ee-p256-sha1.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ee-p256-sha224.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ee-p256-sha256.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ee-p256-sha384.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ee-p256-sha512.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ee-p256.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ee-p384.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ee-p521.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ee-sha1.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ee-sha224.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ee-sha384.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ee-sha512.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ee-trailing.crt', kind: 'cert', rsa: false, error: true },
  { name: 'bearssl/ee.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ica1-1016.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ica1-1017.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ica1-4096.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ica1-p256.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ica1-p384.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ica1-p521.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ica1.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ica2-1016.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ica2-1017.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ica2-4096.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ica2-notCA.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ica2-p256.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ica2-p384.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ica2-p521.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/ica2.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/junk.crt', kind: 'cert', rsa: false, error: true },
  // Contains malformed UTF8String payloads; strict UTF-8 decoder must reject.
  { name: 'bearssl/names.crt', kind: 'cert', rsa: false, error: true },
  { name: 'bearssl/root-p256.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/root-p384.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/root-p521.crt', kind: 'cert', rsa: false },
  { name: 'bearssl/root.crt', kind: 'cert', rsa: false },
  // Decodes as cert, but extension semantic decode is expected-invalid in strict RFC mode.
  { name: 'openssl/ext-subjectDirectoryAttributes.pem', kind: 'cert', rsa: false },
  ...fileVectors(certFiles('openssl'), 'cert', false),
  ...fileVectors(
    fs.existsSync(path.join(ROOT, 'openssl-d2i'))
      ? fs
          .readdirSync(path.join(ROOT, 'openssl-d2i'))
          .sort()
          .map((name) => `openssl-d2i/${name}`)
      : [],
    'cms',
    true,
    true
  ),
  ...fileVectors(
    fs.existsSync(path.join(ROOT, 'openssl-cms'))
      ? fs
          .readdirSync(path.join(ROOT, 'openssl-cms'))
          .sort()
          .map((name) => `openssl-cms/${name}`)
      : [],
    'cms',
    true,
    false,
    true
  ),
  { name: 'PKI.js/cms-signed-issue170.der', kind: 'cms', rsa: true },
  { name: 'PKI.js/ecc-enveloped.der', kind: 'cms', rsa: false, ber: true },
  { name: 'PKI.js/ecc-enveloped.cms', kind: 'cms-pem', rsa: false, ber: true },
  {
    name: 'encrypted-dns/cloudflare-https-jiya.mobileconfig',
    kind: 'cms',
    rsa: false,
    validBefore: 1779494400,
  },
  {
    name: 'encrypted-dns/cloudflare-https-old.mobileconfig',
    kind: 'cms',
    rsa: true,
    ber: true,
    validBefore: 1762041600,
  },
  { name: 'PKI.js/smime-test.eml', kind: 'cms-eml', rsa: true, ber: true },
  { name: 'PKI.js/ecc-recipient-cert.der', kind: 'cert', rsa: false },
  { name: 'PKI.js/ecc-recipient-cert.pem', kind: 'cert', rsa: false },
  { name: 'encrypted-dns/cloudflare-signer-jiya.der', kind: 'cert', rsa: false },
];

const EDNS_OLD = 'encrypted-dns/cloudflare-https-old.mobileconfig';
const EDNS_JIYA = 'encrypted-dns/cloudflare-https-jiya.mobileconfig';
const EDNS_JIYA_DER = 'encrypted-dns/cloudflare-signer-jiya.der';

let tpl_cached: Uint8Array;
function getEdnsJiyaTpl() {
  if (tpl_cached == null) {
    tpl_cached = CMS.signed(read(EDNS_JIYA)).encapContentInfo.eContent || new Uint8Array();
  }
  return tpl_cached.slice();
}
let cert_cached: object;
function getCertKeyRoot(): { cert: string; key: string; root: string } {
  if (cert_cached == null) {
    const cert = pem('openssl/p384-server-cert.pem');
    const key = pem('openssl/p384-server-key.pem');
    const root = pem('openssl/p384-root.pem');
    cert_cached = { cert, key, root };
  }
  return cert_cached;
}

const CERT_CREATED = 1760000000000;
function decodeP384Cert() {
  const tpl = getEdnsJiyaTpl();
  const { cert, key, root } = getCertKeyRoot();
  return CMS.decode(CMS.sign(tpl, cert, key, root, { createdTs: CERT_CREATED }));
}

const certDersFromVector = (name: string): Uint8Array[] => {
  const raw = read(name);
  if (!isText(raw)) return [raw];
  const text = new TextDecoder().decode(raw);
  const certs = pemBlocks(text)
    .filter((b) => b.tag === 'CERTIFICATE')
    .map((b) => b.der);
  return certs.length ? certs : [raw];
};

const oneCmsFromPem = (name: string): Uint8Array => {
  const text = readText(name);
  const block = pemBlocks(text)[0];
  if (!block) throw new Error(`no PEM blocks found in ${name}`);
  return block.der;
};
const cmsFromVector = (name: string): Uint8Array => {
  const raw = read(name);
  if (!isText(raw)) return raw;
  return cmsFromText(name);
};
const pem = (name: string): string => readText(name);
const findSigPos = (haystack: Uint8Array, needle: Uint8Array): number => {
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) if (haystack[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
};
type BerNode = ReturnType<typeof DERUtils.BER.decode>['nodes'][number];
const berNodeSize = (n: BerNode): number => 1 + n.lenBytes + n.len;
const berTlvAt = (nodes: BerNode[], path: number[], base = 0): { pos: number; end: number } => {
  let cur = nodes;
  let pos = base;
  let node: BerNode | undefined;
  for (let depth = 0; depth < path.length; depth++) {
    const idx = path[depth];
    if (idx === undefined) throw new Error(`missing BER path index depth=${depth}`);
    for (let i = 0; i < idx; i++) pos += berNodeSize(cur[i]);
    node = cur[idx];
    if (!node) throw new Error(`bad BER path depth=${depth} idx=${idx}`);
    if (depth < path.length - 1) {
      pos += 1 + node.lenBytes;
      cur = node.children || [];
    }
  }
  if (!node) throw new Error('empty BER path');
  return { pos, end: pos + berNodeSize(node) };
};
const assertNoExtRaw = (cert: ReturnType<typeof X509.decode>): void => {
  for (const e of cert.tbs.extensions?.list || [])
    deepStrictEqual(Object.prototype.hasOwnProperty.call(e, 'value'), false);
};

describe('x509', () => {
  should('DERLen handles definite lengths above 32-bit signed range', () => {
    const high = Uint8Array.from([0x84, 0x80, 0x00, 0x00, 0x00]);
    deepStrictEqual(DERUtils.DERLen.encode(0x80000000), high);
    deepStrictEqual(DERUtils.DERLen.decode(high), 0x80000000);
  });
  should('pemBlocks accepts RFC 7468 internal hyphen label separators', () => {
    deepStrictEqual(pemBlocks('-----BEGIN X-THING-----\nQQ==\n-----END X-THING-----'), [
      { tag: 'X-THING', b64: 'QQ==', der: Uint8Array.of(0x41) },
    ]);
  });
  should('decodes encrypted-dns .der to exact object shape', () => {
    deepStrictEqual(X509.decode(read(EDNS_JIYA_DER)), {
      tbs: {
        version: 2n,
        serial: 260666524766770889472984792527823126213n,
        signature: { algorithm: 'ecdsa-with-SHA384', params: undefined },
        issuer: {
          rdns: [
            [{ oid: '2.5.4.6', value: { TAG: 'printable', data: 'AT' } }],
            [{ oid: '2.5.4.10', value: { TAG: 'printable', data: 'ZeroSSL' } }],
            [
              {
                oid: 'commonName',
                value: { TAG: 'printable', data: 'ZeroSSL ECC Domain Secure Site CA' },
              },
            ],
          ],
        },
        validity: {
          notBefore: { TAG: 'utc', data: '260221000000Z' },
          notAfter: { TAG: 'utc', data: '260522235959Z' },
        },
        subject: {
          rdns: [[{ oid: 'commonName', value: { TAG: 'utf8', data: '*.angleline.' + 'cn' } }]],
        },
        spki: {
          algorithm: {
            algorithm: 'ecPublicKey',
            params: { tag: 6, valueHex: '2b81040022' },
          },
          publicKey: hexToBytes(
            '0453b0b311ad2a5dc47ac6aca18cad46999f9406c0f125060605f80f868dc9f94347afa5dad3f6a30debfa9618c2dd56e5f4ef18c2d4918b1112e62970bba7d30af02223c86875c70c110a53ce192d365f1a0e5c23387871e8fdf3ec4bb439e884'
          ),
        },
        issuerUniqueID: undefined,
        subjectUniqueID: undefined,
        extensions: {
          list: [
            {
              oid: 'authorityKeyIdentifier',
              rest: hexToBytes('0418301680140f6be64bce3947aef67e901e79f0309192c85fa3'),
            },
            {
              oid: 'subjectKeyIdentifier',
              rest: hexToBytes('041604142ef62917d01e63d131826ffc013a1b878d45fe64'),
            },
            { oid: 'keyUsage', rest: hexToBytes('0101ff040403020780') },
            { oid: 'basicConstraints', rest: hexToBytes('0101ff04023000') },
            { oid: 'extendedKeyUsage', rest: hexToBytes('040c300a06082b06010505070301') },
            {
              oid: 'certificatePolicies',
              rest: hexToBytes(
                '044230403034060b2b06010401b2310102024e3025302306082b06010505070201161768747470733a2f2f7365637469676f2e636f6d2f4350533008060667810c010201'
              ),
            },
            {
              oid: 'authorityInfoAccess',
              rest: hexToBytes(
                '047c307a304b06082b06010505073002863f687474703a2f2f7a65726f73736c2e6372742e7365637469676f2e636f6d2f5a65726f53534c454343446f6d61696e5365637572655369746543412e637274302b06082b06010505073001861f687474703a2f2f7a65726f73736c2e6f6373702e7365637469676f2e636f6d'
              ),
            },
            { oid: 'tlsFeature', rest: hexToBytes('04053003020105') },
            {
              oid: 'sctList',
              rest: hexToBytes(
                '0481f60481f300f10076000e5794bcf3aea93e331b2c9907b3f790df9bc23d713225dd21a925ac61c54e210000019c7ea9e83f00000403004730450221008fe0aa0a78a952a293d065023458d28f3ddc590c109cf2904907ec893e7e305d02204b47114d88fe7920dbaf5469b0a8d1b4030f476d7817218197ea03bf4e667317007700d16ea9a568077e6635a03f37a5ddbc03a53c411214d48818f5e931b323cb95040000019c7ea9e7c60000040300483046022100c117c32b2b1309de60740492e86b21212600930fc37f01647a8d584d4e1ab3e9022100916b4e57891f30d8051d9082bf4bb8c5081c0d787a4f716c66baf15a81ec174f'
              ),
            },
            { oid: 'subjectAltName', rest: hexToBytes('04123010820e2a2e616e676c656c696e652e636e') },
          ],
        },
      },
      sigAlg: { algorithm: 'ecdsa-with-SHA384', params: undefined },
      sig: hexToBytes(
        '30640230281d149f501e190fb2e80270ec042ac81547eca74195afb059563ad23213d690bd099b5f9644d7ec07a1a9524022eba1023063b89955400b2d1e9cb038ed90c53b71075c4f4a5da587e647a504d9e684c073016625891992f5661e71838a0ee1f60a'
      ),
    });
  });
  should('rejects DER BIT STRING encodings with nonzero unused tail bits', () => {
    const der = read(EDNS_JIYA_DER).slice();
    const ku = hexToBytes('03020780');
    const at = findSigPos(der, ku);
    if (at < 0) throw new Error('keyUsage BIT STRING marker not found');
    der[at + ku.length - 1] = 0x81;
    throws(() => X509.decode(der), /BIT STRING|unused/i);
  });
  should('rejects DER BOOLEAN TRUE encoded with noncanonical content octet', () => {
    const der = read(EDNS_JIYA_DER).slice();
    const ext = hexToBytes('0603551d130101ff04');
    const at = findSigPos(der, ext);
    if (at < 0) throw new Error('basicConstraints critical TRUE marker not found');
    der[at + 7] = 0x01;
    throws(() => X509.decode(der), /BOOLEAN|DER/i);
  });
  should('all vectors', () => {
    for (const v of VECTORS) {
      if (v.kind === 'cert') {
        const certs = certDersFromVector(v.name);
        if (!certs.length) throw new Error(`no CERTIFICATE blocks in ${v.name}`);
        for (const der of certs) {
          if (v.error) {
            throws(() => X509.decode(der, v.ber ? { allowBER: true } : undefined));
            continue;
          }
          const dec = X509.decode(der, v.ber ? { allowBER: true } : undefined);
          assertNoExtRaw(dec);
          deepStrictEqual(equalBytes(X509.encode(dec), der), true);
        }
        continue;
      }

      const der =
        v.kind === 'cms-eml'
          ? readSigFromEml(v.name)
          : v.kind === 'cms-pem'
            ? oneCmsFromPem(v.name)
            : cmsFromVector(v.name);
      if (v.error) {
        throws(() => CMS.signed(der, v.ber ? { allowBER: true } : undefined));
        continue;
      }
      const ci = CMS.decode(der, v.ber ? { allowBER: true } : undefined);
      deepStrictEqual(equalBytes(CMS.encode(ci), der), true);
      if (ci.contentType !== 'signedData') continue;
      const parsed = CMS.signed(der, v.ber ? { allowBER: true } : undefined);
      for (const c of parsed.certificates || []) {
        if (c.TAG !== 'certificate') continue;
        const derCert = CERTUtils.Certificate.encode(c.data);
        const cd = X509.decode(derCert, v.ber ? { allowBER: true } : undefined);
        assertNoExtRaw(cd);
        deepStrictEqual(equalBytes(X509.encode(cd), derCert), true);
      }
    }
  });
  should('extension semantic decode is OpenSSL-like for known vector OIDs', () => {
    throws(() =>
      X509.extensions(
        X509.decode(certDersFromVector('openssl/ext-subjectDirectoryAttributes.pem')[0])
      )
    );

    const qc = X509.extensions(X509.decode(certDersFromVector('openssl/fake-gp.pem')[0])).find(
      (e) => e.oid === 'qcStatements'
    );
    if (!qc?.qcStatements) throw new Error('missing qcStatements extension');
    deepStrictEqual(qc.qcStatements.list[0], {
      statementId: 'etsiQcCompliance',
      statementInfo: undefined,
    });
    const eku = X509.extensions(X509.decode(certDersFromVector('openssl/fake-gp.pem')[0])).find(
      (e) => e.oid === 'extendedKeyUsage'
    );
    if (!eku?.eku) throw new Error('missing eku extension');
    deepStrictEqual(eku.eku.list.includes('emailProtection'), true);
    deepStrictEqual(eku.eku.list.includes('codeSigning'), true);
    const allEku = X509.extensions({
      ...X509.decode(certDersFromVector('openssl/fake-gp.pem')[0]),
      tbs: {
        ...X509.decode(certDersFromVector('openssl/fake-gp.pem')[0]).tbs,
        extensions: {
          list: [
            {
              oid: 'extendedKeyUsage',
              rest: DERUtils.ASN1.OctetString.encode(
                DERUtils.ASN1.sequence({
                  list: P.array(null, DERUtils.ASN1.OID),
                }).encode({
                  list: [
                    'anyExtendedKeyUsage',
                    'serverAuth',
                    'clientAuth',
                    'codeSigning',
                    'emailProtection',
                    'timeStamping',
                    'OCSPSigning',
                  ],
                })
              ),
            },
          ],
        },
      },
    }).find((e) => e.oid === 'extendedKeyUsage');
    deepStrictEqual(allEku?.eku?.list, [
      'anyExtendedKeyUsage',
      'serverAuth',
      'clientAuth',
      'codeSigning',
      'emailProtection',
      'timeStamping',
      'OCSPSigning',
    ]);
    const emptyEku = X509.decode(certDersFromVector('openssl/fake-gp.pem')[0]);
    emptyEku.tbs.extensions = {
      list: [{ oid: 'extendedKeyUsage', rest: Uint8Array.from([0x04, 0x02, 0x30, 0x00]) }],
    };
    throws(
      () => X509.extensions(emptyEku),
      /extendedKeyUsage must contain at least one KeyPurposeId/
    );

    const ms = X509.extensions(X509.decode(certDersFromVector('openssl/grfc.pem')[0])).find(
      (e) => e.oid === 'msCertType'
    );
    if (!ms) throw new Error('missing msCertType extension');
    deepStrictEqual(ms.msCertType, { TAG: 'int', data: 0n });
  });
  should('decodes constructed structured GeneralName branches', () => {
    const cert = X509.decode(certDersFromVector('openssl/fake-gp.pem')[0]);
    cert.tbs.extensions = {
      list: [
        {
          oid: 'subjectAltName',
          rest: Uint8Array.from([
            0x04, 0x10, 0x30, 0x0e, 0xa3, 0x02, 0x30, 0x00, 0xa5, 0x05, 0xa1, 0x03, 0x0c, 0x01,
            0x78, 0x85, 0x01, 0x78,
          ]),
        },
      ],
    };
    throws(() => X509.extensions(cert));
    cert.tbs.extensions.list[0].rest = Uint8Array.from([
      0x04, 0x0d, 0x30, 0x0b, 0xa3, 0x02, 0x30, 0x00, 0xa5, 0x05, 0xa1, 0x03, 0x0c, 0x01, 0x78,
    ]);
    deepStrictEqual(X509.extensions(cert), [
      {
        oid: 'subjectAltName',
        critical: false,
        san: {
          list: [
            { TAG: 'x400Address', data: Uint8Array.from([0x30, 0x00]) },
            { TAG: 'ediPartyName', data: Uint8Array.from([0xa1, 0x03, 0x0c, 0x01, 0x78]) },
          ],
        },
      },
    ]);
  });
  should('preserves otherName ANY values as raw DER', () => {
    const cert = X509.decode(certDersFromVector('openssl/fake-gp.pem')[0]);
    // RFC 5280 section 4.2.1.6 defines OtherName.value as [0] EXPLICIT
    // ANY DEFINED BY type-id; unknown OIDs must keep the DER value bytes.
    const value = Uint8Array.from([0x30, 0x03, 0x9f, 0x1f, 0x00]);
    cert.tbs.extensions = {
      list: [
        {
          oid: 'subjectAltName',
          rest: Uint8Array.from([
            0x04,
            0x0f,
            0x30,
            0x0d,
            0xa0,
            0x0b,
            0x06,
            0x02,
            0x2a,
            0x03,
            0xa0,
            0x05,
            ...value,
          ]),
        },
      ],
    };
    deepStrictEqual(X509.extensions(cert), [
      {
        oid: 'subjectAltName',
        critical: false,
        san: { list: [{ TAG: 'otherName', data: { type: '1.2.3', value } }] },
      },
    ]);
  });
  should('enforces RFC 5280 GeneralNames SIZE constraint on bare reuse sites', () => {
    const base = X509.decode(certDersFromVector('openssl/fake-gp.pem')[0]);
    const certificateIssuer = (rest: Uint8Array) => {
      const cert = structuredClone(base);
      cert.tbs.extensions = { list: [{ oid: 'certificateIssuer', rest }] };
      return X509.extensions(cert)[0];
    };
    deepStrictEqual(
      certificateIssuer(
        Uint8Array.from([0x04, 0x08, 0x30, 0x06, 0x87, 0x04, 0xc0, 0x00, 0x02, 0x01])
      ),
      {
        oid: 'certificateIssuer',
        critical: false,
        certificateIssuer: {
          list: [{ TAG: 'iPAddress', data: '192.0.2.1' }],
        },
      }
    );
    throws(
      () => certificateIssuer(Uint8Array.from([0x04, 0x02, 0x30, 0x00])),
      /GeneralNames must contain at least one GeneralName/
    );
  });
  should('labels X.520 objectIdentifier SubjectDirectoryAttributes attributes', () => {
    const cert = X509.decode(certDersFromVector('openssl/fake-gp.pem')[0]);
    cert.tbs.extensions = {
      list: [
        {
          oid: 'subjectDirectoryAttributes',
          rest: Uint8Array.from([
            0x04, 0x10, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x6a, 0x31, 0x05, 0x06,
            0x03, 0x55, 0x04, 0x03,
          ]),
        },
      ],
    };
    deepStrictEqual(X509.extensions(cert), [
      {
        oid: 'subjectDirectoryAttributes',
        critical: false,
        subjectDirectoryAttributes: {
          list: [
            {
              type: 'objectIdentifier',
              values: [{ TAG: 'oid', data: 'commonName' }],
            },
          ],
        },
      },
    ]);
  });
  should('strict mode rejects BER vectors unless opted in', () => {
    const der = read(EDNS_OLD);
    throws(() => CMS.decode(der));
    const ci = CMS.decode(der, { allowBER: true });
    deepStrictEqual(ci.contentType, 'signedData');
  });
  should('CMS ContentInfo exposes standard RFC 5652 contentType aliases', () => {
    const content = Uint8Array.from([0x30, 0x00]);
    const items = [
      'data',
      'signedData',
      'envelopedData',
      'digestedData',
      'encryptedData',
      'authenticatedData',
    ];
    deepStrictEqual(
      items.map((name) => ({
        byName: CMS.decode(CMS.encode({ contentType: name, content })).contentType,
        byOID: CMS.decode(CMS.encode({ contentType: rawOid(name), content })).contentType,
      })),
      items.map((name) => ({ byName: name, byOID: name }))
    );
  });
  should('rejects multi-valued sMIMECapabilities attrValues (RFC 8551 section 2.5.2)', () => {
    const tpl = getEdnsJiyaTpl();
    const { cert, key, root } = getCertKeyRoot();
    const der = CMS.sign(tpl, cert, key, root, {
      createdTs: CERT_CREATED,
      smimeCapabilities: ['aes256-cbc'],
    });
    const ci = CMS.decode(der);
    const sd = __TEST.CMSSignedData.decode(ci.content);
    const si = sd.signerInfos[0];
    const attr = (si.signedAttrs || []).find((a) => a.oid === 'attrSMIMECapabilities');
    if (!attr || !attr.values[0]) throw new Error('missing sMIMECapabilities attr');
    deepStrictEqual(
      { signerInfos: sd.signerInfos.length, smimeValues: attr.values.length },
      {
        signerInfos: 1,
        smimeValues: 1,
      }
    );
    attr.values = [attr.values[0], attr.values[0]];
    ci.content = __TEST.CMSSignedData.encode(sd);
    ci.ber = undefined;
    throws(() => CMS.signed(CMS.encode(ci)), /sMIMECapabilities attribute.*exactly one value/i);
  });
  should('rejects malformed SignerInfo shapes in CMS.signed (RFC 5652 section 5.3)', () => {
    const tpl = getEdnsJiyaTpl();
    const { cert, key, root } = getCertKeyRoot();
    const der = CMS.sign(tpl, cert, key, root, { createdTs: CERT_CREATED });
    const mutate = (
      fn: (si: ReturnType<typeof __TEST.CMSSignedData.decode>['signerInfos'][0]) => void
    ) => {
      const ci = CMS.decode(der);
      const sd = __TEST.CMSSignedData.decode(ci.content);
      const si = sd.signerInfos[0];
      if (!si) throw new Error('missing signerInfo');
      fn(si);
      ci.content = __TEST.CMSSignedData.encode(sd);
      ci.ber = undefined;
      return CMS.encode(ci);
    };
    const si = CMS.signed(der).signerInfos[0];
    deepStrictEqual(
      {
        version: si.version.toString(),
        sid: si.sid.TAG,
        signedAttrs: si.signedAttrs?.length,
        unsignedAttrs: si.unsignedAttrs,
      },
      { version: '1', sid: 'issuerSerial', signedAttrs: 3, unsignedAttrs: undefined }
    );
    throws(
      () => CMS.signed(mutate((s) => (s.signedAttrs = []))),
      /SignedAttributes present but empty/
    );
    throws(
      () => CMS.signed(mutate((s) => (s.unsignedAttrs = []))),
      /UnsignedAttributes present but empty/
    );
    throws(
      () =>
        CMS.signed(
          mutate((s) => {
            s.sid = { TAG: 'subjectKeyIdentifier', data: Uint8Array.from([1]) };
            s.version = 1n;
          })
        ),
      /SignerInfo\.version must be 3 for subjectKeyIdentifier SID/
    );
  });
  should('rejects SignedData with version that violates RFC 5652 section 5.1', () => {
    const tpl = getEdnsJiyaTpl();
    const { cert, key, root } = getCertKeyRoot();
    const valid = CMS.sign(tpl, cert, key, root);
    const ci = CMS.decode(valid);
    const bad = new Uint8Array(ci.content);
    let patched = false;
    for (let i = 0; i + 2 < bad.length; i++) {
      if (bad[i] === 0x02 && bad[i + 1] === 0x01 && bad[i + 2] === 0x01) {
        bad[i + 2] = 0x03;
        patched = true;
        break;
      }
    }
    if (!patched) throw new Error('SignedData.version INTEGER not found');
    ci.content = bad;
    throws(() => CMS.signed(CMS.encode(ci)), /SignedData\.version must be 1/);
  });
  should('rejects SignedData CMSVersion outside v0..v5 (RFC 5652 section 10.2.5)', () => {
    const tpl = getEdnsJiyaTpl();
    const { cert, key, root } = getCertKeyRoot();
    const valid = CMS.sign(tpl, cert, key, root);
    const ci = CMS.decode(valid);
    const bad = new Uint8Array(ci.content);
    let patched = false;
    for (let i = 0; i + 2 < bad.length; i++) {
      if (bad[i] === 0x02 && bad[i + 1] === 0x01 && bad[i + 2] === 0x01) {
        bad[i + 2] = 0x06;
        patched = true;
        break;
      }
    }
    if (!patched) throw new Error('SignedData.version INTEGER not found');
    ci.content = bad;
    throws(() => CMS.signed(CMS.encode(ci)), /SignedData\.version CMSVersion must be in v0\.\.v5/);
  });
  should('enforces RFC 5652 section 5.1 digestAlgorithms coverage for signerInfos', () => {
    const { root } = getCertKeyRoot();
    const ci = decodeP384Cert();
    const sd = __TEST.CMSSignedData.decode(ci.content);
    if (!sd.digestAlgorithms[0] || !sd.signerInfos[0])
      throw new Error('digestAlgorithms/signerInfo missing');
    const signerDigest = sd.signerInfos[0].digestAlg.algorithm;
    sd.digestAlgorithms[0].algorithm =
      signerDigest === '2.16.840.1.101.3.4.2.1'
        ? '2.16.840.1.101.3.4.2.2'
        : '2.16.840.1.101.3.4.2.1';
    ci.content = __TEST.CMSSignedData.encode(sd);
    ci.ber = undefined;
    throws(
      () =>
        CMS.verify(CMS.encode(ci), { time: CERT_CREATED, chain: [root], checkSignatures: true }),
      /SignedData\.digestAlgorithms must include each SignerInfo\.digestAlgorithm/
    );
  });
  should(
    'CMS.verify accepts signer certificate from opts.chain when CertificateSet is omitted',
    () => {
      const tpl = getEdnsJiyaTpl();
      const { cert, key, root } = getCertKeyRoot();
      const signed = CMS.sign(tpl, cert, key, root, {
        createdTs: CERT_CREATED,
        extraEntropy: false,
      });
      const ci = CMS.decode(signed);
      const sd = __TEST.CMSSignedData.decode(ci.content);
      sd.certificates = undefined;
      ci.content = __TEST.CMSSignedData.encode(sd);
      ci.ber = undefined;
      const external = CMS.encode(ci);
      const valid = CMS.verify(external, {
        time: CERT_CREATED,
        chain: [cert, root],
        checkSignatures: true,
      });
      deepStrictEqual(
        { signedAttrs: valid.signedAttrs, chainLen: valid.chain.length },
        { signedAttrs: true, chainLen: 2 }
      );
    }
  );
  should('fails closed on multi-signer SignedData in this API profile', () => {
    const { root } = getCertKeyRoot();
    const ci = decodeP384Cert();
    const sd = __TEST.CMSSignedData.decode(ci.content);
    const signerInfo = sd.signerInfos[0];
    if (!signerInfo) throw new Error('SignerInfo[0] missing');
    sd.signerInfos.push({ ...signerInfo });
    ci.content = __TEST.CMSSignedData.encode(sd);
    ci.ber = undefined;
    throws(
      () =>
        CMS.verify(CMS.encode(ci), { time: CERT_CREATED, chain: [root], checkSignatures: true }),
      /this API supports exactly one SignerInfo, got 2/
    );
  });
  should('enforces RFC 5652 section 5.3 signedAttrs presence for non-id-data eContentType', () => {
    const { root } = getCertKeyRoot();

    const ci = decodeP384Cert();
    const sd = __TEST.CMSSignedData.decode(ci.content);
    if (!sd.signerInfos[0]) throw new Error('SignerInfo[0] missing');
    sd.encapContentInfo.eContentType = '1.2.3.4';
    sd.version = 3n;
    sd.signerInfos[0].signedAttrs = undefined;
    ci.content = __TEST.CMSSignedData.encode(sd);
    ci.ber = undefined;
    throws(
      () =>
        CMS.verify(CMS.encode(ci), { time: CERT_CREATED, chain: [root], checkSignatures: true }),
      /SignerInfo\.signedAttrs must be present when eContentType is not id-data/
    );
  });
  should(
    'supports RFC 5652 section 5.3 subjectKeyIdentifier SID and enforces SID/version coupling',
    () => {
      const { root } = getCertKeyRoot();
      const ci = decodeP384Cert();
      const sd = __TEST.CMSSignedData.decode(ci.content);
      const si = sd.signerInfos[0];
      if (!si) throw new Error('SignerInfo[0] missing');
      if (si.sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
      const sidIssuer = CERTUtils.Name.encode(si.sid.data.issuer);
      const signerCert = (sd.certificates || []).find(
        (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
          i.TAG === 'certificate' &&
          i.data.tbs.serial === si.sid.data.serial &&
          equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
      );
      if (!signerCert) throw new Error('signer cert not found');
      const signerSki = X509.extensions(signerCert.data).find((e) => e.ski)?.ski;
      if (!signerSki) throw new Error('signer subjectKeyIdentifier not found');
      si.sid = { TAG: 'subjectKeyIdentifier', data: signerSki };
      si.version = 3n;
      sd.version = 3n;
      ci.content = __TEST.CMSSignedData.encode(sd);
      ci.ber = undefined;
      const signed = CMS.encode(ci);
      CMS.verify(signed, { time: CERT_CREATED, chain: [root], checkSignatures: true });
      si.version = 1n;
      sd.version = 1n;
      ci.content = __TEST.CMSSignedData.encode(sd);
      ci.ber = undefined;
      throws(
        () =>
          CMS.verify(CMS.encode(ci), { time: CERT_CREATED, chain: [root], checkSignatures: true }),
        /SignerInfo\.version must be 3 for subjectKeyIdentifier SID/
      );
    }
  );
  should('fails closed when issuerSerial SID matches multiple certificates', () => {
    const { root } = getCertKeyRoot();
    const ci = decodeP384Cert();
    const sd = __TEST.CMSSignedData.decode(ci.content);
    const sid = sd.signerInfos[0]?.sid;
    if (!sid || sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
    const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
    const signerCert = (sd.certificates || []).find(
      (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
        i.TAG === 'certificate' &&
        i.data.tbs.serial === sid.data.serial &&
        equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
    );
    if (!signerCert || !sd.certificates) throw new Error('certificate set missing');
    sd.certificates.push({ TAG: 'certificate', data: signerCert.data });
    ci.content = __TEST.CMSSignedData.encode(sd);
    ci.ber = undefined;
    throws(
      () =>
        CMS.verify(CMS.encode(ci), { time: CERT_CREATED, chain: [root], checkSignatures: true }),
      /SignerInfo\.sid issuerSerial matched multiple certificates/
    );
  });
  should('fails closed when issuerSerial SID matches CertificateSet and opts.chain', () => {
    const { root } = getCertKeyRoot();
    const ci = decodeP384Cert();
    const sd = __TEST.CMSSignedData.decode(ci.content);
    const sid = sd.signerInfos[0]?.sid;
    if (!sid || sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
    const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
    const signerCert = (sd.certificates || []).find(
      (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
        i.TAG === 'certificate' &&
        i.data.tbs.serial === sid.data.serial &&
        equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
    );
    if (!signerCert) throw new Error('certificate set missing');
    const duplicate = CERTUtils.Certificate.decode(CERTUtils.Certificate.encode(signerCert.data));
    duplicate.tbs.validity.notAfter = { TAG: 'utc', data: '270101000000Z' };
    throws(
      () =>
        CMS.verify(CMS.encode(ci), {
          time: CERT_CREATED,
          chain: [duplicate, root],
          checkSignatures: false,
        }),
      /SignerInfo\.sid issuerSerial matched multiple certificates/
    );
  });
  should('fails closed when subjectKeyIdentifier SID matches CertificateSet and opts.chain', () => {
    const { root } = getCertKeyRoot();
    const ci = decodeP384Cert();
    const sd = __TEST.CMSSignedData.decode(ci.content);
    const si = sd.signerInfos[0];
    if (!si || si.sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
    const sidIssuer = CERTUtils.Name.encode(si.sid.data.issuer);
    const signerCert = (sd.certificates || []).find(
      (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
        i.TAG === 'certificate' &&
        i.data.tbs.serial === si.sid.data.serial &&
        equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
    );
    if (!signerCert) throw new Error('certificate set missing');
    const signerSki = X509.extensions(signerCert.data).find((e) => e.ski)?.ski;
    if (!signerSki) throw new Error('signer subjectKeyIdentifier not found');
    si.sid = { TAG: 'subjectKeyIdentifier', data: signerSki };
    si.version = 3n;
    sd.version = 3n;
    ci.content = __TEST.CMSSignedData.encode(sd);
    ci.ber = undefined;
    const duplicate = CERTUtils.Certificate.decode(CERTUtils.Certificate.encode(signerCert.data));
    duplicate.tbs.validity.notAfter = { TAG: 'utc', data: '270101000000Z' };
    throws(
      () =>
        CMS.verify(CMS.encode(ci), {
          time: CERT_CREATED,
          chain: [duplicate, root],
          checkSignatures: false,
        }),
      /SignerInfo\.sid subjectKeyIdentifier matched multiple certificates/
    );
  });
  should('rejects ContentInfo whose contentType is not id-signedData for CMS.signed', () => {
    const tpl = getEdnsJiyaTpl();
    const { cert, key, root } = getCertKeyRoot();
    const valid = CMS.sign(tpl, cert, key, root);
    const ci = CMS.decode(valid);
    ci.contentType = 'data';
    throws(() => CMS.signed(CMS.encode(ci)), /expected SignedData contentType/);
  });
  should(
    'rejects EnvelopedData contentType in signed-data-only API (RFC 5652 sections 10.2.6/10.2.7 context)',
    () => {
      const tpl = getEdnsJiyaTpl();
      const { cert, key, root } = getCertKeyRoot();
      const valid = CMS.sign(tpl, cert, key, root);
      const ci = CMS.decode(valid);
      ci.contentType = 'envelopedData';
      throws(() => CMS.signed(CMS.encode(ci)), /expected SignedData contentType/);
    }
  );
  should('CMS.sign uses id-data for encapsulated content and contentType signed attribute', () => {
    const tpl = getEdnsJiyaTpl();
    const { cert, key, root } = getCertKeyRoot();
    const out = CMS.signed(CMS.sign(tpl, cert, key, root));
    deepStrictEqual(out.encapContentInfo.eContentType, 'data');
    const ct = (out.signerInfos[0].signedAttrs || []).find((a) => a.oid === 'attrContentType');
    deepStrictEqual(ct?.values.length, 1);
    deepStrictEqual(
      ct?.values[0],
      Uint8Array.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01])
    );
  });
  should(
    'CMS.sign emits digest/signature algorithm identifiers consistent with key (RFC 5652 section 5.5)',
    () => {
      const tpl = getEdnsJiyaTpl();
      const p256 = CMS.signed(
        CMS.sign(
          tpl,
          pem('openssl/p256-server-cert.pem'),
          pem('openssl/p256-server-key.pem'),
          pem('openssl/p384-root.pem')
        )
      );
      deepStrictEqual(p256.signerInfos[0].digestAlg.algorithm, 'sha256');
      deepStrictEqual(p256.signerInfos[0].signatureAlg.algorithm, 'ecdsa-with-SHA256');
      deepStrictEqual(p256.digestAlgorithms[0].algorithm, 'sha256');
      const p384 = CMS.signed(
        CMS.sign(
          tpl,
          pem('openssl/p384-server-cert.pem'),
          pem('openssl/p384-server-key.pem'),
          pem('openssl/p384-root.pem')
        )
      );
      deepStrictEqual(p384.signerInfos[0].digestAlg.algorithm, 'sha384');
      deepStrictEqual(p384.signerInfos[0].signatureAlg.algorithm, 'ecdsa-with-SHA384');
      deepStrictEqual(p384.digestAlgorithms[0].algorithm, 'sha384');
    }
  );
  should('rejects Ed25519 SHA-512 digestAlgorithm NULL params (RFC 8419 section 3.1)', () => {
    const data = new TextEncoder().encode('abc');
    const cert = pem('openssl/client-ed25519-cert.pem');
    const key = pem('openssl/client-ed25519-key.pem');
    const signed = CMS.sign(data, cert, key);
    const mutate = (fn: (sd: ReturnType<typeof __TEST.CMSSignedData.decode>) => void) => {
      const ci = CMS.decode(signed);
      const sd = __TEST.CMSSignedData.decode(ci.content);
      fn(sd);
      ci.content = __TEST.CMSSignedData.encode(sd);
      ci.ber = undefined;
      return CMS.encode(ci);
    };
    throws(
      () =>
        CMS.verify(
          mutate((sd) => {
            sd.digestAlgorithms[0].params = { tag: 0x05, valueHex: '' };
          }),
          { checkSignatures: false }
        ),
      /digestAlgorithm params.*RFC 8419/i
    );
    throws(
      () =>
        CMS.verify(
          mutate((sd) => {
            sd.signerInfos[0].digestAlg.params = { tag: 0x05, valueHex: '' };
          }),
          { checkSignatures: false }
        ),
      /digestAlgorithm params.*RFC 8419/i
    );
    const sig = CMS.compact.sign(data, cert, key);
    throws(
      () => CMS.sign(data, cert, key, '', { digestAlgorithm: 'sha256' }),
      /Ed25519.*digestAlgorithm.*RFC 8419/i
    );
    throws(
      () => CMS.signDetached(data, cert, key, '', { digestAlgorithm: 'sha256' }),
      /Ed25519.*digestAlgorithm.*RFC 8419/i
    );
    throws(
      () => CMS.compact.sign(data, cert, key, { digestAlgorithm: 'sha256' }),
      /Ed25519.*digestAlgorithm.*RFC 8419/i
    );
    throws(
      () => CMS.compact.build(data, sig, cert, '', { digestAlgorithm: 'sha256' }),
      /Ed25519.*digestAlgorithm.*RFC 8419/i
    );
  });
  should('CMS.sign Ed448 signedAttrs follow RFC 8419 section 3.1 SHAKE256-512 profile', () => {
    const data = new TextEncoder().encode('abc');
    const cert = pem('openssl/client-ed448-cert.pem');
    const key = pem('openssl/client-ed448-key.pem');
    const out = CMS.signed(CMS.sign(data, cert, key));
    const signer = out.signerInfos[0];
    if (!signer) throw new Error('SignerInfo[0] missing');
    const md = (signer.signedAttrs || []).find((a) => a.oid === 'attrMessageDigest');
    const value = md?.values[0];
    deepStrictEqual(
      {
        digestAlgorithms: out.digestAlgorithms,
        digestAlg: signer.digestAlg,
        signatureAlg: signer.signatureAlg,
        messageDigest: value,
      },
      {
        digestAlgorithms: [
          {
            algorithm: 'shake256_512',
            params: { tag: 0x02, valueHex: '0200' },
          },
        ],
        digestAlg: {
          algorithm: 'shake256_512',
          params: { tag: 0x02, valueHex: '0200' },
        },
        signatureAlg: { algorithm: 'Ed448', params: undefined },
        messageDigest: Uint8Array.of(0x04, 0x40, ...shake256(data, { dkLen: 64 })),
      }
    );
    const sig = CMS.compact.sign(data, cert, key);
    throws(
      () => CMS.sign(data, cert, key, '', { digestAlgorithm: 'sha512' }),
      /Ed448.*digestAlgorithm.*RFC 8419/i
    );
    throws(
      () => CMS.signDetached(data, cert, key, '', { digestAlgorithm: 'sha512' }),
      /Ed448.*digestAlgorithm.*RFC 8419/i
    );
    throws(
      () => CMS.sign(data, cert, key, '', { digestAlgorithmParams: 'null' }),
      /Ed448.*digestAlgorithm params.*RFC 8419/i
    );
    throws(
      () => CMS.compact.sign(data, cert, key, { digestAlgorithm: 'sha512' }),
      /Ed448.*digestAlgorithm.*RFC 8419/i
    );
    throws(
      () => CMS.compact.build(data, sig, cert, '', { digestAlgorithm: 'sha512' }),
      /Ed448.*digestAlgorithm.*RFC 8419/i
    );
    throws(
      () => CMS.compact.build(data, sig, cert, '', { digestAlgorithmParams: 'null' }),
      /Ed448.*digestAlgorithm params.*RFC 8419/i
    );
    const withoutAttrs = (() => {
      const ci = CMS.decode(CMS.sign(data, cert, key));
      const sd = __TEST.CMSSignedData.decode(ci.content);
      const signerInfo = sd.signerInfos[0];
      const pkcs8 = DERUtils.PKCS8.decode(pemBlocks(key)[0].der);
      if (pkcs8.privateKey.TAG !== 'raw') throw new Error('expected raw Ed448 private key');
      const digestAlg = { algorithm: 'shake256', params: undefined };
      sd.digestAlgorithms = [digestAlg];
      signerInfo.digestAlg = digestAlg;
      signerInfo.signedAttrs = undefined;
      signerInfo.signature = ed448.sign(data, pkcs8.privateKey.data);
      ci.content = __TEST.CMSSignedData.encode(sd);
      ci.ber = undefined;
      return CMS.encode(ci);
    })();
    deepStrictEqual(CMS.verify(withoutAttrs).signedAttrs, false);
  });
  should(
    'CMS.sign encodes digest/signature AlgorithmIdentifier params as absent (RFC 5652 sections 10.1.1/10.1.2)',
    () => {
      const tpl = getEdnsJiyaTpl();
      const out = CMS.signed(
        CMS.sign(
          tpl,
          pem('openssl/p384-server-cert.pem'),
          pem('openssl/p384-server-key.pem'),
          pem('openssl/p384-root.pem')
        )
      );
      deepStrictEqual(out.digestAlgorithms[0].params, undefined);
      deepStrictEqual(out.signerInfos[0].digestAlg.params, undefined);
      deepStrictEqual(out.signerInfos[0].signatureAlg.params, undefined);
    }
  );
  should(
    'RevocationInfoChoice codec roundtrips both crl and other alternatives (RFC 5652 section 10.2.1)',
    () => {
      const other = {
        TAG: 'other' as const,
        data: { format: '1.3.6.1.5.5.7.48.1.1', info: Uint8Array.from([0x05, 0x00]) },
      };
      deepStrictEqual(
        __TEST.CMSRevocationInfoChoice.decode(__TEST.CMSRevocationInfoChoice.encode(other)),
        other
      );
      const crl = {
        TAG: 'crl' as const,
        data: {
          tbsCertList: Uint8Array.from([0x30, 0x00]),
          signatureAlgorithm: { algorithm: 'sha256', params: undefined },
          signatureValue: Uint8Array.from([0xaa, 0xbb]),
        },
      };
      deepStrictEqual(
        __TEST.CMSRevocationInfoChoice.decode(__TEST.CMSRevocationInfoChoice.encode(crl)),
        crl
      );
    }
  );
  should(
    'CertificateChoices codec roundtrips certificate/obsolete/other alternatives (RFC 5652 section 10.2.2)',
    () => {
      const tpl = getEdnsJiyaTpl();
      const signed = CMS.signed(
        CMS.sign(
          tpl,
          pem('openssl/p384-server-cert.pem'),
          pem('openssl/p384-server-key.pem'),
          pem('openssl/p384-root.pem')
        )
      );
      const certChoice = signed.certificates?.find((i) => i.TAG === 'certificate');
      if (!certChoice) throw new Error('missing certificate choice');
      deepStrictEqual(
        __TEST.CMSCertificateChoices.decode(__TEST.CMSCertificateChoices.encode(certChoice)),
        certChoice
      );
      const ext = { TAG: 'extendedCertificate' as const, data: Uint8Array.from([0x30, 0x00]) };
      const v1 = { TAG: 'v1AttrCert' as const, data: Uint8Array.from([0x30, 0x01, 0x00]) };
      const v2 = { TAG: 'v2AttrCert' as const, data: Uint8Array.from([0x30, 0x02, 0x05, 0x00]) };
      const other = {
        TAG: 'other' as const,
        data: Uint8Array.from([0x30, 0x03, 0x02, 0x01, 0x01]),
      };
      deepStrictEqual(
        __TEST.CMSCertificateChoices.decode(__TEST.CMSCertificateChoices.encode(ext)),
        ext
      );
      deepStrictEqual(
        __TEST.CMSCertificateChoices.decode(__TEST.CMSCertificateChoices.encode(v1)),
        v1
      );
      deepStrictEqual(
        __TEST.CMSCertificateChoices.decode(__TEST.CMSCertificateChoices.encode(v2)),
        v2
      );
      deepStrictEqual(
        __TEST.CMSCertificateChoices.decode(__TEST.CMSCertificateChoices.encode(other)),
        other
      );
    }
  );
  should(
    'v1AttrCert-only CertificateSet is unsupported for signer-cert resolution (RFC 5652 section 12.2)',
    () => {
      const { root } = getCertKeyRoot();
      const c = decodeP384Cert();
      const sd = __TEST.CMSSignedData.decode(c.content);
      sd.certificates = [{ TAG: 'v1AttrCert', data: Uint8Array.from([0x30, 0x00]) }];
      sd.version = 3n;
      c.content = __TEST.CMSSignedData.encode(sd);
      c.ber = undefined;
      throws(
        () =>
          CMS.verify(CMS.encode(c), { time: CERT_CREATED, chain: [root], checkSignatures: true }),
        /SignerInfo cert not found/
      );
    }
  );
  should(
    'CertificateSet in generated CMS is DER-sorted as SET OF CertificateChoices (RFC 5652 section 10.2.3)',
    () => {
      const tpl = getEdnsJiyaTpl();
      const out = CMS.signed(
        CMS.sign(
          tpl,
          pem('openssl/p384-server-cert.pem'),
          pem('openssl/p384-server-key.pem'),
          pem('openssl/p384-root.pem')
        )
      );
      const certs = out.certificates || [];
      for (let i = 1; i < certs.length; i++) {
        const a = __TEST.CMSCertificateChoices.encode(certs[i - 1]);
        const b = __TEST.CMSCertificateChoices.encode(certs[i]);
        const n = Math.min(a.length, b.length);
        let cmp = 0;
        for (let j = 0; j < n; j++) {
          cmp = a[j] - b[j];
          if (cmp) break;
        }
        if (!cmp) cmp = a.length - b.length;
        deepStrictEqual(cmp <= 0, true);
      }
    }
  );
  should(
    'CertificateSet in generated CMS dedupes repeated CertificateChoices (RFC 5652 section 10.2.3)',
    () => {
      const tpl = getEdnsJiyaTpl();
      const { cert, key, root } = getCertKeyRoot();
      const choices = (chainPem: string) =>
        (CMS.signed(CMS.sign(tpl, cert, key, chainPem)).certificates || []).map((c) =>
          __TEST.CMSCertificateChoices.encode(c)
        );
      deepStrictEqual(choices(`${cert}${root}${root}`), choices(root));
    }
  );
  should(
    'SignerInfo issuerSerial identifies signer cert by issuer name + serial (RFC 5652 section 10.2.4)',
    () => {
      const tpl = getEdnsJiyaTpl();
      const out = CMS.signed(
        CMS.sign(
          tpl,
          pem('openssl/p384-server-cert.pem'),
          pem('openssl/p384-server-key.pem'),
          pem('openssl/p384-root.pem')
        )
      );
      const si = out.signerInfos[0];
      deepStrictEqual(si.sid.TAG, 'issuerSerial');
      const sid = si.sid.data;
      const sidIssuer = CERTUtils.Name.encode(sid.issuer);
      const cert = (out.certificates || []).find(
        (i) =>
          i.TAG === 'certificate' &&
          i.data.tbs.serial === sid.serial &&
          equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
      );
      if (!cert || cert.TAG !== 'certificate')
        throw new Error('signer certificate for issuerSerial not found');
    }
  );
  should(
    'enforces signedAttrs cardinality/placement for content-type, messageDigest, signingTime (RFC 5652 sections 11.1/11.2/11.3)',
    () => {
      const { root } = getCertKeyRoot();
      const make = (
        mutate: (sd: ReturnType<typeof __TEST.CMSSignedData.decode>) => void
      ): Uint8Array => {
        const c = decodeP384Cert();
        const sd = __TEST.CMSSignedData.decode(c.content);
        mutate(sd);
        c.content = __TEST.CMSSignedData.encode(sd);
        c.ber = undefined;
        return CMS.encode(c);
      };
      const dupCt = make((sd) => {
        const si = sd.signerInfos[0];
        const ct = (si.signedAttrs || []).find((a) => a.oid === 'attrContentType');
        if (!ct) throw new Error('missing content-type attr');
        (si.signedAttrs || []).push(ct);
      });
      throws(
        () => CMS.verify(dupCt, { time: CERT_CREATED, chain: [root], checkSignatures: true }),
        /signedAttrs MUST include exactly one content-type attribute/
      );
      const unsignedMd = make((sd) => {
        const si = sd.signerInfos[0];
        const md = (si.signedAttrs || []).find((a) => a.oid === 'attrMessageDigest');
        if (!md) throw new Error('missing messageDigest attr');
        si.unsignedAttrs = [md];
      });
      throws(
        () => CMS.verify(unsignedMd, { time: CERT_CREATED, chain: [root], checkSignatures: true }),
        /messageDigest attribute MUST NOT be unsigned/
      );
      const dupSt = make((sd) => {
        const si = sd.signerInfos[0];
        const st = (si.signedAttrs || []).find((a) => a.oid === 'attrSigningTime');
        if (!st) throw new Error('missing signingTime attr');
        (si.signedAttrs || []).push(st);
      });
      throws(
        () => CMS.verify(dupSt, { time: CERT_CREATED, chain: [root], checkSignatures: true }),
        /signedAttrs MUST NOT include multiple signingTime attributes/
      );
    }
  );
  should('enforces sMIMECapabilities as a signed attribute (RFC 2634 profile)', () => {
    const tpl = getEdnsJiyaTpl();
    const { cert, key, root } = getCertKeyRoot();
    const der = CMS.sign(tpl, cert, key, root, {
      createdTs: CERT_CREATED,
      smimeCapabilities: ['aes256-cbc'],
    });
    const valid = CMS.verify(der, {
      time: CERT_CREATED,
      chain: [root],
      checkSignatures: false,
    });
    deepStrictEqual(valid.signedAttrs, true);
    const ci = CMS.decode(der);
    const sd = __TEST.CMSSignedData.decode(ci.content);
    const si = sd.signerInfos[0];
    const attrs = si.signedAttrs || [];
    const idx = attrs.findIndex((a) => a.oid === 'attrSMIMECapabilities');
    if (idx === -1) throw new Error('missing sMIMECapabilities attr');
    const [attr] = attrs.splice(idx, 1);
    if (!attr) throw new Error('missing sMIMECapabilities attr');
    si.unsignedAttrs = [attr];
    ci.content = __TEST.CMSSignedData.encode(sd);
    ci.ber = undefined;
    throws(
      () =>
        CMS.verify(CMS.encode(ci), {
          time: CERT_CREATED,
          chain: [root],
          checkSignatures: false,
        }),
      /sMIMECapabilities attribute MUST NOT be unsigned/
    );
  });
  should('rejects countersignature attrs in this API (RFC 5652 section 11.4)', () => {
    const { root } = getCertKeyRoot();
    const make = (
      mutate: (sd: ReturnType<typeof __TEST.CMSSignedData.decode>) => void
    ): Uint8Array => {
      const c = decodeP384Cert();
      const sd = __TEST.CMSSignedData.decode(c.content);
      mutate(sd);
      c.content = __TEST.CMSSignedData.encode(sd);
      c.ber = undefined;
      return CMS.encode(c);
    };
    const badSigned = make((sd) => {
      const si = sd.signerInfos[0];
      (si.signedAttrs || []).push({
        oid: '1.2.840.113549.1.9.6',
        values: [Uint8Array.from([0x31, 0x00])],
      });
    });
    throws(
      () => CMS.verify(badSigned, { time: CERT_CREATED, chain: [root], checkSignatures: true }),
      /countersignature MUST NOT be a signed attribute/
    );
    const badUnsigned = make((sd) => {
      const si = sd.signerInfos[0];
      si.unsignedAttrs = [{ oid: '1.2.840.113549.1.9.6', values: [Uint8Array.from([0x31, 0x00])] }];
    });
    throws(
      () => CMS.verify(badUnsigned, { time: CERT_CREATED, chain: [root], checkSignatures: true }),
      /countersignature is unsupported by this API/
    );
  });
  should(
    'rejects empty SignedAttributes/UnsignedAttributes when present (RFC 5652 section 12.1)',
    () => {
      const { root } = getCertKeyRoot();
      const make = (
        mutate: (sd: ReturnType<typeof __TEST.CMSSignedData.decode>) => void
      ): Uint8Array => {
        const c = decodeP384Cert();
        const sd = __TEST.CMSSignedData.decode(c.content);
        mutate(sd);
        c.content = __TEST.CMSSignedData.encode(sd);
        c.ber = undefined;
        return CMS.encode(c);
      };
      const emptySigned = make((sd) => {
        sd.signerInfos[0].signedAttrs = [];
      });
      throws(
        () => CMS.verify(emptySigned, { time: CERT_CREATED, chain: [root], checkSignatures: true }),
        /SignedAttributes present but empty/
      );
      const emptyUnsigned = make((sd) => {
        sd.signerInfos[0].unsignedAttrs = [];
      });
      throws(
        () =>
          CMS.verify(emptyUnsigned, { time: CERT_CREATED, chain: [root], checkSignatures: true }),
        /UnsignedAttributes present but empty/
      );
    }
  );
  should('enforces RFC 5754 SHA-2/ECDSA AlgorithmIdentifier rules', () => {
    const { root } = getCertKeyRoot();
    const make = (
      mutate: (sd: ReturnType<typeof __TEST.CMSSignedData.decode>) => void
    ): Uint8Array => {
      const c = decodeP384Cert();
      const sd = __TEST.CMSSignedData.decode(c.content);
      mutate(sd);
      c.content = __TEST.CMSSignedData.encode(sd);
      c.ber = undefined;
      return CMS.encode(c);
    };
    const sha2Null = make((sd) => {
      sd.digestAlgorithms[0].params = { tag: 0x05, valueHex: '' };
      sd.signerInfos[0].digestAlg.params = { tag: 0x05, valueHex: '' };
    });
    CMS.verify(sha2Null, { time: CERT_CREATED, chain: [root], checkSignatures: true });
    const sha2DigestSetNullSignerAbsent = make((sd) => {
      sd.digestAlgorithms[0].params = { tag: 0x05, valueHex: '' };
      sd.signerInfos[0].digestAlg.params = undefined;
    });
    CMS.verify(sha2DigestSetNullSignerAbsent, {
      time: CERT_CREATED,
      chain: [root],
      checkSignatures: true,
    });
    const ecdsaNull = make((sd) => {
      sd.signerInfos[0].signatureAlg.params = { tag: 0x05, valueHex: '' };
    });
    throws(
      () => CMS.verify(ecdsaNull, { time: CERT_CREATED, chain: [root], checkSignatures: true }),
      /ECDSA signatureAlgorithm params must be absent/
    );
    const digestMismatch = make((sd) => {
      sd.signerInfos[0].digestAlg.algorithm = '2.16.840.1.101.3.4.2.3';
      sd.digestAlgorithms[0].algorithm = '2.16.840.1.101.3.4.2.3';
    });
    throws(
      () =>
        CMS.verify(digestMismatch, { time: CERT_CREATED, chain: [root], checkSignatures: true }),
      /digestAlgorithm OID mismatch/
    );
  });
  should('enforces RFC 5280 core cert fields (version/serial/issuer) in verify path', () => {
    const { root } = getCertKeyRoot();
    const make = (
      mutate: (
        sd: ReturnType<typeof __TEST.CMSSignedData.decode>,
        signerCert: Extract<
          NonNullable<ReturnType<typeof __TEST.CMSSignedData.decode>['certificates']>[number],
          { TAG: 'certificate' }
        >
      ) => void
    ): Uint8Array => {
      const c = decodeP384Cert();
      const sd = __TEST.CMSSignedData.decode(c.content);
      const sid = sd.signerInfos[0].sid;
      if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
      const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
      const signerCert = (sd.certificates || []).find(
        (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
          i.TAG === 'certificate' &&
          i.data.tbs.serial === sid.data.serial &&
          equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
      );
      if (!signerCert) throw new Error('signer cert not found');
      mutate(sd, signerCert);
      c.content = __TEST.CMSSignedData.encode(sd);
      c.ber = undefined;
      return CMS.encode(c);
    };
    const badVersion = make((sd, signerCert) => {
      signerCert.data.tbs.version = 3n;
    });
    throws(
      () => CMS.verify(badVersion, { time: CERT_CREATED, chain: [root], checkSignatures: true }),
      /signer: certificate version must be 0\.\.2/
    );
    const badSerial = make((sd, signerCert) => {
      signerCert.data.tbs.serial = 0n;
      const sid = sd.signerInfos[0].sid;
      if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
      sid.data.serial = 0n;
    });
    throws(
      () => CMS.verify(badSerial, { time: CERT_CREATED, chain: [root], checkSignatures: true }),
      /signer: certificate serialNumber must be positive/
    );
    const longSerial = make((sd, signerCert) => {
      const n = 1n << 160n;
      signerCert.data.tbs.serial = n;
      const sid = sd.signerInfos[0].sid;
      if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
      sid.data.serial = n;
    });
    throws(
      () => CMS.verify(longSerial, { time: CERT_CREATED, chain: [root], checkSignatures: true }),
      /signer: certificate serialNumber must be <= 20 octets/
    );
    const badIssuer = make((sd, signerCert) => {
      signerCert.data.tbs.issuer = { rdns: [] };
      const sid = sd.signerInfos[0].sid;
      if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
      sid.data.issuer = { rdns: [] };
    });
    throws(
      () => CMS.verify(badIssuer, { time: CERT_CREATED, chain: [root], checkSignatures: true }),
      /signer: certificate issuer distinguished name must be non-empty/
    );
    const dupExt = make((_, signerCert) => {
      const e = signerCert.data.tbs.extensions!.list.find((i) => i.oid === 'subjectKeyIdentifier');
      if (!e) throw new Error('expected subjectKeyIdentifier extension');
      signerCert.data.tbs.extensions!.list.push({ oid: e.oid, rest: e.rest });
    });
    throws(
      () => CMS.verify(dupExt, { time: CERT_CREATED, chain: [root], checkSignatures: true }),
      /signer: certificate contains duplicate extension subjectKeyIdentifier/
    );
    const badValidityOrder = make((_, signerCert) => {
      signerCert.data.tbs.validity.notBefore = { TAG: 'utc', data: '260101000000Z' };
      signerCert.data.tbs.validity.notAfter = { TAG: 'utc', data: '250101000000Z' };
    });
    throws(
      () =>
        CMS.verify(badValidityOrder, { time: CERT_CREATED, chain: [root], checkSignatures: true }),
      /signer: certificate validity notAfter must be >= notBefore/
    );
    const badExtVersion = make((_, signerCert) => {
      signerCert.data.tbs.version = 1n;
    });
    throws(
      () => CMS.verify(badExtVersion, { time: CERT_CREATED, chain: [root], checkSignatures: true }),
      /signer: certificate extensions require version v3/
    );
  });
  should('enforces RFC 5280 subject empty-DN rule (critical SAN required)', () => {
    const { root } = getCertKeyRoot();
    const make = (
      mutate: (
        sd: ReturnType<typeof __TEST.CMSSignedData.decode>,
        signerCert: Extract<
          NonNullable<ReturnType<typeof __TEST.CMSSignedData.decode>['certificates']>[number],
          { TAG: 'certificate' }
        >
      ) => void
    ): Uint8Array => {
      const c = decodeP384Cert();
      const sd = __TEST.CMSSignedData.decode(c.content);
      const sid = sd.signerInfos[0].sid;
      if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
      const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
      const signerCert = (sd.certificates || []).find(
        (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
          i.TAG === 'certificate' &&
          i.data.tbs.serial === sid.data.serial &&
          equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
      );
      if (!signerCert || !signerCert.data.tbs.extensions)
        throw new Error('signer cert/extensions not found');
      mutate(sd, signerCert);
      c.content = __TEST.CMSSignedData.encode(sd);
      c.ber = undefined;
      return CMS.encode(c);
    };
    const badNoSan = make((_, signerCert) => {
      signerCert.data.tbs.subject = { rdns: [] };
      signerCert.data.tbs.extensions!.list = signerCert.data.tbs.extensions!.list.filter(
        (e) => e.oid !== 'subjectAltName'
      );
    });
    throws(
      () => CMS.verify(badNoSan, { time: CERT_CREATED, chain: [root], checkSignatures: true }),
      /signer: empty subject requires critical subjectAltName extension/
    );
    const badNonCriticalSan = make((_, signerCert) => {
      signerCert.data.tbs.subject = { rdns: [] };
      signerCert.data.tbs.extensions!.list = signerCert.data.tbs.extensions!.list.filter(
        (e) => e.oid !== 'subjectAltName'
      );
      const san = Uint8Array.from([0x30, 0x07, 0x82, 0x05, 0x61, 0x2e, 0x63, 0x6f, 0x6d]);
      signerCert.data.tbs.extensions!.list.push({
        oid: 'subjectAltName',
        rest: Uint8Array.from([0x04, san.length, ...san]),
      });
    });
    throws(
      () =>
        CMS.verify(badNonCriticalSan, {
          time: CERT_CREATED,
          chain: [root],
          checkSignatures: true,
        }),
      /signer: empty subject requires critical subjectAltName extension/
    );
  });
  should('enforces RFC 5280 uniqueIdentifier version constraints (section 4.1.2.8)', () => {
    const { root } = getCertKeyRoot();
    const c = decodeP384Cert();
    const sd = __TEST.CMSSignedData.decode(c.content);
    const sid = sd.signerInfos[0].sid;
    if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
    const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
    const signerCert = (sd.certificates || []).find(
      (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
        i.TAG === 'certificate' &&
        i.data.tbs.serial === sid.data.serial &&
        equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
    );
    if (!signerCert) throw new Error('signer cert not found');
    signerCert.data.tbs.version = 1n;
    signerCert.data.tbs.issuerUniqueID = { unused: 3, bytes: Uint8Array.from([0xa0]) };
    const encoded = CERTUtils.Certificate.encode(signerCert.data);
    const decoded = CERTUtils.Certificate.decode(encoded);
    deepStrictEqual(decoded.tbs.issuerUniqueID, {
      unused: 3,
      bytes: Uint8Array.from([0xa0]),
    });
    deepStrictEqual(CERTUtils.Certificate.encode(decoded), encoded);
    signerCert.data.tbs.version = 0n;
    signerCert.data.tbs.issuerUniqueID = { unused: 0, bytes: Uint8Array.from([0xff]) };
    c.content = __TEST.CMSSignedData.encode(sd);
    c.ber = undefined;
    throws(
      () => CMS.verify(CMS.encode(c), { time: CERT_CREATED, chain: [root], checkSignatures: true }),
      /signer: certificate unique identifiers require version v2 or v3/
    );
  });
  should(
    'enforces RFC 5280 certificate signature fields (signatureAlgorithm/signatureValue) in verify path',
    () => {
      const { root } = getCertKeyRoot();
      const make = (
        mutate: (
          sd: ReturnType<typeof __TEST.CMSSignedData.decode>,
          signerCert: Extract<
            NonNullable<ReturnType<typeof __TEST.CMSSignedData.decode>['certificates']>[number],
            { TAG: 'certificate' }
          >
        ) => void
      ): Uint8Array => {
        const c = decodeP384Cert();
        const sd = __TEST.CMSSignedData.decode(c.content);
        const sid = sd.signerInfos[0].sid;
        if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
        const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
        const signerCert = (sd.certificates || []).find(
          (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
            i.TAG === 'certificate' &&
            i.data.tbs.serial === sid.data.serial &&
            equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
        );
        if (!signerCert) throw new Error('signer cert not found');
        mutate(sd, signerCert);
        c.content = __TEST.CMSSignedData.encode(sd);
        c.ber = undefined;
        return CMS.encode(c);
      };
      const badSigAlg = make((_, signerCert) => {
        signerCert.data.sigAlg.algorithm = '1.2.840.10045.4.3.3';
      });
      throws(
        () => CMS.verify(badSigAlg, { time: CERT_CREATED, chain: [root], checkSignatures: true }),
        /signer: certificate signatureAlgorithm must match tbsCertificate\.signature/
      );
      const badSigValue = make((_, signerCert) => {
        signerCert.data.sig = new Uint8Array();
      });
      throws(
        () => CMS.verify(badSigValue, { time: CERT_CREATED, chain: [root], checkSignatures: true }),
        /signer: certificate signatureValue must be non-empty/
      );
    }
  );
  should('enforces RFC 5280 SubjectPublicKeyInfo subjectPublicKey presence in verify path', () => {
    const { root } = getCertKeyRoot();

    const c = decodeP384Cert();
    const sd = __TEST.CMSSignedData.decode(c.content);
    const sid = sd.signerInfos[0].sid;
    if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
    const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
    const signerCert = (sd.certificates || []).find(
      (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
        i.TAG === 'certificate' &&
        i.data.tbs.serial === sid.data.serial &&
        equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
    );
    if (!signerCert) throw new Error('signer cert not found');
    signerCert.data.tbs.spki.publicKey = new Uint8Array();
    c.content = __TEST.CMSSignedData.encode(sd);
    c.ber = undefined;
    throws(
      () => CMS.verify(CMS.encode(c), { time: CERT_CREATED, chain: [root], checkSignatures: true }),
      /signer: certificate SubjectPublicKeyInfo\.publicKey must be non-empty/
    );
  });
  should('enforces RFC 5280 SubjectKeyIdentifier non-empty when present', () => {
    const { root } = getCertKeyRoot();

    const c = decodeP384Cert();
    const sd = __TEST.CMSSignedData.decode(c.content);
    const sid = sd.signerInfos[0].sid;
    if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
    const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
    const signerCert = (sd.certificates || []).find(
      (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
        i.TAG === 'certificate' &&
        i.data.tbs.serial === sid.data.serial &&
        equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
    );
    if (!signerCert || !signerCert.data.tbs.extensions)
      throw new Error('signer cert/extensions not found');
    const ski = signerCert.data.tbs.extensions.list.find((e) => e.oid === 'subjectKeyIdentifier');
    if (!ski) throw new Error('SKI extension not found in signer cert');
    const ASN1 = DERUtils.ASN1;
    // Extension.extnValue wraps DER-encoded KeyIdentifier; the KeyIdentifier
    // itself is an OCTET STRING and this test makes that inner value empty.
    ski.rest = ASN1.OctetString.encode(ASN1.OctetString.encode(new Uint8Array()));
    c.content = __TEST.CMSSignedData.encode(sd);
    c.ber = undefined;
    throws(
      () => CMS.verify(CMS.encode(c), { time: CERT_CREATED, chain: [root], checkSignatures: true }),
      /signer: certificate subjectKeyIdentifier must be non-empty/
    );
  });
  should('enforces RFC 5280 AKI linkage (authorityKeyIdentifier -> issuer SKI)', () => {
    const { root } = getCertKeyRoot();

    const c = decodeP384Cert();
    const sd = __TEST.CMSSignedData.decode(c.content);
    const sid = sd.signerInfos[0].sid;
    if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
    const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
    const signerCert = (sd.certificates || []).find(
      (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
        i.TAG === 'certificate' &&
        i.data.tbs.serial === sid.data.serial &&
        equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
    );
    if (!signerCert || !signerCert.data.tbs.extensions)
      throw new Error('signer cert/extensions not found');
    const aki = signerCert.data.tbs.extensions.list.find((e) => e.oid === 'authorityKeyIdentifier');
    if (!aki) throw new Error('AKI extension not found in signer cert');
    const ASN1 = DERUtils.ASN1;
    const extnValue = ASN1.OctetString.decode(aki.rest);
    if (!extnValue.length) throw new Error('AKI extnValue is empty');
    extnValue[extnValue.length - 1] ^= 0x01;
    aki.rest = ASN1.OctetString.encode(extnValue);
    c.content = __TEST.CMSSignedData.encode(sd);
    c.ber = undefined;
    throws(
      () => CMS.verify(CMS.encode(c), { time: CERT_CREATED, chain: [root], checkSignatures: true }),
      /authorityKeyIdentifier keyIdentifier does not match issuer subjectKeyIdentifier/
    );
  });
  should('enforces RFC 5280 AKI issuer/serial pair constraint', () => {
    const cert = X509.decode(
      hexToBytes(
        '3082012c3081dfa00302010202143ee39c0286eeed43006f2c6d66dce4133789957c300506032b6570300c310a300806035504030c0141301e170d3236303431363233353930325a170d3236303431373233353930325a300c310a300806035504030c0141302a300506032b65700321006a49c999d4c14eb4e10893aa46ed6202c81472ea29bc4bd8ea015e316999abcfa3533051301d0603551d0e04160414943dcd01f649df0cd0e62a2f0c55296c18cc5f7e301f0603551d23041830168014943dcd01f649df0cd0e62a2f0c55296c18cc5f7e300f0603551d130101ff040530030101ff300506032b6570034100476186c95341f535156677af510d2a5b7a01acd7d791baca60cd10fd093ab06cdd963a15a2b746b6ef24a9339ce436ff1334c30b972d6eada756996578da660b'
      )
    );
    const aki = (rest: Uint8Array) => {
      const decoded = structuredClone(cert);
      decoded.tbs.extensions.list.push({ oid: 'authorityKeyIdentifier', rest });
      const all = X509.extensions(decoded).filter((e) => e.oid === 'authorityKeyIdentifier');
      return all[all.length - 1];
    };
    deepStrictEqual(
      aki(
        Uint8Array.from([
          0x04, 0x14, 0x30, 0x12, 0xa1, 0x0d, 0x82, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
          0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x01, 0x01,
        ])
      )?.aki,
      {
        keyIdentifier: undefined,
        authorityCertIssuer: { list: [{ TAG: 'dNSName', data: 'example.com' }] },
        authorityCertSerialNumber: 1n,
      }
    );
    throws(
      () =>
        aki(
          Uint8Array.from([
            0x04, 0x11, 0x30, 0x0f, 0xa1, 0x0d, 0x82, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
            0x65, 0x2e, 0x63, 0x6f, 0x6d,
          ])
        ),
      /authorityKeyIdentifier authorityCertIssuer and authorityCertSerialNumber/
    );
    throws(
      () => aki(Uint8Array.from([0x04, 0x05, 0x30, 0x03, 0x82, 0x01, 0x01])),
      /authorityKeyIdentifier authorityCertIssuer and authorityCertSerialNumber/
    );
    throws(
      () => aki(Uint8Array.from([0x04, 0x07, 0x30, 0x05, 0xa1, 0x00, 0x82, 0x01, 0x01])),
      /authorityKeyIdentifier authorityCertIssuer must contain at least one GeneralName/
    );
  });
  should('enforces RFC 5280 EKU purpose constraints for signer cert', () => {
    const { root } = getCertKeyRoot();

    const c = decodeP384Cert();
    const sd = __TEST.CMSSignedData.decode(c.content);
    const sid = sd.signerInfos[0].sid;
    if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
    const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
    const signerCert = (sd.certificates || []).find(
      (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
        i.TAG === 'certificate' &&
        i.data.tbs.serial === sid.data.serial &&
        equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
    );
    if (!signerCert || !signerCert.data.tbs.extensions)
      throw new Error('signer cert/extensions not found');
    const ASN1 = DERUtils.ASN1;
    // ExtendedKeyUsageSyntax with single id-kp-serverAuth (1.3.6.1.5.5.7.3.1).
    const ekuServerAuth = Uint8Array.from([
      0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01,
    ]);
    // Duplicate extension OIDs are now rejected in verify path; mutate existing EKU instead of appending a second EKU.
    const eku = signerCert.data.tbs.extensions.list.find((e) => e.oid === 'extendedKeyUsage');
    if (!eku) throw new Error('expected extKeyUsage extension');
    eku.rest = ASN1.OctetString.encode(ekuServerAuth);
    c.content = __TEST.CMSSignedData.encode(sd);
    c.ber = undefined;
    throws(
      () =>
        CMS.verify(CMS.encode(c), {
          time: CERT_CREATED,
          chain: [root],
          checkSignatures: true,
          purpose: 'smime',
        }),
      /EKU missing emailProtection/
    );
  });
  should('enforces RFC 5280 certificatePolicies SIZE constraints', () => {
    const { root } = getCertKeyRoot();

    const c = decodeP384Cert();
    const sd = __TEST.CMSSignedData.decode(c.content);
    const sid = sd.signerInfos[0].sid;
    if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
    const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
    const signerCert = (sd.certificates || []).find(
      (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
        i.TAG === 'certificate' &&
        i.data.tbs.serial === sid.data.serial &&
        equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
    );
    if (!signerCert || !signerCert.data.tbs.extensions)
      throw new Error('signer cert/extensions not found');
    // ext.rest = ExtBody inner bytes; extnValue here is DER for empty CertificatePolicies SEQUENCE.
    signerCert.data.tbs.extensions.list.push({
      oid: 'certificatePolicies',
      rest: Uint8Array.from([0x04, 0x02, 0x30, 0x00]),
    });
    c.content = __TEST.CMSSignedData.encode(sd);
    c.ber = undefined;
    throws(
      () =>
        CMS.verify(CMS.encode(c), { time: CERT_CREATED, chain: [root], checkSignatures: false }),
      /certificatePolicies must contain at least one PolicyInformation/
    );
    signerCert.data.tbs.extensions.list.pop();
    const duplicatePolicies = Uint8Array.from([
      0x30, 0x0e, 0x30, 0x05, 0x06, 0x03, 0x2a, 0x03, 0x04, 0x30, 0x05, 0x06, 0x03, 0x2a, 0x03,
      0x04,
    ]);
    signerCert.data.tbs.extensions.list.push({
      oid: 'certificatePolicies',
      rest: Uint8Array.from([0x04, duplicatePolicies.length, ...duplicatePolicies]),
    });
    c.content = __TEST.CMSSignedData.encode(sd);
    c.ber = undefined;
    throws(
      () =>
        CMS.verify(CMS.encode(c), { time: CERT_CREATED, chain: [root], checkSignatures: false }),
      /certificatePolicies policyIdentifier must not appear more than once/
    );
  });
  should('enforces RFC 5280 privateKeyUsagePeriod presence constraint', () => {
    const { root } = getCertKeyRoot();

    const c = decodeP384Cert();
    const sd = __TEST.CMSSignedData.decode(c.content);
    const sid = sd.signerInfos[0].sid;
    if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
    const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
    const signerCert = (sd.certificates || []).find(
      (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
        i.TAG === 'certificate' &&
        i.data.tbs.serial === sid.data.serial &&
        equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
    );
    if (!signerCert || !signerCert.data.tbs.extensions)
      throw new Error('signer cert/extensions not found');
    signerCert.data.tbs.extensions.list.push({
      oid: 'privateKeyUsagePeriod',
      rest: Uint8Array.from([
        0x04, 0x13, 0x30, 0x11, 0x80, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x34, 0x31, 0x37, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
      ]),
    });
    deepStrictEqual(
      X509.extensions(signerCert.data).find((e) => e.privateKeyUsagePeriod),
      {
        oid: 'privateKeyUsagePeriod',
        critical: false,
        privateKeyUsagePeriod: { notBefore: '20260417000000Z', notAfter: undefined },
      }
    );
    signerCert.data.tbs.extensions.list.pop();
    signerCert.data.tbs.extensions.list.push({
      oid: 'privateKeyUsagePeriod',
      rest: Uint8Array.from([0x04, 0x02, 0x30, 0x00]),
    });
    c.content = __TEST.CMSSignedData.encode(sd);
    c.ber = undefined;
    throws(
      () =>
        CMS.verify(CMS.encode(c), { time: CERT_CREATED, chain: [root], checkSignatures: false }),
      /privateKeyUsagePeriod must contain notBefore or notAfter/
    );
    signerCert.data.tbs.extensions.list.pop();
    signerCert.data.tbs.extensions.list.push({
      oid: 'privateKeyUsagePeriod',
      rest: Uint8Array.from([0x04, 0x04, 0x30, 0x02, 0x80, 0x00]),
    });
    c.content = __TEST.CMSSignedData.encode(sd);
    c.ber = undefined;
    throws(
      () =>
        CMS.verify(CMS.encode(c), { time: CERT_CREATED, chain: [root], checkSignatures: false }),
      /expected X509 time/
    );
  });
  should('enforces RFC 5280 DisplayText SIZE constraints', () => {
    const cert = X509.decode(
      hexToBytes(
        '3082012c3081dfa00302010202143ee39c0286eeed43006f2c6d66dce4133789957c300506032b6570300c310a300806035504030c0141301e170d3236303431363233353930325a170d3236303431373233353930325a300c310a300806035504030c0141302a300506032b65700321006a49c999d4c14eb4e10893aa46ed6202c81472ea29bc4bd8ea015e316999abcfa3533051301d0603551d0e04160414943dcd01f649df0cd0e62a2f0c55296c18cc5f7e301f0603551d23041830168014943dcd01f649df0cd0e62a2f0c55296c18cc5f7e300f0603551d130101ff040530030101ff300506032b6570034100476186c95341f535156677af510d2a5b7a01acd7d791baca60cd10fd093ab06cdd963a15a2b746b6ef24a9339ce436ff1334c30b972d6eada756996578da660b'
      )
    );
    const cat = (...chunks: Uint8Array[]): Uint8Array => {
      const out = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.length, 0));
      let pos = 0;
      for (const chunk of chunks) {
        out.set(chunk, pos);
        pos += chunk.length;
      }
      return out;
    };
    const tlv = (tag: number, body: Uint8Array): Uint8Array =>
      cat(Uint8Array.of(tag), DERUtils.DERLen.encode(body.length), body);
    const seq = (body: Uint8Array): Uint8Array => tlv(0x30, body);
    const policies = (userNotice: Uint8Array, qualifierOid = '1.3.6.1.5.5.7.2.2') => {
      const decoded = structuredClone(cert);
      decoded.tbs.extensions.list.push({
        oid: 'certificatePolicies',
        rest: DERUtils.ASN1.OctetString.encode(
          seq(
            seq(
              cat(
                DERUtils.ASN1.OID.encode('anyPolicy'),
                seq(seq(cat(DERUtils.ASN1.OID.encode(qualifierOid), seq(userNotice))))
              )
            )
          )
        ),
      });
      return X509.extensions(decoded).find((e) => e.policies);
    };
    deepStrictEqual(policies(tlv(0x0c, Uint8Array.of(0x41)))?.policies?.list, [
      {
        policy: 'anyPolicy',
        qualifiers: {
          list: [
            {
              TAG: 'userNotice',
              data: {
                noticeRef: undefined,
                explicitText: { tag: 'utf8', text: 'A' },
              },
            },
          ],
        },
      },
    ]);
    deepStrictEqual(
      policies(
        seq(
          cat(
            tlv(0x0c, new TextEncoder().encode('O')),
            seq(tlv(0x02, hexToBytes('20000000000001')))
          )
        )
      )?.policies?.list,
      [
        {
          policy: 'anyPolicy',
          qualifiers: {
            list: [
              {
                TAG: 'userNotice',
                data: {
                  noticeRef: {
                    organization: { tag: 'utf8', text: 'O' },
                    numbers: [9007199254740993n],
                  },
                  explicitText: undefined,
                },
              },
            ],
          },
        },
      ]
    );
    deepStrictEqual(policies(seq(Uint8Array.of(0xbf, 0x1f, 0x00)), '1.2.3.5')?.policies?.list, [
      {
        policy: 'anyPolicy',
        qualifiers: {
          list: [
            {
              TAG: 'unknown',
              data: {
                oid: '1.2.3.5',
                value: {
                  tag: 0x30,
                  children: [
                    { tag: 0x30, children: [{ tag: 0xbf, tagHex: 'bf1f', children: [] }] },
                  ],
                },
              },
            },
          ],
        },
      },
    ]);
    throws(() => policies(tlv(0x0c, new Uint8Array())), /DisplayText.*1\.\.200/);
    throws(
      () => policies(tlv(0x1a, new TextEncoder().encode('A'.repeat(201)))),
      /DisplayText.*1\.\.200/
    );
  });
  should('enforces RFC 5280 policyMappings constraints', () => {
    const { root } = getCertKeyRoot();

    const c = decodeP384Cert();
    const sd = __TEST.CMSSignedData.decode(c.content);
    const sid = sd.signerInfos[0].sid;
    if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
    const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
    const signerCert = (sd.certificates || []).find(
      (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
        i.TAG === 'certificate' &&
        i.data.tbs.serial === sid.data.serial &&
        equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
    );
    if (!signerCert || !signerCert.data.tbs.extensions)
      throw new Error('signer cert/extensions not found');
    // extnValue DER: SEQUENCE{ SEQUENCE{ anyPolicy, 1.2.3 } }
    const mapping = Uint8Array.from([
      0x30, 0x0c, 0x30, 0x0a, 0x06, 0x04, 0x55, 0x1d, 0x20, 0x00, 0x06, 0x02, 0x2a, 0x03,
    ]);
    signerCert.data.tbs.extensions.list.push({
      oid: 'policyMappings',
      rest: Uint8Array.from([0x04, mapping.length, ...mapping]),
    });
    c.content = __TEST.CMSSignedData.encode(sd);
    c.ber = undefined;
    throws(
      () =>
        CMS.verify(CMS.encode(c), { time: CERT_CREATED, chain: [root], checkSignatures: false }),
      /policyMappings must not contain anyPolicy/
    );
  });
  should('enforces RFC 5280 subjectAltName GeneralNames SIZE constraint', () => {
    const { root } = getCertKeyRoot();

    const c = decodeP384Cert();
    const sd = __TEST.CMSSignedData.decode(c.content);
    const sid = sd.signerInfos[0].sid;
    if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
    const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
    const signerCert = (sd.certificates || []).find(
      (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
        i.TAG === 'certificate' &&
        i.data.tbs.serial === sid.data.serial &&
        equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
    );
    if (!signerCert || !signerCert.data.tbs.extensions)
      throw new Error('signer cert/extensions not found');
    const san = signerCert.data.tbs.extensions.list.find((e) => e.oid === 'subjectAltName');
    if (!san) throw new Error('expected subjectAltName extension');
    san.rest = Uint8Array.from([0x04, 0x02, 0x30, 0x00]);
    c.content = __TEST.CMSSignedData.encode(sd);
    c.ber = undefined;
    throws(
      () =>
        CMS.verify(CMS.encode(c), { time: CERT_CREATED, chain: [root], checkSignatures: false }),
      /subjectAltName must contain at least one GeneralName/
    );
    const emptyNames: [
      Uint8Array,
      { TAG: 'rfc822Name' | 'dNSName' | 'uniformResourceIdentifier' | 'iPAddress'; data: string },
    ][] = [
      [Uint8Array.from([0x04, 0x04, 0x30, 0x02, 0x81, 0x00]), { TAG: 'rfc822Name', data: '' }],
      [Uint8Array.from([0x04, 0x04, 0x30, 0x02, 0x82, 0x00]), { TAG: 'dNSName', data: '' }],
      [
        Uint8Array.from([0x04, 0x04, 0x30, 0x02, 0x86, 0x00]),
        { TAG: 'uniformResourceIdentifier', data: '' },
      ],
      [Uint8Array.from([0x04, 0x04, 0x30, 0x02, 0x87, 0x00]), { TAG: 'iPAddress', data: 'hex:' }],
    ];
    for (const [rest, name] of emptyNames) {
      san.rest = rest;
      c.content = __TEST.CMSSignedData.encode(sd);
      c.ber = undefined;
      deepStrictEqual(
        X509.extensions(signerCert.data).find((e) => e.san),
        {
          oid: 'subjectAltName',
          critical: false,
          san: { list: [name] },
        }
      );
      deepStrictEqual(
        CMS.verify(CMS.encode(c), { time: CERT_CREATED, chain: [root], checkSignatures: false })
          .chain.length,
        2
      );
    }
  });
  should('enforces RFC 5280 issuerAltName GeneralNames SIZE constraint', () => {
    const { root } = getCertKeyRoot();

    const c = decodeP384Cert();
    const sd = __TEST.CMSSignedData.decode(c.content);
    const sid = sd.signerInfos[0].sid;
    if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
    const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
    const signerCert = (sd.certificates || []).find(
      (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
        i.TAG === 'certificate' &&
        i.data.tbs.serial === sid.data.serial &&
        equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
    );
    if (!signerCert || !signerCert.data.tbs.extensions)
      throw new Error('signer cert/extensions not found');
    signerCert.data.tbs.extensions.list.push({
      oid: 'issuerAltName',
      rest: Uint8Array.from([0x04, 0x02, 0x30, 0x00]),
    });
    c.content = __TEST.CMSSignedData.encode(sd);
    c.ber = undefined;
    throws(
      () =>
        CMS.verify(CMS.encode(c), { time: CERT_CREATED, chain: [root], checkSignatures: false }),
      /issuerAltName must contain at least one GeneralName/
    );
  });
  should('enforces RFC 5280 subjectDirectoryAttributes SIZE constraints', () => {
    const { root } = getCertKeyRoot();

    const c = decodeP384Cert();
    const sd = __TEST.CMSSignedData.decode(c.content);
    const sid = sd.signerInfos[0].sid;
    if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
    const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
    const signerCert = (sd.certificates || []).find(
      (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
        i.TAG === 'certificate' &&
        i.data.tbs.serial === sid.data.serial &&
        equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
    );
    if (!signerCert || !signerCert.data.tbs.extensions)
      throw new Error('signer cert/extensions not found');
    signerCert.data.tbs.extensions.list.push({
      oid: 'subjectDirectoryAttributes',
      rest: Uint8Array.from([0x04, 0x02, 0x30, 0x00]),
    });
    c.content = __TEST.CMSSignedData.encode(sd);
    c.ber = undefined;
    throws(
      () =>
        CMS.verify(CMS.encode(c), { time: CERT_CREATED, chain: [root], checkSignatures: false }),
      /subjectDirectoryAttributes must contain at least one attribute/
    );
  });
  should('enforces RFC 5280 nameConstraints profile constraints', () => {
    const { root } = getCertKeyRoot();

    const make = (extnValue: Uint8Array): Uint8Array => {
      const c = decodeP384Cert();
      const sd = __TEST.CMSSignedData.decode(c.content);
      const sid = sd.signerInfos[0].sid;
      if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
      const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
      const signerCert = (sd.certificates || []).find(
        (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
          i.TAG === 'certificate' &&
          i.data.tbs.serial === sid.data.serial &&
          equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
      );
      if (!signerCert || !signerCert.data.tbs.extensions)
        throw new Error('signer cert/extensions not found');
      signerCert.data.tbs.extensions.list.push({
        oid: 'nameConstraints',
        rest: Uint8Array.from([0x01, 0x01, 0xff, 0x04, extnValue.length, ...extnValue]),
      });
      c.content = __TEST.CMSSignedData.encode(sd);
      c.ber = undefined;
      return CMS.encode(c);
    };
    const emptyNC = make(Uint8Array.from([0x30, 0x00]));
    throws(
      () => CMS.verify(emptyNC, { time: CERT_CREATED, chain: [root], checkSignatures: false }),
      /nameConstraints must contain permittedSubtrees or excludedSubtrees/
    );
    // NameConstraints with permittedSubtrees and GeneralSubtree.minimum=1.
    const badMinimum = make(
      Uint8Array.from([
        0x30, 0x0e, 0xa0, 0x0c, 0x30, 0x0a, 0x82, 0x05, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x80, 0x01,
        0x01,
      ])
    );
    throws(
      () => CMS.verify(badMinimum, { time: CERT_CREATED, chain: [root], checkSignatures: false }),
      /nameConstraints GeneralSubtree.minimum must be 0 in this profile/
    );

    const openSSLStyle = Uint8Array.from([
      0x30, 0x12, 0xa0, 0x10, 0x30, 0x0e, 0x82, 0x0c, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
      0x65, 0x2e, 0x63, 0x6f, 0x6d,
    ]);
    const openSSLStyleCert = X509.decode(certDersFromVector('openssl/fake-gp.pem')[0]);
    openSSLStyleCert.tbs.extensions = {
      list: [
        {
          oid: 'nameConstraints',
          rest: Uint8Array.from([0x01, 0x01, 0xff, 0x04, openSSLStyle.length, ...openSSLStyle]),
        },
      ],
    };
    deepStrictEqual(X509.extensions(openSSLStyleCert)[0], {
      oid: 'nameConstraints',
      critical: true,
      nameConstraints: {
        permitted: {
          list: [
            {
              base: { TAG: 'dNSName', data: '.example.com' },
              minimum: undefined,
              maximum: undefined,
            },
          ],
        },
        excluded: undefined,
      },
    });

    const cert = X509.decode(certDersFromVector('openssl/fake-gp.pem')[0]);
    cert.tbs.extensions = {
      list: [
        {
          oid: 'nameConstraints',
          rest: Uint8Array.from([
            0x01, 0x01, 0xff, 0x04, 0x10, 0x30, 0x0e, 0xa0, 0x0c, 0x30, 0x0a, 0x87, 0x08, 0xc0,
            0x00, 0x02, 0x00, 0xff, 0xff, 0xff, 0x00,
          ]),
        },
      ],
    };
    deepStrictEqual(X509.extensions(cert), [
      {
        oid: 'nameConstraints',
        critical: true,
        nameConstraints: {
          permitted: {
            list: [
              {
                base: { TAG: 'iPAddress', data: '192.0.2.0/24' },
                minimum: undefined,
                maximum: undefined,
              },
            ],
          },
          excluded: undefined,
        },
      },
    ]);
  });
  should('enforces RFC 5280 policyConstraints syntax constraints', () => {
    const { root } = getCertKeyRoot();
    const make = (extnValue: Uint8Array): Uint8Array => {
      const c = decodeP384Cert();
      const sd = __TEST.CMSSignedData.decode(c.content);
      const sid = sd.signerInfos[0].sid;
      if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
      const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
      const signerCert = (sd.certificates || []).find(
        (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
          i.TAG === 'certificate' &&
          i.data.tbs.serial === sid.data.serial &&
          equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
      );
      if (!signerCert || !signerCert.data.tbs.extensions)
        throw new Error('signer cert/extensions not found');
      signerCert.data.tbs.extensions.list.push({
        oid: 'policyConstraints',
        rest: Uint8Array.from([0x01, 0x01, 0xff, 0x04, extnValue.length, ...extnValue]),
      });
      c.content = __TEST.CMSSignedData.encode(sd);
      c.ber = undefined;
      return CMS.encode(c);
    };
    const empty = make(Uint8Array.from([0x30, 0x00]));
    throws(
      () => CMS.verify(empty, { time: CERT_CREATED, chain: [root], checkSignatures: false }),
      /policyConstraints must contain requireExplicitPolicy or inhibitPolicyMapping/
    );
  });
  should('enforces RFC 5280 cRLDistributionPoints structure constraints', () => {
    const { root } = getCertKeyRoot();
    const c = decodeP384Cert();
    const sd = __TEST.CMSSignedData.decode(c.content);
    const sid = sd.signerInfos[0].sid;
    if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
    const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
    const signerCert = (sd.certificates || []).find(
      (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
        i.TAG === 'certificate' &&
        i.data.tbs.serial === sid.data.serial &&
        equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
    );
    if (!signerCert || !signerCert.data.tbs.extensions)
      throw new Error('signer cert/extensions not found');
    // CRLDP with one DistributionPoint containing only reasons (forbidden by RFC 5280 section 4.2.1.13).
    const crldp = Uint8Array.from([0x30, 0x06, 0x30, 0x04, 0x81, 0x02, 0x07, 0x40]);
    signerCert.data.tbs.extensions.list.push({
      oid: 'crlDistributionPoints',
      rest: Uint8Array.from([0x04, crldp.length, ...crldp]),
    });
    c.content = __TEST.CMSSignedData.encode(sd);
    c.ber = undefined;
    throws(
      () =>
        CMS.verify(CMS.encode(c), { time: CERT_CREATED, chain: [root], checkSignatures: false }),
      /BIT STRING nonzero unused tail bits/
    );
  });
  should('enforces RFC 5280 cRLIssuer distinguished-name constraint', () => {
    const base = X509.decode(certDersFromVector('openssl/p384-root.pem')[0]);
    const crldp = (body: Uint8Array) => {
      const cert = structuredClone(base);
      if (!cert.tbs.extensions) throw new Error('cert/extensions not found');
      cert.tbs.extensions.list.push({
        oid: 'crlDistributionPoints',
        rest: Uint8Array.from([0x04, body.length, ...body]),
      });
      const hits = X509.extensions(cert).filter((e) => e.crlDistributionPoints);
      return hits[hits.length - 1];
    };
    deepStrictEqual(
      crldp(
        Uint8Array.from([
          0x30, 0x14, 0x30, 0x12, 0xa2, 0x10, 0xa4, 0x0e, 0x30, 0x0c, 0x31, 0x0a, 0x30, 0x08, 0x06,
          0x03, 0x55, 0x04, 0x03, 0x0c, 0x01, 0x41,
        ])
      ),
      {
        oid: 'crlDistributionPoints',
        critical: false,
        crlDistributionPoints: {
          list: [
            {
              distributionPoint: undefined,
              reasons: undefined,
              cRLIssuer: {
                list: [
                  {
                    TAG: 'directoryName',
                    data: {
                      rdns: [[{ oid: 'commonName', value: { TAG: 'utf8', data: 'A' } }]],
                    },
                  },
                ],
              },
            },
          ],
        },
      }
    );
    throws(
      () =>
        crldp(
          Uint8Array.from([
            0x30, 0x11, 0x30, 0x0f, 0xa2, 0x0d, 0x82, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
            0x65, 0x2e, 0x63, 0x6f, 0x6d,
          ])
        ),
      /cRLIssuer must only contain directoryName/
    );
  });
  should('enforces RFC 5280 nameRelativeToCRLIssuer non-empty RDN constraint', () => {
    const base = X509.decode(certDersFromVector('openssl/p384-root.pem')[0]);
    const crldp = (body: Uint8Array) => {
      const cert = structuredClone(base);
      if (!cert.tbs.extensions) throw new Error('cert/extensions not found');
      cert.tbs.extensions.list.push({
        oid: 'crlDistributionPoints',
        rest: Uint8Array.from([0x04, body.length, ...body]),
      });
      const hits = X509.extensions(cert).filter((e) => e.crlDistributionPoints);
      return hits[hits.length - 1];
    };
    deepStrictEqual(
      crldp(
        Uint8Array.from([
          0x30, 0x10, 0x30, 0x0e, 0xa0, 0x0c, 0xa1, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03,
          0x0c, 0x01, 0x41,
        ])
      ),
      {
        oid: 'crlDistributionPoints',
        critical: false,
        crlDistributionPoints: {
          list: [
            {
              distributionPoint: {
                TAG: 'nameRelativeToCRLIssuer',
                data: [{ oid: 'commonName', value: { TAG: 'utf8', data: 'A' } }],
              },
              reasons: undefined,
              cRLIssuer: undefined,
            },
          ],
        },
      }
    );
    throws(
      () => crldp(Uint8Array.from([0x30, 0x06, 0x30, 0x04, 0xa0, 0x02, 0xa1, 0x00])),
      /nameRelativeToCRLIssuer must contain at least one AttributeTypeAndValue/
    );
  });
  should('enforces RFC 5280 issuingDistributionPoint profile constraints', () => {
    const base = X509.decode(certDersFromVector('openssl/p384-root.pem')[0]);
    const idp = (body: Uint8Array) => {
      const cert = structuredClone(base);
      if (!cert.tbs.extensions) throw new Error('cert/extensions not found');
      cert.tbs.extensions.list.push({
        oid: 'issuingDistributionPoint',
        rest: Uint8Array.from([0x04, body.length, ...body]),
      });
      const hits = X509.extensions(cert).filter((e) => e.issuingDistributionPoint);
      return hits[hits.length - 1];
    };
    deepStrictEqual(idp(Uint8Array.from([0x30, 0x03, 0x81, 0x01, 0xff])), {
      oid: 'issuingDistributionPoint',
      critical: false,
      issuingDistributionPoint: {
        distributionPoint: undefined,
        onlyContainsUserCerts: true,
        onlyContainsCACerts: undefined,
        onlySomeReasons: undefined,
        indirectCRL: undefined,
        onlyContainsAttributeCerts: undefined,
      },
    });
    throws(() => idp(Uint8Array.from([0x30, 0x00])), /issuingDistributionPoint/);
    throws(
      () => idp(Uint8Array.from([0x30, 0x06, 0x81, 0x01, 0xff, 0x82, 0x01, 0xff])),
      /issuingDistributionPoint/
    );
    throws(() => idp(Uint8Array.from([0x30, 0x03, 0x85, 0x01, 0xff])), /issuingDistributionPoint/);
  });
  should('enforces RFC 5280 freshestCRL criticality constraint', () => {
    const { root } = getCertKeyRoot();
    const c = decodeP384Cert();
    const sd = __TEST.CMSSignedData.decode(c.content);
    const sid = sd.signerInfos[0].sid;
    if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
    const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
    const signerCert = (sd.certificates || []).find(
      (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
        i.TAG === 'certificate' &&
        i.data.tbs.serial === sid.data.serial &&
        equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
    );
    if (!signerCert || !signerCert.data.tbs.extensions)
      throw new Error('signer cert/extensions not found');
    const freshest = hexToBytes(
      // Valid CRLDistributionPoints extnValue bytes copied from openssl/embeddedSCTs3_issuer.pem.
      '044530433041a03fa03d863b687474703a2f2f63726c2e636f6d6f646f63612e636f6d2f434f4d4f444f52534143657274696669636174696f6e417574686f726974792e63726c'
    );
    signerCert.data.tbs.extensions.list.push({
      oid: 'freshestCRL',
      rest: Uint8Array.from([0x01, 0x01, 0xff, ...freshest]),
    });
    c.content = __TEST.CMSSignedData.encode(sd);
    c.ber = undefined;
    throws(
      () =>
        CMS.verify(CMS.encode(c), { time: CERT_CREATED, chain: [root], checkSignatures: false }),
      /freshestCRL extension must be non-critical/
    );
  });
  should('enforces RFC 5280 authorityInfoAccess syntax and criticality constraints', () => {
    const { root } = getCertKeyRoot();
    const c = decodeP384Cert();
    const sd = __TEST.CMSSignedData.decode(c.content);
    const sid = sd.signerInfos[0].sid;
    if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
    const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
    const signerCert = (sd.certificates || []).find(
      (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
        i.TAG === 'certificate' &&
        i.data.tbs.serial === sid.data.serial &&
        equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
    );
    if (!signerCert || !signerCert.data.tbs.extensions)
      throw new Error('signer cert/extensions not found');
    const aia = Uint8Array.from([
      0x30, 0x19, 0x30, 0x17, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x86,
      0x0b, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x6f, 0x63, 0x73, 0x70,
    ]);
    signerCert.data.tbs.extensions.list.push({
      oid: '1.3.6.1.5.5.7.1.1',
      rest: Uint8Array.from([0x01, 0x01, 0xff, 0x04, aia.length, ...aia]),
    });
    c.content = __TEST.CMSSignedData.encode(sd);
    c.ber = undefined;
    throws(
      () =>
        CMS.verify(CMS.encode(c), { time: CERT_CREATED, chain: [root], checkSignatures: false }),
      /authorityInfoAccess extension must be non-critical/
    );
  });
  should('enforces RFC 5280 subjectInfoAccess syntax and criticality constraints', () => {
    const { root } = getCertKeyRoot();
    const c = decodeP384Cert();
    const sd = __TEST.CMSSignedData.decode(c.content);
    const sid = sd.signerInfos[0].sid;
    if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
    const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
    const signerCert = (sd.certificates || []).find(
      (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
        i.TAG === 'certificate' &&
        i.data.tbs.serial === sid.data.serial &&
        equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
    );
    if (!signerCert || !signerCert.data.tbs.extensions)
      throw new Error('signer cert/extensions not found');
    const sia = Uint8Array.from([
      0x30, 0x19, 0x30, 0x17, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x05, 0x86,
      0x0b, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x72, 0x65, 0x70, 0x6f,
    ]);
    signerCert.data.tbs.extensions.list.push({
      oid: '1.3.6.1.5.5.7.1.11',
      rest: Uint8Array.from([0x01, 0x01, 0xff, 0x04, sia.length, ...sia]),
    });
    c.content = __TEST.CMSSignedData.encode(sd);
    c.ber = undefined;
    throws(
      () =>
        CMS.verify(CMS.encode(c), { time: CERT_CREATED, chain: [root], checkSignatures: false }),
      /subjectInfoAccess extension must be non-critical/
    );
  });
  should('enforces RFC 7633 tlsFeature identifier range constraints', () => {
    const { root } = getCertKeyRoot();
    const c = decodeP384Cert();
    const sd = __TEST.CMSSignedData.decode(c.content);
    const sid = sd.signerInfos[0].sid;
    if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
    const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
    const signerCert = (sd.certificates || []).find(
      (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
        i.TAG === 'certificate' &&
        i.data.tbs.serial === sid.data.serial &&
        equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
    );
    if (!signerCert || !signerCert.data.tbs.extensions)
      throw new Error('signer cert/extensions not found');
    // Features ::= SEQUENCE OF INTEGER, but values are TLS extension IDs (uint16).
    const badTLSFeature = Uint8Array.from([0x30, 0x05, 0x02, 0x03, 0x01, 0x00, 0x00]);
    signerCert.data.tbs.extensions.list.push({
      oid: '1.3.6.1.5.5.7.1.24',
      rest: Uint8Array.from([0x04, badTLSFeature.length, ...badTLSFeature]),
    });
    c.content = __TEST.CMSSignedData.encode(sd);
    c.ber = undefined;
    throws(
      () =>
        CMS.verify(CMS.encode(c), { time: CERT_CREATED, chain: [root], checkSignatures: false }),
      /tlsFeature value must be in 0..65535/
    );
  });
  should('enforces RFC 6962 SCT list size and version constraints', () => {
    const { root } = getCertKeyRoot();
    const make = (sctExtnValue: Uint8Array): Uint8Array => {
      const c = decodeP384Cert();
      const sd = __TEST.CMSSignedData.decode(c.content);
      const sid = sd.signerInfos[0].sid;
      if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
      const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
      const signerCert = (sd.certificates || []).find(
        (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
          i.TAG === 'certificate' &&
          i.data.tbs.serial === sid.data.serial &&
          equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
      );
      if (!signerCert || !signerCert.data.tbs.extensions)
        throw new Error('signer cert/extensions not found');
      signerCert.data.tbs.extensions.list.push({
        oid: '1.3.6.1.4.1.11129.2.4.2',
        rest: DERUtils.ASN1.OctetString.encode(sctExtnValue),
      });
      c.content = __TEST.CMSSignedData.encode(sd);
      c.ber = undefined;
      return CMS.encode(c);
    };
    const largeList = (() => {
      const signature = new Uint8Array(975);
      const sct = Uint8Array.from([
        0x00, // sct_version
        ...new Uint8Array(32), // log id
        ...new Uint8Array(8), // timestamp
        0x00,
        0x00, // CtExtensions length
        0x04, // hash algorithm
        0x03, // signature algorithm
        signature.length >>> 8,
        signature.length & 0xff,
        ...signature,
      ]);
      deepStrictEqual(sct.length, 1022);
      return Uint8Array.from([0x04, 0x00, 0x03, 0xfe, ...sct]);
    })();
    CMS.verify(make(largeList), { time: CERT_CREATED, chain: [root], checkSignatures: false });
    // SignedCertificateTimestampList.sct_list length is 0 (forbidden by RFC 6962 section 3.3).
    const emptyList = make(Uint8Array.from([0x00, 0x00]));
    throws(
      () => CMS.verify(emptyList, { time: CERT_CREATED, chain: [root], checkSignatures: false }),
      /sct list must contain at least one SerializedSCT/
    );
    // One SCT with version=1 (RFC 6962 v1 requires sct_version=0).
    const badVersion = (() => {
      const sct = Uint8Array.from([
        0x01, // sct_version
        ...new Uint8Array(32), // log id
        ...new Uint8Array(8), // timestamp
        0x00,
        0x00, // CtExtensions length
        0x04, // hash algorithm
        0x03, // signature algorithm
        0x00,
        0x00, // signature length
      ]);
      return Uint8Array.from([0x00, 0x31, 0x00, 0x2f, ...sct]);
    })();
    throws(
      () =>
        CMS.verify(make(badVersion), {
          time: CERT_CREATED,
          chain: [root],
          checkSignatures: false,
        }),
      /sct_version must be v1 \(0\), got 1/
    );
  });
  should('enforces RFC 5280 criticality for path-processing extensions', () => {
    const { root } = getCertKeyRoot();
    const c = decodeP384Cert();
    const sd = __TEST.CMSSignedData.decode(c.content);
    const sid = sd.signerInfos[0].sid;
    if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
    const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
    const signerCert = (sd.certificates || []).find(
      (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
        i.TAG === 'certificate' &&
        i.data.tbs.serial === sid.data.serial &&
        equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
    );
    if (!signerCert || !signerCert.data.tbs.extensions)
      throw new Error('signer cert/extensions not found');
    signerCert.data.tbs.extensions.list.push({
      oid: 'inhibitAnyPolicy',
      // Non-critical inhibitAnyPolicy = 0
      rest: Uint8Array.from([0x04, 0x03, 0x02, 0x01, 0x00]),
    });
    c.content = __TEST.CMSSignedData.encode(sd);
    c.ber = undefined;
    throws(
      () =>
        CMS.verify(CMS.encode(c), { time: CERT_CREATED, chain: [root], checkSignatures: false }),
      /inhibitAnyPolicy extension must be critical/
    );
  });
  should('fails closed for unsupported RFC 5280 section 6 policy/name processing controls', () => {
    const { root } = getCertKeyRoot();
    const c = decodeP384Cert();
    const sd = __TEST.CMSSignedData.decode(c.content);
    const sid = sd.signerInfos[0].sid;
    if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
    const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
    const signerCert = (sd.certificates || []).find(
      (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
        i.TAG === 'certificate' &&
        i.data.tbs.serial === sid.data.serial &&
        equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
    );
    if (!signerCert || !signerCert.data.tbs.extensions)
      throw new Error('signer cert/extensions not found');
    signerCert.data.tbs.extensions.list.push({
      oid: 'inhibitAnyPolicy',
      // Critical inhibitAnyPolicy = 0.
      rest: Uint8Array.from([0x01, 0x01, 0xff, 0x04, 0x03, 0x02, 0x01, 0x00]),
    });
    c.content = __TEST.CMSSignedData.encode(sd);
    c.ber = undefined;
    throws(
      () =>
        CMS.verify(CMS.encode(c), { time: CERT_CREATED, chain: [root], checkSignatures: false }),
      /nameConstraints\/policyMappings\/policyConstraints\/inhibitAnyPolicy present but RFC 5280 section 6 processing is not implemented/
    );
  });
  should('rejects critical certificateIssuer on certificate surfaces', () => {
    const { root } = getCertKeyRoot();
    const c = decodeP384Cert();
    const sd = __TEST.CMSSignedData.decode(c.content);
    const sid = sd.signerInfos[0].sid;
    if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
    const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
    const signerCert = (sd.certificates || []).find(
      (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
        i.TAG === 'certificate' &&
        i.data.tbs.serial === sid.data.serial &&
        equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
    );
    if (!signerCert || !signerCert.data.tbs.extensions)
      throw new Error('signer cert/extensions not found');
    signerCert.data.tbs.extensions.list.push({
      oid: 'certificateIssuer',
      rest: Uint8Array.from([
        0x01, 0x01, 0xff, 0x04, 0x10, 0x30, 0x0e, 0x82, 0x0c, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
        0x65, 0x2e, 0x74, 0x65, 0x73, 0x74,
      ]),
    });
    c.content = __TEST.CMSSignedData.encode(sd);
    c.ber = undefined;
    throws(
      () =>
        CMS.verify(CMS.encode(c), { time: CERT_CREATED, chain: [root], checkSignatures: false }),
      /unknown critical extension certificateIssuer/
    );
  });
  should('fails closed for unsupported RFC 5280 nameConstraints processing', () => {
    const { root } = getCertKeyRoot();
    const c = decodeP384Cert();
    const sd = __TEST.CMSSignedData.decode(c.content);
    const sid = sd.signerInfos[0].sid;
    if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
    const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
    const signerCert = (sd.certificates || []).find(
      (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
        i.TAG === 'certificate' &&
        i.data.tbs.serial === sid.data.serial &&
        equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
    );
    if (!signerCert || !signerCert.data.tbs.extensions)
      throw new Error('signer cert/extensions not found');
    // NameConstraints with one permitted dNSName subtree (valid syntax, critical extension).
    const nc = Uint8Array.from([
      0x30, 0x0b, 0xa0, 0x09, 0x30, 0x07, 0x82, 0x05, 0x61, 0x2e, 0x63, 0x6f, 0x6d,
    ]);
    signerCert.data.tbs.extensions.list.push({
      oid: 'nameConstraints',
      rest: Uint8Array.from([0x01, 0x01, 0xff, 0x04, nc.length, ...nc]),
    });
    c.content = __TEST.CMSSignedData.encode(sd);
    c.ber = undefined;
    throws(
      () =>
        CMS.verify(CMS.encode(c), { time: CERT_CREATED, chain: [root], checkSignatures: false }),
      /nameConstraints\/policyMappings\/policyConstraints\/inhibitAnyPolicy present but RFC 5280 section 6 processing is not implemented/
    );
  });
  should('fails closed for unsupported RFC 5280 policyMappings processing', () => {
    const { root } = getCertKeyRoot();
    const c = decodeP384Cert();
    const sd = __TEST.CMSSignedData.decode(c.content);
    const sid = sd.signerInfos[0].sid;
    if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
    const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
    const signerCert = (sd.certificates || []).find(
      (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
        i.TAG === 'certificate' &&
        i.data.tbs.serial === sid.data.serial &&
        equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
    );
    if (!signerCert || !signerCert.data.tbs.extensions)
      throw new Error('signer cert/extensions not found');
    const pm = Uint8Array.from([
      0x30, 0x18, 0x30, 0x16, 0x06, 0x08, 0x2a, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x06,
      0x0a, 0x2a, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x01,
    ]);
    signerCert.data.tbs.extensions.list.push({
      oid: 'policyMappings',
      rest: Uint8Array.from([0x04, pm.length, ...pm]),
    });
    c.content = __TEST.CMSSignedData.encode(sd);
    c.ber = undefined;
    throws(
      () =>
        CMS.verify(CMS.encode(c), { time: CERT_CREATED, chain: [root], checkSignatures: false }),
      /nameConstraints\/policyMappings\/policyConstraints\/inhibitAnyPolicy present but RFC 5280 section 6 processing is not implemented/
    );
  });
  should('enforces RFC 5280 basicConstraints/pathLen and cA-keyCertSign consistency', () => {
    const { root } = getCertKeyRoot();
    const make = (
      mutate: (
        sd: ReturnType<typeof __TEST.CMSSignedData.decode>,
        signerCert: Extract<
          NonNullable<ReturnType<typeof __TEST.CMSSignedData.decode>['certificates']>[number],
          { TAG: 'certificate' }
        >
      ) => void
    ): Uint8Array => {
      const c = decodeP384Cert();
      const sd = __TEST.CMSSignedData.decode(c.content);
      const sid = sd.signerInfos[0].sid;
      if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
      const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
      const signerCert = (sd.certificates || []).find(
        (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
          i.TAG === 'certificate' &&
          i.data.tbs.serial === sid.data.serial &&
          equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
      );
      if (!signerCert || !signerCert.data.tbs.extensions)
        throw new Error('signer cert/extensions not found');
      mutate(sd, signerCert);
      c.content = __TEST.CMSSignedData.encode(sd);
      c.ber = undefined;
      return CMS.encode(c);
    };
    const badBasic = make((_, signerCert) => {
      // pathLen with cA=false (or absent) violates RFC 5280 section 4.2.1.9.
      // Keep one BasicConstraints instance; duplicate OIDs are rejected by RFC 5280 section 4.2 guard.
      const basic = signerCert.data.tbs.extensions!.list.find((e) => e.oid === 'basicConstraints');
      if (!basic) throw new Error('expected basicConstraints extension');
      basic.rest = Uint8Array.from([0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00]);
    });
    throws(
      () => CMS.verify(badBasic, { time: CERT_CREATED, chain: [root], checkSignatures: false }),
      /basicConstraints pathLenConstraint requires cA=true/
    );
    const badCAUsage = make((_, signerCert) => {
      // Set cA=false and keyCertSign=true.
      // Keep one BasicConstraints instance; duplicate OIDs are rejected by RFC 5280 section 4.2 guard.
      const basic = signerCert.data.tbs.extensions!.list.find((e) => e.oid === 'basicConstraints');
      if (!basic) throw new Error('expected basicConstraints extension');
      basic.rest = Uint8Array.from([0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0x00]);
      const keyUsage = signerCert.data.tbs.extensions!.list.find((e) => e.oid === 'keyUsage');
      if (keyUsage)
        keyUsage.rest = Uint8Array.from([0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x02, 0x04]);
      else
        signerCert.data.tbs.extensions!.list.push({
          oid: 'keyUsage',
          rest: Uint8Array.from([0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x02, 0x04]),
        });
    });
    throws(
      () => CMS.verify(badCAUsage, { time: CERT_CREATED, chain: [root], checkSignatures: false }),
      /keyUsage keyCertSign requires basicConstraints cA=true/
    );
  });
  should('enforces RFC 3820 proxyCertInfo criticality and policy rules', () => {
    const { root } = getCertKeyRoot();
    const make = (
      mutate: (
        sd: ReturnType<typeof __TEST.CMSSignedData.decode>,
        signerCert: Extract<
          NonNullable<ReturnType<typeof __TEST.CMSSignedData.decode>['certificates']>[number],
          { TAG: 'certificate' }
        >
      ) => void
    ): Uint8Array => {
      const c = decodeP384Cert();
      const sd = __TEST.CMSSignedData.decode(c.content);
      const sid = sd.signerInfos[0].sid;
      if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
      const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
      const signerCert = (sd.certificates || []).find(
        (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
          i.TAG === 'certificate' &&
          i.data.tbs.serial === sid.data.serial &&
          equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
      );
      if (!signerCert || !signerCert.data.tbs.extensions)
        throw new Error('signer cert/extensions not found');
      mutate(sd, signerCert);
      c.content = __TEST.CMSSignedData.encode(sd);
      c.ber = undefined;
      return CMS.encode(c);
    };
    // ProxyCertInfo extnValue: SEQUENCE { proxyPolicy SEQUENCE { policyLanguage = id-ppl-inheritAll } }.
    const proxyInheritAll = Uint8Array.from([
      0x30, 0x0c, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x15, 0x01,
    ]);
    const badNonCritical = make((_, signerCert) => {
      signerCert.data.tbs.extensions!.list.push({
        oid: '1.3.6.1.5.5.7.1.14',
        rest: Uint8Array.from([0x04, proxyInheritAll.length, ...proxyInheritAll]),
      });
    });
    throws(
      () =>
        CMS.verify(badNonCritical, { time: CERT_CREATED, chain: [root], checkSignatures: false }),
      /proxyCertInfo extension must be critical/
    );
    const badCA = make((_, signerCert) => {
      signerCert.data.tbs.extensions!.list.push({
        oid: '1.3.6.1.5.5.7.1.14',
        rest: Uint8Array.from([0x01, 0x01, 0xff, 0x04, proxyInheritAll.length, ...proxyInheritAll]),
      });
      // Keep one BasicConstraints instance; duplicate OIDs are rejected by RFC 5280 section 4.2 guard.
      const basic = signerCert.data.tbs.extensions!.list.find((e) => e.oid === 'basicConstraints');
      if (!basic) throw new Error('expected basicConstraints extension');
      basic.rest = Uint8Array.from([0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff]);
    });
    throws(
      () => CMS.verify(badCA, { time: CERT_CREATED, chain: [root], checkSignatures: false }),
      /proxy certificate basicConstraints cA MUST NOT be TRUE|signer certificate must not be a CA certificate/
    );
  });
  should('enforces RFC 5280 KeyUsage constraints for signer and issuer certs', () => {
    const { root } = getCertKeyRoot();
    const make = (
      mutate: (
        sd: ReturnType<typeof __TEST.CMSSignedData.decode>,
        signerCert: Extract<
          NonNullable<ReturnType<typeof __TEST.CMSSignedData.decode>['certificates']>[number],
          { TAG: 'certificate' }
        >
      ) => void
    ): Uint8Array => {
      const c = decodeP384Cert();
      const sd = __TEST.CMSSignedData.decode(c.content);
      const sid = sd.signerInfos[0].sid;
      if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
      const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
      const signerCert = (sd.certificates || []).find(
        (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
          i.TAG === 'certificate' &&
          i.data.tbs.serial === sid.data.serial &&
          equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
      );
      if (!signerCert) throw new Error('signer cert not found');
      mutate(sd, signerCert);
      c.content = __TEST.CMSSignedData.encode(sd);
      c.ber = undefined;
      return CMS.encode(c);
    };
    // ext.rest stores ExtBody *inner* bytes: [critical?] + OCTET STRING(extnValue).
    // keyUsage extnValue is DER BIT STRING TLV; here we supply "no bits set".
    const KU_NONE = Uint8Array.from([0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x00, 0x00]);
    const KU_SIGN_ONLY = Uint8Array.from([0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80]);
    const KU_COMMIT_ONLY = Uint8Array.from([0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x06, 0x40]);
    const KU_SIGN_AND_CERT = Uint8Array.from([
      0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x02, 0x84,
    ]);
    const setKU = (
      cert: Extract<
        NonNullable<ReturnType<typeof __TEST.CMSSignedData.decode>['certificates']>[number],
        { TAG: 'certificate' }
      >,
      rest: Uint8Array
    ) => {
      if (!cert.data.tbs.extensions) throw new Error('cert extensions missing');
      const ku =
        cert.data.tbs.extensions.list.find((e) => e.oid === 'keyUsage') ||
        (() => {
          const e = { oid: 'keyUsage', rest: new Uint8Array() };
          cert.data.tbs.extensions!.list.push(e);
          return e;
        })();
      ku.rest = rest;
    };
    const badSigner = make((_, signerCert) => {
      setKU(signerCert, KU_NONE);
    });
    throws(
      () => CMS.verify(badSigner, { time: CERT_CREATED, chain: [root], checkSignatures: false }),
      /signer keyUsage missing digitalSignature/
    );
    const contentCommitmentSigner = make((_, signerCert) => {
      setKU(signerCert, KU_COMMIT_ONLY);
    });
    CMS.verify(contentCommitmentSigner, {
      time: CERT_CREATED,
      chain: [root],
      checkSignatures: false,
    });
    const caSigner = make((_, signerCert) => {
      if (!signerCert.data.tbs.extensions) throw new Error('signer cert extensions missing');
      const basic = signerCert.data.tbs.extensions.list.find((e) => e.oid === 'basicConstraints');
      if (!basic) throw new Error('expected basicConstraints extension');
      basic.rest = Uint8Array.from([0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff]);
      setKU(signerCert, KU_SIGN_AND_CERT);
    });
    CMS.verify(caSigner, { time: CERT_CREATED, chain: [root], checkSignatures: false });
    const badIssuer = make((sd, signerCert) => {
      const signerIssuer = CERTUtils.Name.encode(signerCert.data.tbs.issuer);
      const issuer = (sd.certificates || []).find(
        (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
          i.TAG === 'certificate' &&
          equalBytes(CERTUtils.Name.encode(i.data.tbs.subject), signerIssuer)
      );
      if (!issuer) throw new Error('issuer cert not found');
      setKU(issuer, KU_SIGN_ONLY);
    });
    throws(
      () => CMS.verify(badIssuer, { time: CERT_CREATED, chain: [], checkSignatures: false }),
      /issuer keyUsage missing keyCertSign/
    );
  });
  should('verify is validate plus signature checks', () => {
    const tpl = getEdnsJiyaTpl();
    const { cert, key, root } = getCertKeyRoot();
    const signed = CMS.sign(tpl, cert, key, root);
    const okOpts = { time: CERT_CREATED, chain: [root] as string[] };
    const v = CMS.verify(signed, okOpts);
    deepStrictEqual(typeof v.signer.tbs, 'object');
    CMS.verify(signed, { ...okOpts, checkSignatures: true });
    // Best-effort mode for environments without system trust roots: verify signatures and
    // return chain, while leaving trust-anchor policy to the caller.
    CMS.verify(signed, { time: okOpts.time, checkSignatures: true });
    const parsed = CMS.signed(signed);
    const sig = parsed.signerInfos[0].signature;
    if (!sig) throw new Error('missing signer signature');
    const at = findSigPos(signed, sig);
    if (at < 0) throw new Error('signature bytes not found in cms payload');
    const tampered = new Uint8Array(signed);
    tampered[at + sig.length - 1] ^= 0x01;
    CMS.verify(tampered, { ...okOpts, checkSignatures: false });
    throws(() => CMS.verify(tampered, { ...okOpts, checkSignatures: true }));
  });
  should('requires chain to terminate at supplied trust anchors (RFC 5280 section 6)', () => {
    const tpl = getEdnsJiyaTpl();
    const { cert, key, root } = getCertKeyRoot();
    const wrongRoot = pem('openssl/ca-root2.pem');
    const signed = CMS.sign(tpl, cert, key, root, { createdTs: CERT_CREATED });
    throws(
      () => CMS.verify(signed, { time: CERT_CREATED, chain: [wrongRoot], checkSignatures: true }),
      /certificate chain does not terminate at a supplied trust anchor/
    );
    const rootDer = certDersFromVector('openssl/p384-root.pem')[0];
    const forgedRoot = CERTUtils.Certificate.decode(rootDer);
    forgedRoot.tbs.spki.publicKey = new Uint8Array(forgedRoot.tbs.spki.publicKey);
    forgedRoot.tbs.spki.publicKey[forgedRoot.tbs.spki.publicKey.length - 1] ^= 1;
    const forgedRootDer = CERTUtils.Certificate.encode(forgedRoot);
    throws(
      () =>
        CMS.verify(signed, { time: CERT_CREATED, chain: [forgedRootDer], checkSignatures: true }),
      /certificate chain does not terminate at a supplied trust anchor/
    );
    CMS.verify(signed, { time: CERT_CREATED, chain: [root], checkSignatures: true });
  });
  should('verifies certificate signatures along the chain (RFC 5280 section 6.1.3)', () => {
    const tpl = getEdnsJiyaTpl();
    const { cert, key, root } = getCertKeyRoot();
    const signed = CMS.sign(tpl, cert, key, root, { createdTs: CERT_CREATED });
    const c = CMS.decode(signed);
    const sd = __TEST.CMSSignedData.decode(c.content);
    const sid = sd.signerInfos[0].sid;
    if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
    const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
    const signerCert = (sd.certificates || []).find(
      (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
        i.TAG === 'certificate' &&
        i.data.tbs.serial === sid.data.serial &&
        equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
    );
    if (!signerCert) throw new Error('signer cert not found');
    const badSig = new Uint8Array(signerCert.data.sig);
    badSig[badSig.length - 1] ^= 1;
    signerCert.data.sig = badSig;
    c.content = __TEST.CMSSignedData.encode(sd);
    c.ber = undefined;
    const tampered = CMS.encode(c);
    CMS.verify(tampered, { time: CERT_CREATED, chain: [root], checkSignatures: false });
    throws(
      () => CMS.verify(tampered, { time: CERT_CREATED, chain: [root], checkSignatures: true }),
      /certificate signature invalid/
    );
  });
  should('accepts non-critical CA basicConstraints during path validation', () => {
    const tpl = getEdnsJiyaTpl();
    const { cert, key, root } = getCertKeyRoot();
    const signed = CMS.sign(tpl, cert, key, root, { createdTs: CERT_CREATED });
    const c = CMS.decode(signed);
    const sd = __TEST.CMSSignedData.decode(c.content);
    const sid = sd.signerInfos[0]?.sid;
    if (!sid || sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
    const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
    const signerCert = (sd.certificates || []).find(
      (i) =>
        i.TAG === 'certificate' &&
        i.data.tbs.serial === sid.data.serial &&
        equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
    );
    if (!signerCert || signerCert.TAG !== 'certificate') throw new Error('signer cert not found');
    const issuerName = CERTUtils.Name.encode(signerCert.data.tbs.issuer);
    const issuerCert = (sd.certificates || []).find(
      (i) =>
        i.TAG === 'certificate' && equalBytes(CERTUtils.Name.encode(i.data.tbs.subject), issuerName)
    );
    if (!issuerCert || issuerCert.TAG !== 'certificate') throw new Error('issuer cert not found');
    const removeBasicCritical = (item: typeof issuerCert.data) => {
      const basic = item.tbs.extensions?.list.find((e) => e.oid === 'basicConstraints');
      if (!basic) throw new Error('expected basicConstraints extension');
      deepStrictEqual(basic.rest.slice(0, 3), Uint8Array.from([0x01, 0x01, 0xff]));
      basic.rest = basic.rest.slice(3);
    };
    removeBasicCritical(issuerCert.data);
    const rootCert = CERTUtils.Certificate.decode(certDersFromVector('openssl/p384-root.pem')[0]);
    removeBasicCritical(rootCert);
    c.content = __TEST.CMSSignedData.encode(sd);
    c.ber = undefined;
    const verified = CMS.verify(CMS.encode(c), {
      time: CERT_CREATED,
      chain: [CERTUtils.Certificate.encode(rootCert)],
      checkSignatures: true,
    });
    // RFC 5280 section 4.2.1.9's criticality MUST is for conforming CA
    // generation; verifier path validation in section 6.1.4(k) accepts cA=true.
    deepStrictEqual(verified.chain.length, 2);
  });
  should('prefers valid issuer when multiple subject-matching issuer candidates exist', () => {
    const { root } = getCertKeyRoot();
    const c = decodeP384Cert();
    const sd = __TEST.CMSSignedData.decode(c.content);
    const sid = sd.signerInfos[0]?.sid;
    if (!sid || sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
    const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
    const signerCert = (sd.certificates || []).find(
      (i) =>
        i.TAG === 'certificate' &&
        i.data.tbs.serial === sid.data.serial &&
        equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
    );
    if (!signerCert) throw new Error('signer cert not found');
    const issuerName = CERTUtils.Name.encode(signerCert.data.tbs.issuer);
    const issuerCert = (sd.certificates || []).find(
      (i) =>
        i.TAG === 'certificate' && equalBytes(CERTUtils.Name.encode(i.data.tbs.subject), issuerName)
    );
    if (!issuerCert || issuerCert.TAG !== 'certificate') throw new Error('issuer cert not found');
    const badIssuer = structuredClone(issuerCert);
    const pk = badIssuer.data.tbs.spki.publicKey;
    if (!pk.length) throw new Error('issuer public key missing');
    pk[pk.length - 1] ^= 1;
    if (!sd.certificates) throw new Error('certificate set missing');
    const issuerPos = sd.certificates.indexOf(issuerCert);
    if (issuerPos < 0) throw new Error('issuer cert index not found');
    sd.certificates.splice(issuerPos, 0, badIssuer);
    c.content = __TEST.CMSSignedData.encode(sd);
    c.ber = undefined;
    CMS.verify(CMS.encode(c), { time: CERT_CREATED, chain: [root], checkSignatures: true });
  });
  should('does not collapse distinct issuer certs that share subject/serial/spki', () => {
    const { root } = getCertKeyRoot();
    const c = decodeP384Cert();
    const sd = __TEST.CMSSignedData.decode(c.content);
    const sid = sd.signerInfos[0]?.sid;
    if (!sid || sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
    const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
    const signerCert = (sd.certificates || []).find(
      (i) =>
        i.TAG === 'certificate' &&
        i.data.tbs.serial === sid.data.serial &&
        equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
    );
    if (!signerCert) throw new Error('signer cert not found');
    const issuerName = CERTUtils.Name.encode(signerCert.data.tbs.issuer);
    const issuerCert = (sd.certificates || []).find(
      (i) =>
        i.TAG === 'certificate' && equalBytes(CERTUtils.Name.encode(i.data.tbs.subject), issuerName)
    );
    if (!issuerCert || issuerCert.TAG !== 'certificate') throw new Error('issuer cert not found');
    const variantIssuer = structuredClone(issuerCert);
    const sig = variantIssuer.data.sig;
    if (!sig.length) throw new Error('issuer signature missing');
    sig[sig.length - 1] ^= 1;
    if (!sd.certificates) throw new Error('certificate set missing');
    sd.certificates.push(variantIssuer);
    c.content = __TEST.CMSSignedData.encode(sd);
    c.ber = undefined;
    throws(
      () =>
        CMS.verify(CMS.encode(c), { time: CERT_CREATED, chain: [root], checkSignatures: false }),
      /multiple issuer certificates/
    );
  });
  should('without trust anchors, verify returns partial chain when top issuer is missing', () => {
    const c = decodeP384Cert();
    const sd = __TEST.CMSSignedData.decode(c.content);
    const sid = sd.signerInfos[0].sid;
    if (sid.TAG !== 'issuerSerial') throw new Error('expected issuerSerial sid');
    const sidIssuer = CERTUtils.Name.encode(sid.data.issuer);
    const signerCert = (sd.certificates || []).find(
      (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
        i.TAG === 'certificate' &&
        i.data.tbs.serial === sid.data.serial &&
        equalBytes(CERTUtils.Name.encode(i.data.tbs.issuer), sidIssuer)
    );
    if (!signerCert) throw new Error('signer cert not found');
    const issuerCert = (sd.certificates || []).find(
      (i): i is Extract<NonNullable<typeof sd.certificates>[number], { TAG: 'certificate' }> =>
        i.TAG === 'certificate' &&
        equalBytes(
          CERTUtils.Name.encode(i.data.tbs.subject),
          CERTUtils.Name.encode(signerCert.data.tbs.issuer)
        )
    );
    if (!issuerCert) throw new Error('issuer cert not found');
    issuerCert.data.tbs.issuer = {
      rdns: [[{ oid: 'commonName', value: { TAG: 'utf8', data: 'missing-issuer' } }]],
    };
    c.content = __TEST.CMSSignedData.encode(sd);
    c.ber = undefined;
    const out = CMS.verify(CMS.encode(c), {
      time: CERT_CREATED,
      chain: [],
      checkSignatures: true,
    });
    deepStrictEqual(out.chain.length, 2);
  });
  should(
    'verify rejects detached/attached content mismatch via messageDigest attr (RFC 5652 section 5.4)',
    () => {
      const tpl = getEdnsJiyaTpl();
      const { cert, key, root } = getCertKeyRoot();
      const signed = CMS.sign(tpl, cert, key, root);
      const d = CMS.detach(signed);
      const bad = new Uint8Array(d.content);
      bad[bad.length - 1] ^= 1;
      const rebuilt = CMS.attach(d.signature, bad);
      throws(
        () => CMS.verify(rebuilt, { time: CERT_CREATED, chain: [root], checkSignatures: true }),
        /messageDigest attribute does not match eContent/
      );
    }
  );
  should('verify rejects signatures over implicit signedAttrs bytes (RFC 5652 section 5.4)', () => {
    const tpl = getEdnsJiyaTpl();
    const cert = pem('openssl/client-ed25519-cert.pem');
    const key = pem('openssl/client-ed25519-key.pem');
    const der = CMS.sign(tpl, cert, key, '', { createdTs: CERT_CREATED });
    const ci = CMS.decode(der);
    const sd = __TEST.CMSSignedData.decode(ci.content);
    const ber = DERUtils.BER.decode(ci.content);
    const signedAttrs = berTlvAt(ber.nodes, [0, 4, 0, 3]);
    const pkcs8 = DERUtils.PKCS8.decode(pemBlocks(key)[0].der);
    if (pkcs8.privateKey.TAG !== 'raw') throw new Error('expected Ed25519 PKCS#8 private key');
    const si = sd.signerInfos[0];
    si.signature = ed25519.sign(
      ci.content.subarray(signedAttrs.pos, signedAttrs.end),
      pkcs8.privateKey.data
    );
    ci.content = __TEST.CMSSignedData.encode(sd);
    ci.ber = undefined;
    throws(
      () => CMS.verify(CMS.encode(ci), { time: CERT_CREATED, checkSignatures: true }),
      /CMS signature invalid/
    );
  });
  should('attach and verifyDetached reject signature that already has eContent', () => {
    const tpl = getEdnsJiyaTpl();
    const { cert, key, root } = getCertKeyRoot();
    const attached = CMS.sign(tpl, cert, key, root);
    throws(
      () => CMS.attach(attached, tpl),
      /CMS\.attach expects detached signature with absent eContent/
    );
    throws(
      () =>
        CMS.verifyDetached(attached, tpl, {
          time: CERT_CREATED,
          chain: [root],
          checkSignatures: true,
        }),
      /CMS\.attach expects detached signature with absent eContent/
    );
  });
  should('detach rejects CMS that is already detached (no eContent)', () => {
    const tpl = getEdnsJiyaTpl();
    const { cert, key, root } = getCertKeyRoot();
    const attached = CMS.sign(tpl, cert, key, root);
    const detached = CMS.detach(attached).signature;
    throws(() => CMS.detach(detached), /CMS\.detach expects attached CMS with present eContent/);
  });
  should('verify with signature checks rejects detached CMS without external content', () => {
    const tpl = getEdnsJiyaTpl();
    const { cert, key, root } = getCertKeyRoot();
    const attached = CMS.sign(tpl, cert, key, root);
    const detached = CMS.detach(attached).signature;
    throws(
      () => CMS.verify(detached, { time: CERT_CREATED, chain: [root], checkSignatures: true }),
      /CMS\.verify\(\{checkSignatures:true\}\) requires attached eContent; use CMS\.verifyDetached/
    );
  });
  should('verify rejects content-type attr mismatch vs eContentType (RFC 5652 section 5.6)', () => {
    const tpl = getEdnsJiyaTpl();
    const { cert, key, root } = getCertKeyRoot();
    const signed = CMS.sign(tpl, cert, key, root);
    const ci = CMS.decode(signed);
    const bad = new Uint8Array(ci.content);
    const idDataOID = Uint8Array.from([
      0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
    ]);
    const at = findSigPos(bad, idDataOID);
    if (at < 0) throw new Error('id-data OID not found');
    bad[at + idDataOID.length - 1] = 0x02;
    let patchedVersion = false;
    for (let i = 0; i + 2 < bad.length; i++) {
      if (bad[i] === 0x02 && bad[i + 1] === 0x01 && bad[i + 2] === 0x01) {
        bad[i + 2] = 0x03;
        patchedVersion = true;
        break;
      }
    }
    if (!patchedVersion) throw new Error('SignedData.version INTEGER not found');
    ci.content = bad;
    throws(
      () =>
        CMS.verify(CMS.encode(ci), { time: CERT_CREATED, chain: [root], checkSignatures: true }),
      /content-type attribute does not match encapContentInfo\.eContentType/
    );
  });
  should('validation mode still enforces signedAttrs semantics (RFC 5652 sections 5.4/5.6)', () => {
    const tpl = getEdnsJiyaTpl();
    const { cert, key, root } = getCertKeyRoot();
    const signed = CMS.sign(tpl, cert, key, root);
    const d = CMS.detach(signed);
    const bad = new Uint8Array(d.content);
    bad[bad.length - 1] ^= 1;
    const rebuilt = CMS.attach(d.signature, bad);
    throws(
      () => CMS.verify(rebuilt, { time: CERT_CREATED, chain: [root], checkSignatures: false }),
      /messageDigest attribute does not match eContent/
    );
  });
  should('validation is deterministic by explicit at timestamp', () => {
    const tpl = getEdnsJiyaTpl();
    const certPem = pem('openssl/p384-server-cert.pem');
    const keyPem = pem('openssl/p384-server-key.pem');
    const rootPem = pem('openssl/p384-root.pem');
    const certDer = pemBlocks(certPem)[0].der;
    const cert = X509.decode(certDer);
    const signed = CMS.sign(tpl, certPem, keyPem, rootPem);
    const notBefore = certTime(cert.tbs.validity.notBefore);
    const notAfter = certTime(cert.tbs.validity.notAfter);
    const inside = Math.floor((notBefore + notAfter) / 2) * 1000;
    const before = (notBefore - 1) * 1000;
    CMS.verify(signed, { time: inside, chain: [rootPem], checkSignatures: false });
    CMS.verify(signed, { time: inside, chain: [rootPem], checkSignatures: true });
    throws(
      () => CMS.verify(signed, { time: before, chain: [rootPem], checkSignatures: false }),
      /signer certificate outside validity window/
    );
    throws(
      () => CMS.verify(signed, { time: before, chain: [rootPem], checkSignatures: true }),
      /signer certificate outside validity window/
    );
  });
  should('verify requires integer time in milliseconds', () => {
    const tpl = getEdnsJiyaTpl();
    const { cert, key, root } = getCertKeyRoot();
    const signed = CMS.sign(tpl, cert, key, root);
    throws(
      () => CMS.verify(signed, { time: 1760000000000.5, chain: [root], checkSignatures: false }),
      /expected safe integer time in milliseconds/
    );
  });
  should('rsa vectors are explicitly unsupported in verify', () => {
    const cms = VECTORS.filter(
      (v) => !v.error && v.rsa && (v.kind === 'cms' || v.kind === 'cms-pem' || v.kind === 'cms-eml')
    );
    for (const v of cms) {
      const der =
        v.kind === 'cms-eml'
          ? readSigFromEml(v.name)
          : v.kind === 'cms-pem'
            ? oneCmsFromPem(v.name)
            : cmsFromVector(v.name);
      const ci = CMS.decode(der, v.ber ? { allowBER: true } : undefined);
      if (ci.contentType !== '1.2.840.113549.1.7.2') continue;
      throws(() =>
        CMS.verify(der, {
          time: CERT_CREATED,
          allowBER: v.ber ? true : undefined,
          checkSignatures: true,
        })
      );
    }
  });
  should('validation mode enforces signedAttrs semantics for RSA CMS too', () => {
    const der = read(EDNS_OLD);
    const c = CMS.decode(der, { allowBER: true });
    const sd = __TEST.CMSSignedData.decode(c.content);
    const si = sd.signerInfos[0];
    const ct = (si.signedAttrs || []).find((a) => a.oid === 'attrContentType');
    if (!ct) throw new Error('content-type attribute not found');
    ct.values = [
      Uint8Array.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]),
    ];
    c.content = __TEST.CMSSignedData.encode(sd);
    throws(
      () =>
        CMS.verify(CMS.encode(c), {
          time: CERT_CREATED,
          allowBER: true,
          checkSignatures: false,
        }),
      /content-type attribute does not match encapContentInfo\.eContentType/
    );
  });
  should('ec sign verify roundtrip matrix', () => {
    const tpl = getEdnsJiyaTpl();
    const signers = [
      {
        cert: pem('openssl/p256-server-cert.pem'),
        key: pem('openssl/p256-server-key.pem'),
        chain: pem('openssl/p384-root.pem'),
        time: CERT_CREATED,
      },
      {
        cert: pem('openssl/p384-server-cert.pem'),
        key: pem('openssl/p384-server-key.pem'),
        chain: pem('openssl/p384-root.pem'),
        time: CERT_CREATED,
      },
    ];
    for (const s of signers) {
      const out = CMS.sign(tpl, s.cert, s.key, s.chain);
      CMS.verify(out, { time: s.time, chain: [s.chain], checkSignatures: false });
      CMS.verify(out, { time: s.time, chain: [s.chain], checkSignatures: true });
    }
  });
  should('compact build(compact.sign) is byte-equal to CMS.sign (default attrs)', () => {
    const tpl = getEdnsJiyaTpl();
    const { cert, key, root } = getCertKeyRoot();
    const sig = CMS.compact.sign(tpl, cert, key, { extraEntropy: false });
    const signed = CMS.compact.build(tpl, sig, cert, root);
    const expected = CMS.sign(tpl, cert, key, root, { extraEntropy: false });
    deepStrictEqual(signed, expected);
    deepStrictEqual(CMS.signed(signed).signerInfos[0].signature, sig);
    CMS.verify(signed, { time: CERT_CREATED, chain: [root], checkSignatures: true });
  });
  should('compact build rejects malformed compact signature bytes', () => {
    const tpl = getEdnsJiyaTpl();
    const { cert, root } = getCertKeyRoot();
    throws(
      () => CMS.compact.build(tpl, Uint8Array.from([1, 2, 3]), cert, root),
      /invalid ECDSA DER signature integer length|tlv|TLV|expected/
    );
  });
  should('compact sign rejects Ed25519 PKCS#8 whose optional publicKey masks a bad seed', () => {
    const tpl = getEdnsJiyaTpl();
    const cert = pem('openssl/client-ed25519-cert.pem');
    const key = pem('openssl/client-ed25519-key.pem');
    const certObj = X509.decode(pemBlocks(cert)[0].der);
    const pkcs8 = DERUtils.PKCS8.decode(pemBlocks(key)[0].der);
    if (pkcs8.algorithm.info.TAG !== 'Ed25519' || pkcs8.privateKey.TAG !== 'raw')
      throw new Error('expected raw Ed25519 PKCS#8 private key');
    const secret = pkcs8.privateKey.data.slice();
    secret[0] ^= 1;
    const der = DERUtils.PKCS8.encode({
      ...pkcs8,
      version: 1n,
      privateKey: { TAG: 'raw', data: secret },
      publicKey: certObj.tbs.spki.publicKey,
    });
    const lines = base64.encode(der).match(/.{1,64}/g);
    if (!lines) throw new Error('base64 line wrap failed');
    const badKey = `-----BEGIN PRIVATE KEY-----\n${lines.join('\n')}\n-----END PRIVATE KEY-----\n`;
    throws(() => CMS.compact.sign(tpl, cert, badKey), /certificate and private key do not match/);
  });
  should('compact build(compact.sign) is byte-equal to CMS.sign (with createdTs)', () => {
    const tpl = getEdnsJiyaTpl();
    const { cert, key, root } = getCertKeyRoot();
    const createdTs = CERT_CREATED;
    const sig = CMS.compact.sign(tpl, cert, key, { createdTs: createdTs, extraEntropy: false });
    const signed = CMS.compact.build(tpl, sig, cert, root, { createdTs: createdTs });
    const expected = CMS.sign(tpl, cert, key, root, {
      createdTs: createdTs,
      extraEntropy: false,
    });
    deepStrictEqual(signed, expected);
    CMS.verify(signed, { time: createdTs, chain: [root], checkSignatures: true });
  });
  should('sign/signDetached support compact attrs+algorithm options', () => {
    const tpl = getEdnsJiyaTpl();
    const cert = pem('openssl/p256-server-cert.pem');
    const key = pem('openssl/p256-server-key.pem');
    const root = pem('openssl/p384-root.pem');
    const opts = {
      createdTs: CERT_CREATED,
      extraEntropy: false as const,
      smimeCapabilities: ['aes256-cbc', 'aes192-cbc', 'aes128-cbc'],
      messageDigest: Uint8Array.from(Array.from({ length: 32 }, (_, i) => i + 1)),
      digestAlgorithm: '2.16.840.1.101.3.4.2.1',
      signatureAlgorithm: '1.2.840.10045.4.3.2',
    };
    const sig = CMS.compact.sign(tpl, cert, key, opts);
    const built = CMS.compact.build(tpl, sig, cert, root, opts);
    deepStrictEqual(CMS.sign(tpl, cert, key, root, opts), built);
    deepStrictEqual(CMS.signDetached(tpl, cert, key, root, opts), CMS.detach(built).signature);
  });
  should('rejects S/MIME capabilities that require parameters when only OID is provided', () => {
    const tpl = getEdnsJiyaTpl();
    const { cert, key, root } = getCertKeyRoot();
    const smimeValue = (capability: string) => {
      const der = CMS.sign(tpl, cert, key, root, {
        createdTs: CERT_CREATED,
        extraEntropy: false,
        smimeCapabilities: [capability],
      });
      const signed = CMS.signed(der);
      const attr = signed.signerInfos[0].signedAttrs?.find(
        (a) => a.oid === 'attrSMIMECapabilities'
      );
      if (!attr || !attr.values[0]) throw new Error('missing sMIMECapabilities attr');
      return attr.values[0];
    };
    deepStrictEqual(
      smimeValue('2.16.840.1.101.3.4.1.42'),
      hexToBytes('300d300b060960864801650304012a')
    );
    deepStrictEqual(
      smimeValue(' 2.16.840.1.101.3.4.1.42 '),
      hexToBytes('300d300b060960864801650304012a')
    );
    throws(() => smimeValue('rc2-cbc'), /rc2-cbc|parameters/i);
    throws(() => smimeValue('1.2.840.113549.3.2'), /1\.2\.840\.113549\.3\.2|parameters/i);
    // RFC 3278 section 7 and RFC 5990 section 2.4 also require capability
    // parameters for these raw OIDs; this string-only helper cannot emit them.
    throws(() => smimeValue('1.3.133.16.840.63.0.2'), /1\.3\.133\.16\.840\.63\.0\.2|parameters/i);
    throws(() => smimeValue('1.3.133.16.840.63.0.3'), /1\.3\.133\.16\.840\.63\.0\.3|parameters/i);
    throws(() => smimeValue('1.3.133.16.840.63.0.16'), /1\.3\.133\.16\.840\.63\.0\.16|parameters/i);
    throws(
      () => smimeValue('1.2.840.113549.1.9.16.3.14'),
      /1\.2\.840\.113549\.1\.9\.16\.3\.14|parameters/i
    );
  });
  should(
    'compact sign/build support SHA-224 digestAlgorithm override (RFC 5754 section 2.1)',
    () => {
      const tpl = getEdnsJiyaTpl();
      const cert = pem('openssl/p256-server-cert.pem');
      const key = pem('openssl/p256-server-key.pem');
      const root = pem('openssl/p384-root.pem');
      const opts = { digestAlgorithm: 'sha224', extraEntropy: false as const };
      const sig = CMS.compact.sign(tpl, cert, key, opts);
      const built = CMS.compact.build(tpl, sig, cert, root, opts);
      // compact.build validates ECDSA DER shape before assembling CMS metadata,
      // so use a real compact signature while exercising the build-only option path.
      const byName = CMS.compact.build(tpl, sig, cert, root, {
        digestAlgorithm: 'sha224',
      });
      const byOID = CMS.compact.build(tpl, sig, cert, root, {
        digestAlgorithm: rawOid('sha224'),
      });
      const view = (der: Uint8Array) => {
        const signed = CMS.signed(der);
        return {
          digestAlgorithms: signed.digestAlgorithms,
          signerDigest: signed.signerInfos[0].digestAlg,
          signatureAlg: signed.signerInfos[0].signatureAlg,
        };
      };
      deepStrictEqual(
        { built: view(built), byName: view(byName), byOID: view(byOID) },
        {
          built: {
            digestAlgorithms: [{ algorithm: 'sha224', params: undefined }],
            signerDigest: { algorithm: 'sha224', params: undefined },
            signatureAlg: { algorithm: 'ecdsa-with-SHA224', params: undefined },
          },
          byName: {
            digestAlgorithms: [{ algorithm: 'sha224', params: undefined }],
            signerDigest: { algorithm: 'sha224', params: undefined },
            signatureAlg: { algorithm: 'ecdsa-with-SHA224', params: undefined },
          },
          byOID: {
            digestAlgorithms: [{ algorithm: 'sha224', params: undefined }],
            signerDigest: { algorithm: 'sha224', params: undefined },
            signatureAlg: { algorithm: 'ecdsa-with-SHA224', params: undefined },
          },
        }
      );
      CMS.verify(built, { time: CERT_CREATED, chain: [root], checkSignatures: true });
    }
  );
  should('ECDSA SHA-224 algorithm aliases match RFC 5754 OIDs', () => {
    const tpl = getEdnsJiyaTpl();
    const cert = pem('openssl/p256-server-cert.pem');
    const key = pem('openssl/p256-server-key.pem');
    const root = pem('openssl/p384-root.pem');
    const sig = CMS.compact.sign(tpl, cert, key, {
      digestAlgorithm: 'sha224',
      extraEntropy: false,
    });
    const opts = { digestAlgorithm: 'sha224' };
    const raw = CMS.signed(
      CMS.compact.build(tpl, sig, cert, root, {
        ...opts,
        signatureAlgorithm: '1.2.840.10045.4.3.1',
      })
    ).signerInfos[0].signatureAlg;
    const named = CMS.signed(
      CMS.compact.build(tpl, sig, cert, root, {
        ...opts,
        signatureAlgorithm: 'ecdsa-with-SHA224',
      })
    ).signerInfos[0].signatureAlg;
    deepStrictEqual(
      { raw, named },
      {
        raw: { algorithm: 'ecdsa-with-SHA224', params: undefined },
        named: { algorithm: 'ecdsa-with-SHA224', params: undefined },
      }
    );
    CMS.verify(CMS.compact.build(tpl, sig, cert, root, { ...opts }), {
      time: CERT_CREATED,
      chain: [root],
      checkSignatures: true,
    });
  });
  should('SMIME capability parser covers all vector-seen capability OIDs', () => {
    const seen = new Set<string>();
    const covered = new Set<string>([
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
    const decodeCaps = DERUtils.ASN1.sequence({
      list: P.array(
        null,
        DERUtils.ASN1.sequence({
          capabilityID: DERUtils.ASN1.OID,
          paramsAny: P.bytes(null),
        })
      ),
    });
    for (const v of VECTORS) {
      if (v.error) continue;
      if (v.kind !== 'cms' && v.kind !== 'cms-pem' && v.kind !== 'cms-eml') continue;
      const der =
        v.kind === 'cms-eml'
          ? readSigFromEml(v.name)
          : v.kind === 'cms-pem'
            ? oneCmsFromPem(v.name)
            : cmsFromVector(v.name);
      if (CMS.contentType(der, { allowBER: v.ber ? true : undefined }) !== 'signedData') continue;
      const signed = CMS.signed(der, { allowBER: v.ber ? true : undefined });
      for (const si of signed.signerInfos || [])
        for (const a of si.signedAttrs || []) {
          if (a.oid !== 'attrSMIMECapabilities') continue;
          for (const c of decodeCaps.decode(a.values[0]).list) seen.add(c.capabilityID);
        }
    }
    for (const id of seen) deepStrictEqual(covered.has(id), true);
  });
  should('vectors with validBefore pass before and fail after boundary', () => {
    const timed = VECTORS.filter((v) => !v.error && v.validBefore);
    for (const v of timed) {
      const der =
        v.kind === 'cms-eml'
          ? readSigFromEml(v.name)
          : v.kind === 'cms-pem'
            ? oneCmsFromPem(v.name)
            : cmsFromVector(v.name);
      const before = ((v.validBefore as number) - 1) * 1000;
      const after = ((v.validBefore as number) + 1) * 1000;
      CMS.verify(der, { time: before, allowBER: v.ber ? true : undefined, checkSignatures: false });
      throws(
        () =>
          CMS.verify(der, {
            time: after,
            allowBER: v.ber ? true : undefined,
            checkSignatures: false,
          }),
        /certificate outside validity window|certificate not valid at time/
      );
    }
  });
  describe('ip address', () => {
    should('generic IPv4 parser roundtrip and rejects invalid inputs', () => {
      const ok = ['0.0.0.0', '1.2.3.4', '127.0.0.1', '255.255.255.255'];
      for (const ip of ok) {
        const b1 = __TEST.IPv4.encode(ip);
        const s = __TEST.IPv4.decode(b1);
        const b2 = __TEST.IPv4.encode(s);
        deepStrictEqual(b2, b1);
      }
      const bad = [
        '256.0.0.1',
        '1.2.3',
        '1.2.3.4.5',
        'a.b.c.d',
        '-1.2.3.4',
        '01.02.03',
        '01.2.3.4',
        '001.002.003.004',
      ];
      for (const ip of bad) throws(() => __TEST.IPv4.encode(ip));
    });
    should('generic IPv6 parser roundtrip and rejects invalid inputs', () => {
      const ok = [
        '::',
        '::1',
        '2001:db8::1',
        '::ffff:192.0.2.1',
        '2001:db8::192.0.2.1',
        '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
      ];
      for (const ip of ok) {
        const b1 = __TEST.IPv6.encode(ip);
        const s = __TEST.IPv6.decode(b1);
        const b2 = __TEST.IPv6.encode(s);
        deepStrictEqual(b2, b1);
      }
      const bad = [
        ':::1',
        '2001::db8::1',
        '2001:db8',
        '2001:db8:zzzz::1',
        '1.2.3.4',
        '::ffff:001.002.003.004',
        '2001:db8:0:0:0:0:0:0:1',
        ':1:2:3:4:5:6:7:8',
        '1:2:3:4:5:6:7:8:',
        ':2001:db8::1',
        '2001:db8::1:',
      ];
      for (const ip of bad) throws(() => __TEST.IPv6.encode(ip));
    });
  });
  describe('asn1 strings', () => {
    should('PrintableString validates character set', () => {
      deepStrictEqual(
        __TEST.PrintableString.decode(__TEST.PrintableString.encode("A-Z 0/9'+=?")),
        "A-Z 0/9'+=?"
      );
      throws(() => __TEST.PrintableString.encode('under_score'));
      throws(() => __TEST.PrintableString.encode('cafe\u00E9'));
    });
    should('NumericString validates character set', () => {
      deepStrictEqual(
        __TEST.NumericString.decode(__TEST.NumericString.encode('123 456 7890')),
        '123 456 7890'
      );
      throws(() => __TEST.NumericString.encode('12A3'));
      throws(() => __TEST.NumericString.encode('12-3'));
    });
    should('TeletexString rejects non-latin1 characters', () => {
      deepStrictEqual(
        __TEST.TeletexString.decode(__TEST.TeletexString.encode('caf\u00E9')),
        'caf\u00E9'
      );
      throws(() => __TEST.TeletexString.encode('\u20AC'));
    });
    should('X509.encode rejects malformed UTF-16 in UTF8String values', () => {
      const cert = X509.decode(certDersFromVector('openssl/fake-gp.pem')[0]);
      cert.tbs.subject.rdns[0][0].value = { TAG: 'utf8', data: 'A\u{1F600}' };
      const encoded = X509.encode(cert);
      deepStrictEqual(X509.decode(encoded).tbs.subject.rdns[0][0].value, {
        TAG: 'utf8',
        data: 'A\u{1F600}',
      });
      cert.tbs.subject.rdns[0][0].value = { TAG: 'utf8', data: '\uD800' };
      throws(() => X509.encode(cert), /utf8 expected well-formed string/);
    });
    should('X509.encode rejects BMPString values outside the Basic Multilingual Plane', () => {
      const cert = X509.decode(certDersFromVector('openssl/fake-gp.pem')[0]);
      cert.tbs.subject.rdns[0][0].value = { TAG: 'bmp', data: 'A\u2603' };
      const encoded = X509.encode(cert);
      deepStrictEqual(X509.decode(encoded).tbs.subject.rdns[0][0].value, {
        TAG: 'bmp',
        data: 'A\u2603',
      });
      cert.tbs.subject.rdns[0][0].value = { TAG: 'bmp', data: 'A\u{1F600}' };
      throws(() => X509.encode(cert), /BMPString|Basic Multilingual Plane|surrogate/i);
    });
    should('X509.decode accepts RFC 5280 UniversalString commonName values', () => {
      const universalCN = hexToBytes(
        '3082012f3081e2a00302010202143ee39c0286eeed43006f2c6d66dce4133789957c300506032b6570300c310a300806035504030c0141301e170d3236303431363233353930325a170d3236303431373233353930325a300f310d300b06035504031c0400000041302a300506032b65700321006a49c999d4c14eb4e10893aa46ed6202c81472ea29bc4bd8ea015e316999abcfa3533051301d0603551d0e04160414943dcd01f649df0cd0e62a2f0c55296c18cc5f7e301f0603551d23041830168014943dcd01f649df0cd0e62a2f0c55296c18cc5f7e300f0603551d130101ff040530030101ff300506032b6570034100476186c95341f535156677af510d2a5b7a01acd7d791baca60cd10fd093ab06cdd963a15a2b746b6ef24a9339ce436ff1334c30b972d6eada756996578da660b'
      );
      deepStrictEqual(X509.decode(universalCN).tbs.subject.rdns, [
        [{ oid: 'commonName', value: { TAG: 'universal', data: 'A' } }],
      ]);
    });
    should('X509.decode preserves non-string AttributeValue as raw TLV', () => {
      // RFC 5280 section 4.1.2.4 defines AttributeValue as ANY DEFINED BY AttributeType.
      const rawAttr = hexToBytes(
        '3082012f3081e2a00302010202143ee39c0286eeed43006f2c6d66dce4133789957c300506032b6570300c310a300806035504030c0141301e170d3236303431363233353930325a170d3236303431373233353930325a300f310d300b060355046a06042a030405302a300506032b65700321006a49c999d4c14eb4e10893aa46ed6202c81472ea29bc4bd8ea015e316999abcfa3533051301d0603551d0e04160414943dcd01f649df0cd0e62a2f0c55296c18cc5f7e301f0603551d23041830168014943dcd01f649df0cd0e62a2f0c55296c18cc5f7e300f0603551d130101ff040530030101ff300506032b6570034100476186c95341f535156677af510d2a5b7a01acd7d791baca60cd10fd093ab06cdd963a15a2b746b6ef24a9339ce436ff1334c30b972d6eada756996578da660b'
      );
      const cert = X509.decode(rawAttr);
      deepStrictEqual(cert.tbs.subject.rdns, [
        [
          {
            oid: 'objectIdentifier',
            value: { TAG: 'raw', data: { tag: 0x06, valueHex: '2a030405' } },
          },
        ],
      ]);
      deepStrictEqual(X509.encode(cert), rawAttr);
    });
    should('UniversalString maps UCS-4 scalars to JS strings and rejects invalid scalars', () => {
      const text = 'A\u{1F600}';
      const der = Uint8Array.from([0x1c, 0x08, 0x00, 0x00, 0x00, 0x41, 0x00, 0x01, 0xf6, 0x00]);
      deepStrictEqual(__TEST.UniversalString.encode(text), der);
      deepStrictEqual(__TEST.UniversalString.decode(der), text);
      throws(
        () => __TEST.UniversalString.decode(Uint8Array.from([0x1c, 0x04, 0x00, 0x11, 0x00, 0x00])),
        /UniversalString: expected Unicode scalar/
      );
      throws(
        () => __TEST.UniversalString.decode(Uint8Array.from([0x1c, 0x04, 0x00, 0x00, 0xd8, 0x00])),
        /UniversalString: expected Unicode scalar/
      );
      throws(
        () => __TEST.UniversalString.encode('\uD800'),
        /UniversalString: expected Unicode scalar/
      );
    });
  });
  describe('x509 time', () => {
    const derTime = (tag: 0x17 | 0x18, text: string): Uint8Array => {
      const b = new TextEncoder().encode(text);
      return Uint8Array.from([tag, b.length, ...b]);
    };
    const utcTs = (y: number, mo: number, d: number, h: number, mi: number, s: number): number => {
      const date = new Date(0);
      date.setUTCFullYear(y, mo, d);
      date.setUTCHours(h, mi, s, 0);
      return Math.floor(date.getTime() / 1000);
    };
    should('encodes timestamp as UTCTime in 1950..2049 and GeneralizedTime otherwise', () => {
      const utcTs = Math.floor(Date.UTC(2026, 0, 2, 3, 4, 5) / 1000);
      const genTs = Math.floor(Date.UTC(2050, 0, 1, 0, 0, 0) / 1000);
      const utcDer = __TEST.X509Time.encode(utcTs);
      const genDer = __TEST.X509Time.encode(genTs);
      deepStrictEqual(utcDer[0], 0x17);
      deepStrictEqual(genDer[0], 0x18);
    });
    should('roundtrips timestamp through DER time', () => {
      const vals = [
        Math.floor(Date.UTC(1999, 11, 31, 23, 59, 59) / 1000),
        Math.floor(Date.UTC(2026, 0, 2, 3, 4, 5) / 1000),
        Math.floor(Date.UTC(2050, 0, 1, 0, 0, 0) / 1000),
      ];
      for (const ts of vals)
        deepStrictEqual(__TEST.X509Time.decode(__TEST.X509Time.encode(ts)), ts);
    });
    should('rejects encoding years outside the GeneralizedTime YYYY range', () => {
      const y0 = utcTs(0, 0, 1, 0, 0, 0);
      deepStrictEqual(__TEST.X509Time.encode(y0), derTime(0x18, '00000101000000Z'));
      deepStrictEqual(__TEST.X509Time.decode(derTime(0x18, '00000101000000Z')), y0);
      throws(() => __TEST.X509Time.encode(utcTs(-1, 0, 1, 0, 0, 0)), /GeneralizedTime|YYYY|0000/);
      throws(
        () => __TEST.X509Time.encode(utcTs(10000, 0, 1, 0, 0, 0)),
        /GeneralizedTime|YYYY|0000/
      );
    });
    should('rejects invalid calendar/range values in UTCTime and GeneralizedTime', () => {
      const bad = [
        derTime(0x17, '260101240000Z'),
        derTime(0x17, '260101006000Z'),
        derTime(0x17, '260101000060Z'),
        derTime(0x17, '261301000000Z'),
        derTime(0x17, '260231000000Z'),
        derTime(0x18, '20260230000000Z'),
      ];
      for (const v of bad) throws(() => __TEST.X509Time.decode(v));
    });
  });
});

should.runWhen(import.meta.url);

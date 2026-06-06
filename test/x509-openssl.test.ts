import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual, throws } from 'node:assert';
import { execFileSync } from 'node:child_process';
import * as P from 'micro-packed';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ASN1 } from '../src/asn1.ts';
import { CMS, __TEST } from '../src/x509.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.join(__dirname, 'vectors', 'certs');

const EDNS_OLD = 'encrypted-dns/cloudflare-https-old.mobileconfig';
const EDNS_JIYA = 'encrypted-dns/cloudflare-https-jiya.mobileconfig';
const EDNS_JIYA_VALID_AT = 1773000000;
// const EDNS_JIYA_DER = 'encrypted-dns/cloudflare-signer-jiya.der';

const read = (name: string): Uint8Array => new Uint8Array(fs.readFileSync(path.join(ROOT, name)));
const bytesEq = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((v, i) => v === b[i]);
const opensslEnv = (home: string) => {
  const { OPENSSL_CONF, RANDFILE, SSL_CERT_DIR, SSL_CERT_FILE, ...env } = process.env;
  return {
    ...env,
    HOME: home,
    OPENSSL_CONF: path.join(home, 'openssl.cnf'),
    RANDFILE: path.join(home, '.rnd'),
  };
};
const openssl = (home: string, args: string[]): Uint8Array => {
  fs.writeFileSync(path.join(home, 'openssl.cnf'), '');
  return new Uint8Array(
    execFileSync('openssl', args, { env: opensslEnv(home), stdio: ['ignore', 'pipe', 'pipe'] })
  );
};
const tmp = <T>(fn: (dir: string) => T): T => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mkp-openssl-'));
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
};
const explicitPkcs8 = (keyPem: string): string =>
  tmp((dir) => {
    const src = path.join(dir, 'named-key.pem');
    const sec1 = path.join(dir, 'explicit-sec1.pem');
    const out = path.join(dir, 'explicit-key.pem');
    fs.writeFileSync(src, keyPem);
    openssl(dir, ['ec', '-in', src, '-param_enc', 'explicit', '-out', sec1]);
    openssl(dir, ['pkcs8', '-topk8', '-nocrypt', '-in', sec1, '-out', out]);
    return fs.readFileSync(out, 'utf8');
  });
const parseSigningTime = (attr: Uint8Array): number => {
  if (attr.length < 2) throw new Error('signingTime attr too short');
  let t = attr[0];
  let l = attr[1];
  let at = 2;
  if (t === 0x31) {
    if (attr.length < 4) throw new Error('signingTime attr SET too short');
    t = attr[2];
    l = attr[3];
    at = 4;
  }
  const raw = new TextDecoder().decode(attr.slice(at, at + l));
  if (t === 0x17) {
    const yy = Number(raw.slice(0, 2));
    const year = yy >= 50 ? 1900 + yy : 2000 + yy;
    const mo = Number(raw.slice(2, 4));
    const d = Number(raw.slice(4, 6));
    const h = Number(raw.slice(6, 8));
    const mi = Number(raw.slice(8, 10));
    const s = Number(raw.slice(10, 12));
    return Date.UTC(year, mo - 1, d, h, mi, s);
  }
  if (t === 0x18) {
    const year = Number(raw.slice(0, 4));
    const mo = Number(raw.slice(4, 6));
    const d = Number(raw.slice(6, 8));
    const h = Number(raw.slice(8, 10));
    const mi = Number(raw.slice(10, 12));
    const s = Number(raw.slice(12, 14));
    return Date.UTC(year, mo - 1, d, h, mi, s);
  }
  throw new Error(`signingTime attr: expected UTCTime/GeneralizedTime, got 0x${t.toString(16)}`);
};
const cmsOpenSSL = (
  opts:
    | {
        mode: 'verify';
        cmsDer: Uint8Array;
        caPem?: string;
        certPem?: string;
        content?: Uint8Array;
        attime?: number;
      }
    | {
        mode: 'sign';
        content: Uint8Array;
        certPem: string;
        keyPem: string;
        chainPem?: string;
        detached: boolean;
        binary?: boolean;
        smimecap?: boolean;
        noattr?: boolean;
        nocerts?: boolean;
        noSigningTime?: boolean;
        stream?: boolean;
        deterministic?: boolean;
        md?: string;
        keyid?: boolean;
        cades?: boolean;
      }
): Uint8Array =>
  tmp((dir) => {
    const outFile = path.join(dir, 'out.der');
    if (opts.mode === 'verify') {
      const cmsFile = path.join(dir, 'msg.der');
      fs.writeFileSync(cmsFile, opts.cmsDer);
      const verifyOut = path.join(dir, 'out.bin');
      const contentFile = opts.content ? path.join(dir, 'content.bin') : undefined;
      if (contentFile) fs.writeFileSync(contentFile, opts.content);
      const caFile = opts.caPem ? path.join(dir, 'ca.pem') : undefined;
      if (caFile) fs.writeFileSync(caFile, opts.caPem);
      const certFile = opts.certPem ? path.join(dir, 'cert.pem') : undefined;
      if (certFile) fs.writeFileSync(certFile, opts.certPem);
      const args = [
        'cms',
        '-verify',
        ...(opts.content ? ['-binary'] : []),
        '-inform',
        'DER',
        '-in',
        cmsFile,
        ...(contentFile ? ['-content', contentFile] : []),
        ...(caFile ? ['-CAfile', caFile] : []),
        ...(certFile ? ['-certfile', certFile] : []),
        ...(opts.attime === undefined ? [] : ['-attime', `${opts.attime}`]),
        '-purpose',
        'any',
        '-out',
        verifyOut,
      ];
      openssl(dir, args);
      return new Uint8Array(fs.readFileSync(verifyOut));
    }
    const inFile = path.join(dir, 'in.bin');
    const certFile = path.join(dir, 'cert.pem');
    const keyFile = path.join(dir, 'key.pem');
    fs.writeFileSync(inFile, opts.content);
    fs.writeFileSync(certFile, opts.certPem);
    fs.writeFileSync(keyFile, opts.keyPem);
    const args = [
      'cms',
      '-sign',
      ...(opts.binary === false ? [] : ['-binary']),
      ...(opts.smimecap === true ? [] : ['-nosmimecap']),
      ...(opts.noattr ? ['-noattr'] : []),
      ...(opts.nocerts ? ['-nocerts'] : []),
      ...(opts.noSigningTime ? ['-no_signing_time'] : []),
      ...(opts.stream ? ['-stream'] : []),
      ...(opts.keyid ? ['-keyid'] : []),
      ...(opts.cades ? ['-cades'] : []),
      ...(opts.detached ? [] : ['-nodetach']),
      '-outform',
      'DER',
      '-in',
      inFile,
      '-signer',
      certFile,
      '-inkey',
      keyFile,
      ...(opts.chainPem ? ['-certfile', path.join(dir, 'chain.pem')] : []),
      '-out',
      outFile,
    ];
    if (opts.chainPem) fs.writeFileSync(path.join(dir, 'chain.pem'), opts.chainPem);
    if (opts.deterministic) args.push('-keyopt', 'nonce-type:1');
    if (opts.md) args.push('-md', opts.md);
    openssl(dir, args);
    return new Uint8Array(fs.readFileSync(outFile));
  });
type OpenSSLFixtures = {
  root: string;
  wrong: string;
  edRoot: string;
  ed448Root: string;
  caSigner: { cert: string; key: string };
  p256: { cert: string; key: string };
  p384: { cert: string; key: string };
  p521: { cert: string; key: string };
  bp256: { cert: string; key: string };
  bp384: { cert: string; key: string };
  bp512: { cert: string; key: string };
  ed25519: { cert: string; key: string };
  ed448: { cert: string; key: string };
};
const genOpenSSLFixtures = (): OpenSSLFixtures =>
  tmp((dir) => {
    const genRoot = (
      name: string,
      spec:
        | {
            alg: 'EC';
            curve:
              | 'P-256'
              | 'P-384'
              | 'P-521'
              | 'brainpoolP256r1'
              | 'brainpoolP384r1'
              | 'brainpoolP512r1';
          }
        | { alg: 'ED25519' | 'ED448' }
    ): { cert: string; key: string } => {
      const key = path.join(dir, `${name}-root-key.pem`);
      const cert = path.join(dir, `${name}-root-cert.pem`);
      if (spec.alg === 'EC')
        openssl(dir, [
          'genpkey',
          '-algorithm',
          'EC',
          '-pkeyopt',
          `ec_paramgen_curve:${spec.curve}`,
          '-out',
          key,
        ]);
      else openssl(dir, ['genpkey', '-algorithm', spec.alg, '-out', key]);
      openssl(dir, [
        'req',
        '-x509',
        '-new',
        '-key',
        key,
        '-subj',
        `/CN=${name} Root CA`,
        '-sha256',
        '-days',
        '3650',
        '-out',
        cert,
        '-addext',
        'basicConstraints=critical,CA:TRUE,pathlen:1',
        '-addext',
        'keyUsage=critical,keyCertSign,cRLSign',
      ]);
      return { cert: fs.readFileSync(cert, 'utf8'), key: fs.readFileSync(key, 'utf8') };
    };
    const genCaSigner = (name: string): { cert: string; key: string } => {
      const key = path.join(dir, `${name}-ca-signer-key.pem`);
      const cert = path.join(dir, `${name}-ca-signer-cert.pem`);
      openssl(dir, [
        'genpkey',
        '-algorithm',
        'EC',
        '-pkeyopt',
        'ec_paramgen_curve:P-256',
        '-out',
        key,
      ]);
      openssl(dir, [
        'req',
        '-x509',
        '-new',
        '-key',
        key,
        '-subj',
        `/CN=${name} CA CMS Signer`,
        '-sha256',
        '-days',
        '3650',
        '-out',
        cert,
        '-addext',
        'basicConstraints=critical,CA:TRUE,pathlen:0',
        '-addext',
        'keyUsage=critical,digitalSignature,keyCertSign',
      ]);
      return { cert: fs.readFileSync(cert, 'utf8'), key: fs.readFileSync(key, 'utf8') };
    };
    const genLeaf = (
      name: string,
      spec:
        | {
            alg: 'EC';
            curve:
              | 'P-256'
              | 'P-384'
              | 'P-521'
              | 'brainpoolP256r1'
              | 'brainpoolP384r1'
              | 'brainpoolP512r1';
          }
        | { alg: 'ED25519' | 'ED448' },
      ca: { cert: string; key: string }
    ): { cert: string; key: string } => {
      const key = path.join(dir, `${name}-leaf-key.pem`);
      const csr = path.join(dir, `${name}-leaf.csr`);
      const cert = path.join(dir, `${name}-leaf-cert.pem`);
      const caFile = path.join(dir, `${name}-ca.pem`);
      const caKey = path.join(dir, `${name}-ca-key.pem`);
      const ext = path.join(dir, `${name}-leaf.ext`);
      fs.writeFileSync(caFile, ca.cert);
      fs.writeFileSync(caKey, ca.key);
      fs.writeFileSync(
        ext,
        [
          'basicConstraints=critical,CA:FALSE',
          'keyUsage=critical,digitalSignature',
          'subjectKeyIdentifier=hash',
          'authorityKeyIdentifier=keyid',
        ].join('\n')
      );
      if (spec.alg === 'EC')
        openssl(dir, [
          'genpkey',
          '-algorithm',
          'EC',
          '-pkeyopt',
          `ec_paramgen_curve:${spec.curve}`,
          '-out',
          key,
        ]);
      else openssl(dir, ['genpkey', '-algorithm', spec.alg, '-out', key]);
      openssl(dir, ['req', '-new', '-key', key, '-subj', `/CN=${name} Leaf`, '-out', csr]);
      openssl(dir, [
        'x509',
        '-req',
        '-in',
        csr,
        '-CA',
        caFile,
        '-CAkey',
        caKey,
        '-CAcreateserial',
        '-out',
        cert,
        '-days',
        '3650',
        '-sha256',
        '-extfile',
        ext,
      ]);
      return { cert: fs.readFileSync(cert, 'utf8'), key: fs.readFileSync(key, 'utf8') };
    };
    const root = genRoot('mkp-p384', { alg: 'EC', curve: 'P-384' });
    const wrong = genRoot('mkp-wrong', { alg: 'EC', curve: 'P-256' });
    const caSigner = genCaSigner('mkp-p256');
    const p256 = genLeaf('mkp-p256', { alg: 'EC', curve: 'P-256' }, root);
    const p384 = genLeaf('mkp-p384', { alg: 'EC', curve: 'P-384' }, root);
    const p521 = genLeaf('mkp-p521', { alg: 'EC', curve: 'P-521' }, root);
    const bp256 = genLeaf('mkp-bp256', { alg: 'EC', curve: 'brainpoolP256r1' }, root);
    const bp384 = genLeaf('mkp-bp384', { alg: 'EC', curve: 'brainpoolP384r1' }, root);
    const bp512 = genLeaf('mkp-bp512', { alg: 'EC', curve: 'brainpoolP512r1' }, root);
    const edRoot = genRoot('mkp-ed25519', { alg: 'ED25519' });
    const ed448Root = genRoot('mkp-ed448', { alg: 'ED448' });
    const ed25519 = genLeaf('mkp-ed25519', { alg: 'ED25519' }, edRoot);
    const ed448 = genLeaf('mkp-ed448', { alg: 'ED448' }, ed448Root);
    return {
      root: root.cert,
      wrong: wrong.cert,
      edRoot: edRoot.cert,
      ed448Root: ed448Root.cert,
      caSigner,
      p256,
      p384,
      p521,
      bp256,
      bp384,
      bp512,
      ed25519,
      ed448,
    };
  });
const fixtures = genOpenSSLFixtures();
// Generated OpenSSL certs use the current time as notBefore, so a fixed
// historical verification timestamp eventually falls outside their validity.
const FIXTURE_TIME = Date.now();

describe('x509 openssl', () => {
  should('openssl accepts generated p256 and p384 signatures and returns original content', () => {
    const root = fixtures.root;
    const base = CMS.signed(read(EDNS_JIYA)).encapContentInfo.eContent || new Uint8Array();
    const alt =
      CMS.signed(read(EDNS_OLD), { allowBER: true }).encapContentInfo.eContent || new Uint8Array();
    const p256Cert = fixtures.p256.cert;
    const p256Key = fixtures.p256.key;
    const p384Cert = fixtures.p384.cert;
    const p384Key = fixtures.p384.key;
    const templates = [
      { tpl: base, expected: base },
      { tpl: alt, expected: alt },
    ] as const;
    for (const file of templates) {
      const tpl = file.tpl;
      const expected = file.expected;
      const p256 = CMS.sign(tpl, p256Cert, p256Key, root);
      const p384 = CMS.sign(tpl, p384Cert, p384Key, root);
      const out256 = cmsOpenSSL({ mode: 'verify', cmsDer: p256, caPem: root });
      const out384 = cmsOpenSSL({ mode: 'verify', cmsDer: p384, caPem: root });
      deepStrictEqual(out256, out384);
      deepStrictEqual(out256, expected);
    }
  });
  should('openssl rejects generated signature with wrong CA', () => {
    const tpl = CMS.signed(read(EDNS_JIYA)).encapContentInfo.eContent || new Uint8Array();
    const root = fixtures.root;
    const wrong = fixtures.wrong;
    const p384 = CMS.sign(tpl, fixtures.p384.cert, fixtures.p384.key, root);
    throws(() => cmsOpenSSL({ mode: 'verify', cmsDer: p384, caPem: wrong }));
  });
  should('openssl rejects generated signature without CAfile', () => {
    const tpl = CMS.signed(read(EDNS_JIYA)).encapContentInfo.eContent || new Uint8Array();
    const root = fixtures.root;
    const p384 = CMS.sign(tpl, fixtures.p384.cert, fixtures.p384.key, root);
    throws(() => cmsOpenSSL({ mode: 'verify', cmsDer: p384 }));
  });
  should('accepts OpenSSL CMS signed by a CA cert when keyUsage permits message signing', () => {
    const content = CMS.signed(read(EDNS_JIYA)).encapContentInfo.eContent || new Uint8Array();
    const signed = cmsOpenSSL({
      mode: 'sign',
      content,
      certPem: fixtures.caSigner.cert,
      keyPem: fixtures.caSigner.key,
      detached: false,
      md: 'sha256',
    });
    deepStrictEqual(
      cmsOpenSSL({ mode: 'verify', cmsDer: signed, caPem: fixtures.caSigner.cert }),
      content
    );
    CMS.verify(signed, {
      time: FIXTURE_TIME,
      chain: [fixtures.caSigner.cert],
      checkSignatures: true,
    });
  });
  should('detach verify attach works for existing ecdsa mobileconfig', () => {
    const src = read(EDNS_JIYA);
    const detached = CMS.detach(src);
    const detachedOut = cmsOpenSSL({
      mode: 'verify',
      cmsDer: detached.signature,
      content: detached.content,
      // The checked-in mobileconfig certificate expires; pin OpenSSL to the same valid time used by local CMS.verify below.
      attime: EDNS_JIYA_VALID_AT,
    });
    deepStrictEqual(detachedOut, detached.content);
    const rebuilt = CMS.attach(detached.signature, detached.content);
    deepStrictEqual(rebuilt, src);
    CMS.verifyDetached(detached.signature, detached.content, {
      // This case validates detach/attach roundtrip only; strict chain-continuity is covered in x509.test.ts.
      checkSignatures: false,
      time: 1773000000000,
    });
  });
  should('openssl detached and local detached both use absent eContent', () => {
    const content = CMS.signed(read(EDNS_JIYA)).encapContentInfo.eContent || new Uint8Array();
    const cert = fixtures.p256.cert;
    const key = fixtures.p256.key;
    const chain = fixtures.root;
    const opensslDetached = cmsOpenSSL({
      mode: 'sign',
      content,
      certPem: cert,
      keyPem: key,
      chainPem: chain,
      detached: true,
      deterministic: true,
    });
    const signingTimeAttr = (CMS.signed(opensslDetached).signerInfos[0].signedAttrs || []).find(
      (a) => a.oid === 'attrSigningTime'
    );
    if (!signingTimeAttr) throw new Error('openssl signedAttrs missing signingTime');
    const createdTs = parseSigningTime(signingTimeAttr.values[0]);
    const localAttached = CMS.sign(content, cert, key, chain, { createdTs, extraEntropy: false });
    const localDetached = CMS.detach(localAttached);
    deepStrictEqual(CMS.signed(opensslDetached).encapContentInfo.eContent, undefined);
    deepStrictEqual(CMS.signed(localDetached.signature).encapContentInfo.eContent, undefined);
    const sigOpenSSL = CMS.signed(opensslDetached).signerInfos[0].signature;
    const sigLocal = CMS.signed(localDetached.signature).signerInfos[0].signature;
    deepStrictEqual(sigLocal, sigOpenSSL);
    deepStrictEqual(
      cmsOpenSSL({ mode: 'verify', cmsDer: localDetached.signature, content, caPem: chain }),
      content
    );
  });
  should('openssl ecdsa signing is non-deterministic byte-wise (detached and attached)', () => {
    const content = CMS.signed(read(EDNS_JIYA)).encapContentInfo.eContent || new Uint8Array();
    const cert = fixtures.p256.cert;
    const key = fixtures.p256.key;
    const chain = fixtures.root;
    const d1 = cmsOpenSSL({
      mode: 'sign',
      content,
      certPem: cert,
      keyPem: key,
      chainPem: chain,
      detached: true,
    });
    const d2 = cmsOpenSSL({
      mode: 'sign',
      content,
      certPem: cert,
      keyPem: key,
      chainPem: chain,
      detached: true,
    });
    const a1 = cmsOpenSSL({
      mode: 'sign',
      content,
      certPem: cert,
      keyPem: key,
      chainPem: chain,
      detached: false,
    });
    const a2 = cmsOpenSSL({
      mode: 'sign',
      content,
      certPem: cert,
      keyPem: key,
      chainPem: chain,
      detached: false,
    });
    deepStrictEqual(bytesEq(d1, d2), false);
    deepStrictEqual(bytesEq(a1, a2), false);
  });
  should(
    'openssl nonce-type:1 matches local signature bytes with signedAttrs when createdTs is aligned',
    () => {
      const content = CMS.signed(read(EDNS_JIYA)).encapContentInfo.eContent || new Uint8Array();
      const cert = fixtures.p256.cert;
      const key = fixtures.p256.key;
      const chain = fixtures.root;
      const openssl = cmsOpenSSL({
        mode: 'sign',
        content,
        certPem: cert,
        keyPem: key,
        chainPem: chain,
        detached: false,
        deterministic: true,
      });
      const parsed = CMS.signed(openssl);
      const signingTimeAttr = (parsed.signerInfos[0].signedAttrs || []).find(
        (a) => a.oid === 'attrSigningTime'
      );
      if (!signingTimeAttr) throw new Error('openssl signedAttrs missing signingTime');
      const createdTs = parseSigningTime(signingTimeAttr.values[0]);
      const local = CMS.sign(content, cert, key, chain, { createdTs, extraEntropy: false });
      const sigOssl = CMS.signed(openssl).signerInfos[0].signature;
      const sigLocal = CMS.signed(local).signerInfos[0].signature;
      deepStrictEqual(sigLocal, sigOssl);
    }
  );
  should('byte-for-byte parity: signedAttrs signatures for all supported EC curves', () => {
    const content = CMS.signed(read(EDNS_JIYA)).encapContentInfo.eContent || new Uint8Array();
    const cases = [
      { cert: fixtures.p256.cert, key: fixtures.p256.key, chain: fixtures.root, md: 'sha256' },
      { cert: fixtures.p384.cert, key: fixtures.p384.key, chain: fixtures.root, md: 'sha384' },
      { cert: fixtures.p521.cert, key: fixtures.p521.key, chain: fixtures.root, md: 'sha512' },
      { cert: fixtures.bp256.cert, key: fixtures.bp256.key, chain: fixtures.root, md: 'sha256' },
      { cert: fixtures.bp384.cert, key: fixtures.bp384.key, chain: fixtures.root, md: 'sha384' },
      { cert: fixtures.bp512.cert, key: fixtures.bp512.key, chain: fixtures.root, md: 'sha512' },
    ] as const;
    for (const c of cases) {
      const openssl = cmsOpenSSL({
        mode: 'sign',
        content,
        certPem: c.cert,
        keyPem: c.key,
        chainPem: c.chain,
        detached: false,
        deterministic: true,
        md: c.md,
      });
      const parsed = CMS.signed(openssl);
      const signingTimeAttr = (parsed.signerInfos[0].signedAttrs || []).find(
        (a) => a.oid === 'attrSigningTime'
      );
      if (!signingTimeAttr) throw new Error('openssl signedAttrs missing signingTime');
      const createdTs = parseSigningTime(signingTimeAttr.values[0]);
      const local = CMS.sign(content, c.cert, c.key, c.chain, { createdTs, extraEntropy: false });
      deepStrictEqual(
        CMS.signed(local).signerInfos[0].signature,
        CMS.signed(openssl).signerInfos[0].signature
      );
      deepStrictEqual(cmsOpenSSL({ mode: 'verify', cmsDer: local, caPem: c.chain }), content);
      CMS.verify(local, { checkSignatures: true, time: createdTs, chain: [c.chain] });
    }
  });
  should(
    'byte-for-byte parity: Ed25519 signatures with signedAttrs when createdTs is aligned',
    () => {
      const content = CMS.signed(read(EDNS_JIYA)).encapContentInfo.eContent || new Uint8Array();
      const c = { cert: fixtures.ed25519.cert, key: fixtures.ed25519.key, chain: fixtures.edRoot };
      const openssl = cmsOpenSSL({
        mode: 'sign',
        content,
        certPem: c.cert,
        keyPem: c.key,
        chainPem: c.chain,
        detached: false,
        md: 'sha512',
      });
      const parsed = CMS.signed(openssl);
      const signingTimeAttr = (parsed.signerInfos[0].signedAttrs || []).find(
        (a) => a.oid === 'attrSigningTime'
      );
      if (!signingTimeAttr) throw new Error('openssl signedAttrs missing signingTime');
      const createdTs = parseSigningTime(signingTimeAttr.values[0]);
      const local = CMS.sign(content, c.cert, c.key, c.chain, { createdTs });
      deepStrictEqual(
        CMS.signed(local).signerInfos[0].signature,
        CMS.signed(openssl).signerInfos[0].signature
      );
      deepStrictEqual(cmsOpenSSL({ mode: 'verify', cmsDer: local, caPem: c.chain }), content);
      CMS.verify(local, { checkSignatures: true, time: createdTs, chain: [c.chain] });
    }
  );
  should('documents OpenSSL Ed448 CMS digest mismatch with RFC 8419 signedAttrs', () => {
    const content = CMS.signed(read(EDNS_JIYA)).encapContentInfo.eContent || new Uint8Array();
    const c = { cert: fixtures.ed448.cert, key: fixtures.ed448.key, chain: fixtures.ed448Root };
    // RFC 8419 section 3.1 requires Ed448 signedAttrs to use id-shake256-len
    // with INTEGER 512 params; OpenSSL 3.5.4 has no Ed448 CMS default digest.
    throws(() =>
      cmsOpenSSL({
        mode: 'sign',
        content,
        certPem: c.cert,
        keyPem: c.key,
        chainPem: c.chain,
        detached: false,
      })
    );
    const sha512 = cmsOpenSSL({
      mode: 'sign',
      content,
      certPem: c.cert,
      keyPem: c.key,
      chainPem: c.chain,
      detached: false,
      md: 'sha512',
    });
    const shake = cmsOpenSSL({
      mode: 'sign',
      content,
      certPem: c.cert,
      keyPem: c.key,
      chainPem: c.chain,
      detached: false,
      md: 'shake256',
    });
    deepStrictEqual(CMS.signed(sha512).signerInfos[0].digestAlg.algorithm, 'sha512');
    deepStrictEqual(CMS.signed(shake).signerInfos[0].digestAlg.algorithm, 'shake256');
    throws(
      () => CMS.verify(sha512, { checkSignatures: true, time: FIXTURE_TIME, chain: [c.chain] }),
      /Ed448 SignerInfo digestAlgorithm must be shake256_512.*got sha512/
    );
    throws(
      () => CMS.verify(shake, { checkSignatures: true, time: FIXTURE_TIME, chain: [c.chain] }),
      /Ed448 SignerInfo digestAlgorithm must be shake256_512.*got shake256/
    );
    const local = CMS.sign(content, c.cert, c.key, c.chain, { createdTs: FIXTURE_TIME });
    CMS.verify(local, { checkSignatures: true, time: FIXTURE_TIME, chain: [c.chain] });
    throws(
      () => cmsOpenSSL({ mode: 'verify', cmsDer: local, caPem: c.chain }),
      /unknown digest algorithm|unsupported/
    );
  });
  should('openssl and local signer are equivalent by verification for same inputs', () => {
    const root = fixtures.root;
    const content = CMS.signed(read(EDNS_JIYA)).encapContentInfo.eContent || new Uint8Array();
    const cert = fixtures.p256.cert;
    const key = fixtures.p256.key;
    const localAttached = CMS.sign(content, cert, key, root);
    const opensslAttached = cmsOpenSSL({
      mode: 'sign',
      content,
      certPem: cert,
      keyPem: key,
      chainPem: root,
      detached: false,
    });
    const opensslDetached = cmsOpenSSL({
      mode: 'sign',
      content,
      certPem: cert,
      keyPem: key,
      chainPem: root,
      detached: true,
    });
    deepStrictEqual(cmsOpenSSL({ mode: 'verify', cmsDer: localAttached, caPem: root }), content);
    deepStrictEqual(cmsOpenSSL({ mode: 'verify', cmsDer: opensslAttached, caPem: root }), content);
    deepStrictEqual(
      cmsOpenSSL({ mode: 'verify', cmsDer: opensslDetached, content, caPem: root }),
      content
    );
    CMS.verify(localAttached, { checkSignatures: true, time: FIXTURE_TIME, chain: [root] });
    CMS.verify(opensslAttached, { checkSignatures: true, time: FIXTURE_TIME, chain: [root] });
    CMS.verifyDetached(opensslDetached, content, {
      checkSignatures: true,
      time: FIXTURE_TIME,
      chain: [root],
    });
  });
  should('local parser verifies OpenSSL SHA-224 CMS with S/MIME capabilities', () => {
    const root = fixtures.root;
    const content = CMS.signed(read(EDNS_JIYA)).encapContentInfo.eContent || new Uint8Array();
    const openssl = cmsOpenSSL({
      mode: 'sign',
      content,
      certPem: fixtures.p256.cert,
      keyPem: fixtures.p256.key,
      chainPem: root,
      detached: false,
      deterministic: true,
      md: 'sha224',
      smimecap: true,
    });
    const parsed = CMS.signed(openssl);
    const smime = (parsed.signerInfos[0].signedAttrs || []).find(
      (a) => a.oid === 'attrSMIMECapabilities'
    );
    if (!smime) throw new Error('openssl signedAttrs missing sMIMECapabilities');
    const caps = ASN1.sequence({
      list: P.array(
        null,
        ASN1.sequence({
          capabilityID: ASN1.OID,
          paramsAny: P.bytes(null),
        })
      ),
    }).decode(smime.values[0]);
    CMS.verify(openssl, { checkSignatures: true, time: FIXTURE_TIME, chain: [root] });
    deepStrictEqual(
      {
        content: cmsOpenSSL({
          mode: 'verify',
          cmsDer: openssl,
          caPem: root,
        }),
        digest: parsed.signerInfos[0].digestAlg,
        signature: parsed.signerInfos[0].signatureAlg,
        smimeValues: smime.values.length,
        hasAes256Cbc: caps.list.some((c) => c.capabilityID === 'aes256-cbc'),
      },
      {
        content,
        digest: { algorithm: 'sha224', params: undefined },
        signature: { algorithm: 'ecdsa-with-SHA224', params: undefined },
        smimeValues: 1,
        hasAes256Cbc: true,
      }
    );
  });
  should('local verifier accepts OpenSSL id-data CMS without signedAttrs', () => {
    const root = fixtures.root;
    const content = CMS.signed(read(EDNS_JIYA)).encapContentInfo.eContent || new Uint8Array();
    const openssl = cmsOpenSSL({
      mode: 'sign',
      content,
      certPem: fixtures.p256.cert,
      keyPem: fixtures.p256.key,
      chainPem: root,
      detached: false,
      deterministic: true,
      md: 'sha256',
      noattr: true,
    });
    const parsed = CMS.signed(openssl);
    deepStrictEqual(
      {
        content: cmsOpenSSL({
          mode: 'verify',
          cmsDer: openssl,
          caPem: root,
        }),
        signedAttrs: CMS.verify(openssl, {
          checkSignatures: true,
          time: FIXTURE_TIME,
          chain: [root],
        }).signedAttrs,
        digest: parsed.signerInfos[0].digestAlg,
        attrs: parsed.signerInfos[0].signedAttrs,
      },
      {
        content,
        signedAttrs: false,
        digest: { algorithm: 'sha256', params: undefined },
        attrs: undefined,
      }
    );
  });
  should('local verifier accepts OpenSSL CMS signedAttrs without signingTime', () => {
    const root = fixtures.root;
    const content = CMS.signed(read(EDNS_JIYA)).encapContentInfo.eContent || new Uint8Array();
    const openssl = cmsOpenSSL({
      mode: 'sign',
      content,
      certPem: fixtures.p256.cert,
      keyPem: fixtures.p256.key,
      chainPem: root,
      detached: false,
      deterministic: true,
      md: 'sha256',
      noSigningTime: true,
    });
    const attrs = CMS.signed(openssl).signerInfos[0].signedAttrs || [];
    deepStrictEqual(
      {
        content: cmsOpenSSL({
          mode: 'verify',
          cmsDer: openssl,
          caPem: root,
        }),
        local: CMS.verify(openssl, {
          checkSignatures: true,
          time: FIXTURE_TIME,
          chain: [root],
        }).signedAttrs,
        signingTime: attrs.find((a) => a.oid === 'attrSigningTime'),
      },
      {
        content,
        local: true,
        signingTime: undefined,
      }
    );
  });
  should('local verifier accepts OpenSSL streaming BER CMS when BER is opted in', () => {
    const root = fixtures.root;
    const content = CMS.signed(read(EDNS_JIYA)).encapContentInfo.eContent || new Uint8Array();
    const openssl = cmsOpenSSL({
      mode: 'sign',
      content,
      certPem: fixtures.p256.cert,
      keyPem: fixtures.p256.key,
      chainPem: root,
      detached: true,
      md: 'sha256',
      stream: true,
    });
    throws(() => CMS.verify(openssl, { checkSignatures: true, time: FIXTURE_TIME, chain: [root] }));
    deepStrictEqual(
      {
        content: cmsOpenSSL({ mode: 'verify', cmsDer: openssl, caPem: root }),
        local: CMS.verify(openssl, {
          allowBER: true,
          checkSignatures: true,
          time: FIXTURE_TIME,
          chain: [root],
        }).signedAttrs,
      },
      {
        content,
        local: true,
      }
    );
  });
  should(
    'local verifier accepts OpenSSL CMS when signer certificate is supplied externally',
    () => {
      const root = fixtures.root;
      const content = CMS.signed(read(EDNS_JIYA)).encapContentInfo.eContent || new Uint8Array();
      const openssl = cmsOpenSSL({
        mode: 'sign',
        content,
        certPem: fixtures.p256.cert,
        keyPem: fixtures.p256.key,
        chainPem: root,
        detached: false,
        deterministic: true,
        md: 'sha256',
        nocerts: true,
      });
      const parsed = CMS.signed(openssl);
      const valid = CMS.verify(openssl, {
        checkSignatures: true,
        time: FIXTURE_TIME,
        chain: [fixtures.p256.cert, root],
      });
      deepStrictEqual(
        {
          certificateCount: parsed.certificates?.length,
          signerSubject: valid.signer.tbs.subject,
          chainLen: valid.chain.length,
        },
        {
          certificateCount: 1,
          signerSubject: CMS.verify(
            CMS.sign(content, fixtures.p256.cert, fixtures.p256.key, root),
            {
              checkSignatures: true,
              time: FIXTURE_TIME,
              chain: [root],
            }
          ).signer.tbs.subject,
          chainLen: 2,
        }
      );
    }
  );
  should('local verifier accepts OpenSSL subjectKeyIdentifier SignerIdentifier', () => {
    const root = fixtures.root;
    const content = CMS.signed(read(EDNS_JIYA)).encapContentInfo.eContent || new Uint8Array();
    const openssl = cmsOpenSSL({
      mode: 'sign',
      content,
      certPem: fixtures.p256.cert,
      keyPem: fixtures.p256.key,
      chainPem: root,
      detached: false,
      deterministic: true,
      md: 'sha256',
      keyid: true,
      nocerts: true,
    });
    const parsed = CMS.signed(openssl);
    const valid = CMS.verify(openssl, {
      checkSignatures: true,
      time: FIXTURE_TIME,
      chain: [fixtures.p256.cert, root],
    });
    deepStrictEqual(
      {
        content: cmsOpenSSL({
          mode: 'verify',
          cmsDer: openssl,
          caPem: root,
          certPem: fixtures.p256.cert,
        }),
        sid: parsed.signerInfos[0].sid.TAG,
        certCount: parsed.certificates?.length,
        signerSubject: valid.signer.tbs.subject,
      },
      {
        content,
        sid: 'subjectKeyIdentifier',
        certCount: 1,
        signerSubject: CMS.verify(CMS.sign(content, fixtures.p256.cert, fixtures.p256.key, root), {
          checkSignatures: true,
          time: FIXTURE_TIME,
          chain: [root],
        }).signer.tbs.subject,
      }
    );
  });
  should('local verifier accepts OpenSSL CAdES signingCertificateV2 signed attribute', () => {
    const root = fixtures.root;
    const content = CMS.signed(read(EDNS_JIYA)).encapContentInfo.eContent || new Uint8Array();
    const openssl = cmsOpenSSL({
      mode: 'sign',
      content,
      certPem: fixtures.p256.cert,
      keyPem: fixtures.p256.key,
      chainPem: root,
      detached: false,
      deterministic: true,
      md: 'sha256',
      cades: true,
    });
    const parsed = CMS.signed(openssl);
    const attrs = parsed.signerInfos[0].signedAttrs || [];
    CMS.verify(openssl, { checkSignatures: true, time: FIXTURE_TIME, chain: [root] });
    deepStrictEqual(
      {
        content: cmsOpenSSL({ mode: 'verify', cmsDer: openssl, caPem: root }),
        attrOids: attrs.map((a) => a.oid),
      },
      {
        content,
        attrOids: [
          'attrContentType',
          'attrSigningTime',
          'attrMessageDigest',
          '1.2.840.113549.1.9.16.2.47',
        ],
      }
    );
  });
  should('string input maps to OpenSSL text mode (no -binary), Uint8Array maps to -binary', () => {
    const cert = fixtures.p256.cert;
    const key = fixtures.p256.key;
    const chain = fixtures.root;
    const text = 'a\nb\n';
    const bytes = new TextEncoder().encode(text);
    const opensslText = cmsOpenSSL({
      mode: 'sign',
      content: bytes,
      certPem: cert,
      keyPem: key,
      chainPem: chain,
      detached: false,
      binary: false,
      smimecap: false,
      deterministic: true,
    });
    const opensslBinary = cmsOpenSSL({
      mode: 'sign',
      content: bytes,
      certPem: cert,
      keyPem: key,
      chainPem: chain,
      detached: false,
      binary: true,
      smimecap: false,
      deterministic: true,
    });
    const stText = (CMS.signed(opensslText).signerInfos[0].signedAttrs || []).find(
      (a) => a.oid === 'attrSigningTime'
    );
    const stBinary = (CMS.signed(opensslBinary).signerInfos[0].signedAttrs || []).find(
      (a) => a.oid === 'attrSigningTime'
    );
    if (!stText || !stBinary) throw new Error('openssl signedAttrs missing signingTime');
    const localText = CMS.sign(text, cert, key, chain, {
      createdTs: parseSigningTime(stText.values[0]),
      extraEntropy: false,
    });
    const localBinary = CMS.sign(bytes, cert, key, chain, {
      createdTs: parseSigningTime(stBinary.values[0]),
      extraEntropy: false,
    });
    deepStrictEqual(
      CMS.signed(localText).signerInfos[0].signature,
      CMS.signed(opensslText).signerInfos[0].signature
    );
    deepStrictEqual(
      CMS.signed(localBinary).signerInfos[0].signature,
      CMS.signed(opensslBinary).signerInfos[0].signature
    );
    deepStrictEqual(
      bytesEq(
        CMS.signed(localText).encapContentInfo.eContent || new Uint8Array(),
        new TextEncoder().encode('a\r\nb\r\n')
      ),
      true
    );
    deepStrictEqual(
      bytesEq(CMS.signed(localBinary).encapContentInfo.eContent || new Uint8Array(), bytes),
      true
    );
  });
  should(
    'mobileconfig parity: openssl verifies with system trust; local verifies structure without external chain',
    () => {
      const der = read(EDNS_JIYA);
      deepStrictEqual(
        cmsOpenSSL({ mode: 'verify', cmsDer: der, attime: EDNS_JIYA_VALID_AT }).length > 0,
        true
      );
      CMS.verify(der, { checkSignatures: false, time: 1773000000000 });
    }
  );
});

describe('x509 openssl explicit params', () => {
  should('runtime-generated supported keys interop when EC keys use explicit params', () => {
    const content = CMS.signed(read(EDNS_JIYA)).encapContentInfo.eContent || new Uint8Array();
    const cases = [
      {
        curve: 'P-256',
        cert: fixtures.p256.cert,
        keyPem: explicitPkcs8(fixtures.p256.key),
        chain: fixtures.root,
        md: 'sha256',
        deterministic: true,
      },
      {
        curve: 'P-384',
        cert: fixtures.p384.cert,
        keyPem: explicitPkcs8(fixtures.p384.key),
        chain: fixtures.root,
        md: 'sha384',
        deterministic: true,
      },
      {
        curve: 'P-521',
        cert: fixtures.p521.cert,
        keyPem: explicitPkcs8(fixtures.p521.key),
        chain: fixtures.root,
        md: 'sha512',
        deterministic: true,
      },
      {
        curve: 'brainpoolP256r1',
        cert: fixtures.bp256.cert,
        keyPem: explicitPkcs8(fixtures.bp256.key),
        chain: fixtures.root,
        md: 'sha256',
        deterministic: true,
      },
      {
        curve: 'brainpoolP384r1',
        cert: fixtures.bp384.cert,
        keyPem: explicitPkcs8(fixtures.bp384.key),
        chain: fixtures.root,
        md: 'sha384',
        deterministic: true,
      },
      {
        curve: 'brainpoolP512r1',
        cert: fixtures.bp512.cert,
        keyPem: explicitPkcs8(fixtures.bp512.key),
        chain: fixtures.root,
        md: 'sha512',
        deterministic: true,
      },
    ] as const;
    for (const c of cases) {
      deepStrictEqual(__TEST.keyCurve(c.keyPem), c.curve);
      const openssl = cmsOpenSSL({
        mode: 'sign',
        content,
        certPem: c.cert,
        keyPem: c.keyPem,
        chainPem: c.chain,
        detached: false,
        deterministic: c.deterministic,
        md: c.md,
      });
      const parsed = CMS.signed(openssl);
      const signingTimeAttr = (parsed.signerInfos[0].signedAttrs || []).find(
        (a) => a.oid === 'attrSigningTime'
      );
      if (!signingTimeAttr) throw new Error('openssl signedAttrs missing signingTime');
      const createdTs = parseSigningTime(signingTimeAttr.values[0]);
      const local = CMS.sign(content, c.cert, c.keyPem, c.chain, {
        createdTs,
        extraEntropy: false,
      });
      deepStrictEqual(
        CMS.signed(local).signerInfos[0].signature,
        CMS.signed(openssl).signerInfos[0].signature
      );
      deepStrictEqual(cmsOpenSSL({ mode: 'verify', cmsDer: local, caPem: c.chain }), content);
      CMS.verify(local, { checkSignatures: true, time: createdTs, chain: [c.chain] });
    }
  });
});

should.runWhen(import.meta.url);

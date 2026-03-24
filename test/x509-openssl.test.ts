import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual, throws } from 'node:assert';
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CMS } from '../src/x509.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.join(__dirname, 'vectors', 'certs');

const EDNS_OLD = 'encrypted-dns/cloudflare-https-old.mobileconfig';
const EDNS_JIYA = 'encrypted-dns/cloudflare-https-jiya.mobileconfig';
// const EDNS_JIYA_DER = 'encrypted-dns/cloudflare-signer-jiya.der';

const read = (name: string): Uint8Array => new Uint8Array(fs.readFileSync(path.join(ROOT, name)));
const bytesEq = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((v, i) => v === b[i]);
const openssl = (args: string[]): Uint8Array =>
  new Uint8Array(execFileSync('openssl', args, { stdio: ['ignore', 'pipe', 'pipe'] }));
const tmp = <T>(fn: (dir: string) => T): T => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mkp-openssl-'));
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
};
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
    | { mode: 'verify'; cmsDer: Uint8Array; caPem?: string; content?: Uint8Array }
    | {
        mode: 'sign';
        content: Uint8Array;
        certPem: string;
        keyPem: string;
        chainPem?: string;
        detached: boolean;
        binary?: boolean;
        smimecap?: boolean;
        deterministic?: boolean;
        md?: string;
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
        '-purpose',
        'any',
        '-out',
        verifyOut,
      ];
      openssl(args);
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
    openssl(args);
    return new Uint8Array(fs.readFileSync(outFile));
  });
type OpenSSLFixtures = {
  root: string;
  wrong: string;
  edRoot: string;
  ed448Root: string;
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
        openssl([
          'genpkey',
          '-algorithm',
          'EC',
          '-pkeyopt',
          `ec_paramgen_curve:${spec.curve}`,
          '-out',
          key,
        ]);
      else openssl(['genpkey', '-algorithm', spec.alg, '-out', key]);
      openssl([
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
        ['basicConstraints=critical,CA:FALSE', 'keyUsage=critical,digitalSignature'].join('\n')
      );
      if (spec.alg === 'EC')
        openssl([
          'genpkey',
          '-algorithm',
          'EC',
          '-pkeyopt',
          `ec_paramgen_curve:${spec.curve}`,
          '-out',
          key,
        ]);
      else openssl(['genpkey', '-algorithm', spec.alg, '-out', key]);
      openssl(['req', '-new', '-key', key, '-subj', `/CN=${name} Leaf`, '-out', csr]);
      openssl([
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
  should('detach verify attach works for existing ecdsa mobileconfig', () => {
    const src = read(EDNS_JIYA);
    const detached = CMS.detach(src);
    const detachedOut = cmsOpenSSL({
      mode: 'verify',
      cmsDer: detached.signature,
      content: detached.content,
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
      (a) => a.oid === '1.2.840.113549.1.9.5'
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
        (a) => a.oid === '1.2.840.113549.1.9.5'
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
        (a) => a.oid === '1.2.840.113549.1.9.5'
      );
      if (!signingTimeAttr) throw new Error('openssl signedAttrs missing signingTime');
      const createdTs = parseSigningTime(signingTimeAttr.values[0]);
      const local = CMS.sign(content, c.cert, c.key, c.chain, { createdTs, extraEntropy: false });
      deepStrictEqual(
        CMS.signed(local).signerInfos[0].signature,
        CMS.signed(openssl).signerInfos[0].signature
      );
      deepStrictEqual(cmsOpenSSL({ mode: 'verify', cmsDer: local, caPem: c.chain }), content);
      CMS.verify(local, { checkSignatures: true, time: 1773000000000, chain: [c.chain] });
    }
  });
  should(
    'byte-for-byte parity: Ed25519/Ed448 signatures with signedAttrs when createdTs is aligned',
    () => {
      const content = CMS.signed(read(EDNS_JIYA)).encapContentInfo.eContent || new Uint8Array();
      const cases = [
        { cert: fixtures.ed25519.cert, key: fixtures.ed25519.key, chain: fixtures.edRoot },
        { cert: fixtures.ed448.cert, key: fixtures.ed448.key, chain: fixtures.ed448Root },
      ] as const;
      for (const c of cases) {
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
          (a) => a.oid === '1.2.840.113549.1.9.5'
        );
        if (!signingTimeAttr) throw new Error('openssl signedAttrs missing signingTime');
        const createdTs = parseSigningTime(signingTimeAttr.values[0]);
        const local = CMS.sign(content, c.cert, c.key, c.chain, { createdTs });
        deepStrictEqual(
          CMS.signed(local).signerInfos[0].signature,
          CMS.signed(openssl).signerInfos[0].signature
        );
        deepStrictEqual(cmsOpenSSL({ mode: 'verify', cmsDer: local, caPem: c.chain }), content);
        CMS.verify(local, { checkSignatures: true, time: 1773000000000, chain: [c.chain] });
      }
    }
  );
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
    CMS.verify(localAttached, { checkSignatures: true, time: 1773000000000, chain: [root] });
    CMS.verify(opensslAttached, { checkSignatures: true, time: 1773000000000, chain: [root] });
    CMS.verifyDetached(opensslDetached, content, {
      checkSignatures: true,
      time: 1773000000000,
      chain: [root],
    });
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
      (a) => a.oid === '1.2.840.113549.1.9.5'
    );
    const stBinary = (CMS.signed(opensslBinary).signerInfos[0].signedAttrs || []).find(
      (a) => a.oid === '1.2.840.113549.1.9.5'
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
      deepStrictEqual(cmsOpenSSL({ mode: 'verify', cmsDer: der }).length > 0, true);
      CMS.verify(der, { checkSignatures: false, time: 1773000000000 });
    }
  );
});

should.runWhen(import.meta.url);

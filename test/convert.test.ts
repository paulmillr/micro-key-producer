import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { ed448, x448 } from '@noble/curves/ed448.js';
import { p256, p384, p521 } from '@noble/curves/nist.js';
import * as web from '@noble/curves/webcrypto.js';
import { describe, should } from '@paulmillr/jsbt/test.js';
import * as P from 'micro-packed';
import { deepStrictEqual, throws } from 'node:assert';
import * as convert from '../src/convert.ts';
import { base64armor } from '../src/utils.ts';
import { DER_VECTORS } from './convert-vectors.ts';

const CURVES = {
  p256: { lib: p256, web: web.p256, jwk: convert.p256_jwk, der: convert.p256_der },
  p384: { lib: p384, web: web.p384, jwk: convert.p384_jwk, der: convert.p384_der },
  p521: { lib: p521, web: web.p521, jwk: convert.p521_jwk, der: convert.p521_der },
  ed25519: { lib: ed25519, web: web.ed25519, jwk: convert.ed25519_jwk, der: convert.ed25519_der },
  x25519: { lib: x25519, web: web.x25519, jwk: convert.x25519_jwk, der: convert.x25519_der },
  ed448: { lib: ed448, web: web.ed448, jwk: convert.ed448_jwk, der: convert.ed448_der },
  x448: { lib: x448, web: web.x448, jwk: convert.x448_jwk, der: convert.x448_der },
};

describe('convert', () => {
  should('ASN.1', () => {
    const { ASN1, PKCS8, SPKI } = convert.DERUtils;
    for (const { name, type, pem, decoded, notImplemented, shouldFail } of DER_VECTORS) {
      const ARMOR = pem.split('\n')[0].replaceAll('-', '').replace('BEGIN ', '');
      const coder = base64armor(ARMOR, 10, P.bytes(null));
      const bytes = coder.decode(pem);
      const value = ASN1.debug.decode(bytes);
      if (ARMOR === 'PRIVATE KEY') {
        if (notImplemented || shouldFail) {
          throws(() => PKCS8.decode(bytes));
          continue;
        }
        if (decoded) deepStrictEqual(PKCS8.decode(bytes), decoded);
        deepStrictEqual(PKCS8.encode(PKCS8.decode(bytes)), bytes);
      } else if (ARMOR === 'PUBLIC KEY') {
        if (notImplemented || shouldFail) {
          throws(() => SPKI.decode(bytes));
          continue;
        }
        if (decoded) deepStrictEqual(SPKI.decode(bytes), decoded);
        deepStrictEqual(SPKI.encode(SPKI.decode(bytes)), bytes);
      }
    }
  });
  for (const name in CURVES) {
    if (['ed448', 'x448', 'x25519', 'ed25519'].includes(name) && process.versions.bun) continue;
    describe(name, () => {
      const { lib, web, jwk, der } = CURVES[name];
      const other = CURVES[name === 'p256' ? 'p384' : 'p256'];

      if (jwk) {
        should('jwk', async () => {
          const keys = lib.keygen();
          const pubUnc = lib.getPublicKey(keys.secretKey, false);
          deepStrictEqual(
            await web.utils.convertPublicKey(keys.publicKey, 'raw', 'jwk'),
            await web.utils.convertPublicKey(pubUnc, 'raw', 'jwk')
          );
          // Pub
          const jwkKey = await web.utils.convertPublicKey(keys.publicKey, 'raw', 'jwk');
          deepStrictEqual(jwk.publicKey.decode(jwkKey), keys.publicKey);
          deepStrictEqual(jwk.publicKey.encode(keys.publicKey), jwkKey);
          deepStrictEqual(
            jwk.publicKey.decode(jwk.publicKey.encode(keys.publicKey)),
            keys.publicKey
          );
          // Sec
          const jwkSecKey = await web.utils.convertSecretKey(keys.secretKey, 'raw', 'jwk');
          deepStrictEqual(jwk.secretKey.decode(jwkSecKey), keys.secretKey);
          deepStrictEqual(jwk.secretKey.encode(keys.secretKey), jwkSecKey);
          deepStrictEqual(
            jwk.secretKey.decode(jwk.secretKey.encode(keys.secretKey)),
            keys.secretKey
          );

          // Verify that it fails to import keys from other curves
          const otherSec = await other.web.utils.randomSecretKey('jwk');
          const otherPub = await other.web.getPublicKey(otherSec, {
            formatSec: 'jwk',
            formatPub: 'jwk',
          });
          throws(() => jwk.secretKey.decode(otherSec));
          throws(() => jwk.publicKey.decode(otherPub));
          // Round-trip
          const sec = await web.utils.randomSecretKey('jwk');
          const pub = await web.getPublicKey(sec, {
            formatSec: 'jwk',
            formatPub: 'jwk',
          });
          deepStrictEqual(jwk.secretKey.encode(jwk.secretKey.decode(sec)), sec);
          deepStrictEqual(jwk.publicKey.encode(jwk.publicKey.decode(pub)), pub);
        });
      }
      if (der) {
        should('DER', async () => {
          const keys = lib.keygen();
          const pubUnc = lib.getPublicKey(keys.secretKey, false);
          deepStrictEqual(
            await web.utils.convertPublicKey(keys.publicKey, 'raw', 'spki'),
            await web.utils.convertPublicKey(pubUnc, 'raw', 'spki')
          );
          // Pub
          // It is uncompressed after conversion via webcrypto, but could be compressed too!
          const derKey = await web.utils.convertPublicKey(keys.publicKey, 'raw', 'spki');
          deepStrictEqual(der.publicKey.decode(derKey), pubUnc);
          deepStrictEqual(der.publicKey.encode(pubUnc), derKey);
          // Sec
          const derSecKey = await web.utils.convertSecretKey(keys.secretKey, 'raw', 'pkcs8');
          deepStrictEqual(der.secretKey.decode(derSecKey), keys.secretKey);
          // noble/wecrypto returns pkcs8 key without publicKey if created from raw secretKey
          deepStrictEqual(der.secretKey.encode(keys.secretKey, { noPublicKey: true }), derSecKey);
          // Round-trip
          const webFullPkcs8 = await web.utils.randomSecretKey('pkcs8');
          deepStrictEqual(der.secretKey.encode(der.secretKey.decode(webFullPkcs8)), webFullPkcs8);
          const webFullSpki = await web.getPublicKey(webFullPkcs8, {
            formatSec: 'pkcs8',
            formatPub: 'spki',
          });
          deepStrictEqual(der.publicKey.encode(der.publicKey.decode(webFullSpki)), webFullSpki);
          // Verify that it fails to import keys from other curves
          const otherFullPkcs8 = await other.web.utils.randomSecretKey('pkcs8');
          throws(() => der.secretKey.decode(otherFullPkcs8));
          const otherFullSpki = await other.web.getPublicKey(otherFullPkcs8, {
            formatSec: 'pkcs8',
            formatPub: 'spki',
          });
          throws(() => der.publicKey.decode(otherFullSpki));
        });
      }
    });
  }
});

should.runWhen(import.meta.url);

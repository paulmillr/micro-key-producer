import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { ed448, x448 } from '@noble/curves/ed448.js';
import { p256, p384, p521 } from '@noble/curves/nist.js';
import * as web from '@noble/curves/webcrypto.js';
import { concatBytes } from '@noble/hashes/utils.js';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { hex } from '@scure/base';
import * as P from 'micro-packed';
import { deepStrictEqual, throws } from 'node:assert';
import { ASN1, BER, DER } from '../src/asn1.ts';
import { PKCS8, PKCS8SecretKey, RSAPrivateKey, SPKI } from '../src/convert.ts';
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
const EC_CURVES = {
  p256: 'P-256',
  p384: 'P-384',
  p521: 'P-521',
} as const;
const JWK_SIG_ALGS = { p256: 'ES256', p384: 'ES384', p521: 'ES512' } as const;
const P_ECDH_JWKS = {
  p256: { web: web.p256, jwk: convert.p256_jwk_ecdh },
  p384: { web: web.p384, jwk: convert.p384_jwk_ecdh },
  p521: { web: web.p521, jwk: convert.p521_jwk_ecdh },
} as const;
const indexOfBytes = (buf: Uint8Array, needle: Uint8Array) => {
  for (let i = 0; i <= buf.length - needle.length; i++) {
    let match = true;
    for (let j = 0; j < needle.length; j++) {
      if (buf[i + j] === needle[j]) continue;
      match = false;
      break;
    }
    if (match) return i;
  }
  return -1;
};

describe('convert', () => {
  should('base64armor validators', () => {
    throws(() => base64armor(1 as never, 64, P.bytes(null)), TypeError);
    throws(() => base64armor('', 64, P.bytes(null)), RangeError);
    throws(() => base64armor('MESSAGE', '64' as never, P.bytes(null)), TypeError);
    throws(() => base64armor('MESSAGE', 0, P.bytes(null)), RangeError);
    throws(() => base64armor('MESSAGE', 64, 1 as never), TypeError);
    throws(() => base64armor('MESSAGE', 64, P.bytes(null), 1 as never), TypeError);
  });
  should('strict DER conversion rejects unknown EC namedCurve', () => {
    const bad = SPKI.encode({
      algorithm: {
        info: { TAG: 'EC', data: { TAG: 'namedCurve', data: '1.3.6.1.4.1.8301.3.1.2.9.0.33' } },
      },
      publicKey: new Uint8Array(65),
    });
    throws(() => convert.p256_der.publicKey.decode(bad));
  });
  should('ASN.1', () => {
    deepStrictEqual(DER.length.encode(0x7f), Uint8Array.from([0x7f]));
    deepStrictEqual(DER.length.encode(0x80), Uint8Array.from([0x81, 0x80]));
    deepStrictEqual(DER.length.encode(0x1234), Uint8Array.from([0x82, 0x12, 0x34]));
    deepStrictEqual(DER.length.encode(0x80000000), Uint8Array.from([0x84, 0x80, 0x00, 0x00, 0x00]));
    deepStrictEqual(DER.length.decode(Uint8Array.from([0x84, 0x80, 0x00, 0x00, 0x00])), 0x80000000);
    throws(() => DER.length.decode(Uint8Array.from([0x82, 0x00, 0x80])));
    throws(() => DER.length.encode(-1));
    throws(() => DER.length.encode(1.5));
    deepStrictEqual(ASN1.Integer.decode(hex.decode('02020080')), 128n);
    deepStrictEqual(hex.encode(ASN1.Integer.encode(128n)), '02020080');
    throws(() => ASN1.Integer.decode(hex.decode('040101')));
    throws(() => ASN1.Integer.decode(hex.decode('0200')));
    throws(() => ASN1.Integer.decode(hex.decode('02020001')));
    throws(() => ASN1.Integer.decode(hex.decode('0202007f')));
    const rawTree = {
      tag: 0x30,
      children: [{ tag: 0x02, valueHex: '01' }],
    };
    deepStrictEqual(ASN1.TLVNode.decode(hex.decode('3003020101')), rawTree);
    deepStrictEqual(hex.encode(ASN1.TLVNode.encode(rawTree)), '3003020101');
    const highTagTree = {
      tag: 0xbf,
      tagHex: 'bf1f',
      children: [{ tag: 0x02, valueHex: '01' }],
    };
    deepStrictEqual(ASN1.TLVNode.decode(hex.decode('bf1f03020101')), highTagTree);
    deepStrictEqual(hex.encode(ASN1.TLVNode.encode(highTagTree)), 'bf1f03020101');
    throws(() => ASN1.TLVNode.decode(hex.decode('1f1e00')));
    throws(() => ASN1.any.decode(hex.decode('1f800000')));
    throws(() => BER.decode(hex.decode('1f1e00')));
    const rawAlg = { algorithm: '1.2.3', params: { tag: 0x05, valueHex: '' } };
    deepStrictEqual(ASN1.AlgorithmIdentifier.decode(hex.decode('300606022a030500')), rawAlg);
    deepStrictEqual(hex.encode(ASN1.AlgorithmIdentifier.encode(rawAlg)), '300606022a030500');
    const rawAlgNoParams = { algorithm: '1.2.3', params: undefined };
    deepStrictEqual(ASN1.AlgorithmIdentifier.decode(hex.decode('300406022a03')), rawAlgNoParams);
    deepStrictEqual(hex.encode(ASN1.AlgorithmIdentifier.encode(rawAlgNoParams)), '300406022a03');
    const rawAttr = { oid: '1.2.3', values: [Uint8Array.of(0x04, 0x01, 0xaa)] };
    deepStrictEqual(ASN1.Attribute.decode(hex.decode('300906022a0331030401aa')), rawAttr);
    deepStrictEqual(hex.encode(ASN1.Attribute.encode(rawAttr)), '300906022a0331030401aa');
    const rawTime = { TAG: 'utc' as const, data: '250101000000Z' };
    deepStrictEqual(ASN1.Time.decode(hex.decode('170d3235303130313030303030305a')), rawTime);
    deepStrictEqual(hex.encode(ASN1.Time.encode(rawTime)), '170d3235303130313030303030305a');
    const rawSig = { r: 1n, s: 2n };
    deepStrictEqual(ASN1.ECDSASig.decode(hex.decode('3006020101020102')), rawSig);
    deepStrictEqual(hex.encode(ASN1.ECDSASig.encode(rawSig)), '3006020101020102');
    const rawString = { TAG: 'utf8' as const, data: 'hi' };
    deepStrictEqual(ASN1.StringOrRaw.decode(hex.decode('0c026869')), rawString);
    deepStrictEqual(hex.encode(ASN1.StringOrRaw.encode(rawString)), '0c026869');
    const rawNode = { tag: 0x05, valueHex: '' };
    deepStrictEqual(ASN1.StringOrRaw.decode(hex.decode('0500')), { TAG: 'raw', data: rawNode });
    deepStrictEqual(hex.encode(ASN1.StringOrRaw.encode({ TAG: 'raw', data: rawNode })), '0500');
    deepStrictEqual(ASN1.AnyValue.decode(ASN1.Boolean.encode(true)), { TAG: 'bool', data: true });
    deepStrictEqual(ASN1.AnyValue.decode(ASN1.Integer.encode(5n)), { TAG: 'int', data: 5n });
    deepStrictEqual(ASN1.AnyValue.decode(ASN1.OID.encode('2.5.4.3')), {
      TAG: 'oid',
      data: 'commonName',
    });
    deepStrictEqual(ASN1.AnyValue.decode(ASN1.OctetString.encode(Uint8Array.of(1))), {
      TAG: 'octet',
      data: Uint8Array.of(1),
    });
    deepStrictEqual(ASN1.AnyValue.decode(ASN1.Time.encode(rawTime)), {
      TAG: 'time',
      data: rawTime,
    });
    deepStrictEqual(ASN1.AnyValue.decode(ASN1.String.encode(rawString)), {
      TAG: 'text',
      data: rawString,
    });
    deepStrictEqual(ASN1.AnyValue.decode(hex.decode('0500')), { TAG: 'raw', data: rawNode });
    const tailAny = ASN1.sequence({ oid: ASN1.OID, value: ASN1.optional(ASN1.TLVNode) });
    const tailAnyValue = { oid: '1.2.3', value: { tag: 0x9f, tagHex: '9f1f', valueHex: '' } };
    deepStrictEqual(tailAny.decode(hex.decode('300706022a039f1f00')), tailAnyValue);
    deepStrictEqual(hex.encode(tailAny.encode(tailAnyValue)), '300706022a039f1f00');
    const tailAnyAbsent = { oid: '1.2.3', value: undefined };
    deepStrictEqual(tailAny.decode(hex.decode('300406022a03')), tailAnyAbsent);
    deepStrictEqual(hex.encode(tailAny.encode(tailAnyAbsent)), '300406022a03');
    const strictSet = ASN1.set(ASN1.OID);
    deepStrictEqual(strictSet.decode(hex.decode('310606012906012a')), ['1.1', '1.2']);
    throws(() => strictSet.decode(hex.decode('310606012a060129')));
    const berSet = ASN1.set(ASN1.OID, { ber: true });
    deepStrictEqual(berSet.decode(hex.decode('310606012a060129')), ['1.2', '1.1']);
    deepStrictEqual(hex.encode(berSet.encode(['1.2', '1.1'])), '310606012906012a');
    deepStrictEqual(ASN1.OID.decode(ASN1.OID.encode('2.268435455')), '2.268435455');
    deepStrictEqual(ASN1.OID.decode(ASN1.OID.encode('2.48.1')), '2.48.1');
    deepStrictEqual(ASN1.OID.decode(ASN1.OID.encode('2.840.10045.3.1.7')), '2.840.10045.3.1.7');
    throws(() => ASN1.OID.encode('1.2.x'));
    throws(() => ASN1.OID.encode('1.2.'));
    throws(() => ASN1.OID.encode('1.2.-1'));
    throws(() =>
      ASN1.OID.decode(
        Uint8Array.from([0x06, 0x09, 0x88, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00])
      )
    );
    throws(() => ASN1.OID.decode(Uint8Array.from([0x06, 0x02, 0x80, 0x2a])));
    const attrs = [
      Uint8Array.from([0x30, 0x03, 0x06, 0x01, 0x02]),
      Uint8Array.from([0x30, 0x03, 0x06, 0x01, 0x01]),
    ];
    const key = {
      version: 0n,
      algorithm: { info: { TAG: 'Ed25519' as const, data: null } },
      privateKey: { TAG: 'raw' as const, data: new Uint8Array(32) },
      attributes: attrs,
    };
    deepStrictEqual(PKCS8.decode(PKCS8.encode(key)).attributes, [attrs[1], attrs[0]]);
    deepStrictEqual(
      hex.encode(PKCS8.encode(key)),
      '303a020100300506032b6570042204200000000000000000000000000000000000000000000000000000000000000000a00a30030601013003060102'
    );
    const pkcs8Base = {
      version: 0n,
      algorithm: { info: { TAG: 'Ed25519' as const, data: null } },
      privateKey: { TAG: 'raw' as const, data: Uint8Array.of(1, 2, 3) },
      attributes: undefined,
      publicKey: undefined,
    };
    const pkcs8Pub = { ...pkcs8Base, version: 1n, publicKey: Uint8Array.of(9) };
    deepStrictEqual(PKCS8.decode(PKCS8.encode(pkcs8Base)), pkcs8Base);
    deepStrictEqual(PKCS8.decode(PKCS8.encode(pkcs8Pub)), pkcs8Pub);
    throws(() => PKCS8.encode({ ...pkcs8Base, version: 0n, publicKey: Uint8Array.of(9) }));
    throws(() => PKCS8.encode({ ...pkcs8Base, version: 1n }));
    throws(() => PKCS8.encode({ ...pkcs8Base, version: 2n }));
    throws(() => PKCS8.decode(hex.decode('3015020100300506032b65700405040301020381020009')));
    throws(() => PKCS8.decode(hex.decode('3011020101300506032b657004050403010203')));
    throws(() => PKCS8.decode(hex.decode('3011020102300506032b657004050403010203')));
    const ecSecret = {
      version: 1n,
      privateKey: Uint8Array.of(1, 2, 3),
      parameters: undefined,
      publicKey: undefined,
    };
    const ecPkcs8Secret = { TAG: 'struct' as const, data: ecSecret };
    deepStrictEqual(PKCS8SecretKey.decode(PKCS8SecretKey.encode(ecPkcs8Secret)), ecPkcs8Secret);
    throws(() => PKCS8SecretKey.encode({ TAG: 'struct', data: { ...ecSecret, version: 0n } }));
    throws(() => PKCS8SecretKey.encode({ TAG: 'struct', data: { ...ecSecret, version: 2n } }));
    throws(() => PKCS8SecretKey.decode(hex.decode('30080201000403010203')));
    throws(() => PKCS8SecretKey.decode(hex.decode('30080201020403010203')));
    const specifiedCurveKey = (version: bigint, seed?: Uint8Array) => ({
      version: 0n,
      algorithm: {
        info: {
          TAG: 'EC' as const,
          data: {
            TAG: 'specifiedCurve' as const,
            data: {
              version,
              fieldId: { info: { TAG: 'primeField' as const, data: 23n } },
              curve: { a: Uint8Array.of(1), b: Uint8Array.of(2), seed },
              base: Uint8Array.of(4, 3, 4),
              order: 5n,
              cofactor: 1n,
              hash: undefined,
              rest: Uint8Array.of(),
            },
          },
        },
      },
      privateKey: { TAG: 'raw' as const, data: Uint8Array.of(9) },
      attributes: undefined,
      publicKey: undefined,
    });
    deepStrictEqual(
      PKCS8.decode(PKCS8.encode(specifiedCurveKey(2n, Uint8Array.of(7)))),
      specifiedCurveKey(2n, Uint8Array.of(7))
    );
    throws(() => PKCS8.encode(specifiedCurveKey(2n)));
    throws(() => PKCS8.encode(specifiedCurveKey(3n)));
    throws(() => PKCS8.encode(specifiedCurveKey(4n)));
    throws(() =>
      PKCS8.decode(
        hex.decode(
          '3039020100302f06072a8648ce3d02013024020102300c06072a8648ce3d0101020117300604010104010204030403040201050201010403040109'
        )
      )
    );
    throws(() =>
      PKCS8.decode(
        hex.decode(
          '3039020100302f06072a8648ce3d02013024020103300c06072a8648ce3d0101020117300604010104010204030403040201050201010403040109'
        )
      )
    );
    throws(() =>
      PKCS8.decode(
        hex.decode(
          '3039020100302f06072a8648ce3d02013024020104300c06072a8648ce3d0101020117300604010104010204030403040201050201010403040109'
        )
      )
    );
    const rsa = DER_VECTORS.find((i) => i.name === 'rsa2048-priv');
    if (!rsa) throw new Error('missing rsa2048-priv vector');
    const rsaPkcs8 = base64armor('PRIVATE KEY', 10, P.bytes(null)).decode(rsa.pem);
    const rsaStart = indexOfBytes(rsaPkcs8, hex.decode('02010002820101')) - 4;
    if (rsaStart < 0) throw new Error('missing embedded RSAPrivateKey payload');
    const rsaRaw = rsaPkcs8.slice(rsaStart);
    deepStrictEqual(PKCS8.decode(rsaPkcs8), {
      version: 0n,
      algorithm: { info: { TAG: 'rsaEncryption', data: null } },
      privateKey: { TAG: 'raw', data: rsaRaw },
      attributes: undefined,
      publicKey: undefined,
    });
    deepStrictEqual(
      PKCS8.encode({
        version: 0n,
        algorithm: { info: { TAG: 'rsaEncryption', data: null } },
        privateKey: { TAG: 'raw', data: rsaRaw },
        attributes: undefined,
        publicKey: undefined,
      }),
      rsaPkcs8
    );
    const rsaKey = RSAPrivateKey.decode(rsaRaw);
    const rsaVersionOnly = rsaRaw.slice();
    rsaVersionOnly[6] = 1;
    throws(() => RSAPrivateKey.decode(rsaVersionOnly));
    throws(() => RSAPrivateKey.encode({ ...rsaKey, version: 1n }));
    const rsaMulti = {
      ...rsaKey,
      version: 1n,
      otherPrimeInfos: [{ prime: 17n, exponent: 3n, coefficient: 5n }],
    };
    deepStrictEqual(
      RSAPrivateKey.decode(RSAPrivateKey.encode(rsaMulti)),
      rsaMulti
    );
    throws(() => RSAPrivateKey.encode({ ...rsaMulti, version: 0n }));
    const rsaMultiVersion0 = RSAPrivateKey.encode(rsaMulti);
    rsaMultiVersion0[6] = 0;
    throws(() => RSAPrivateKey.decode(rsaMultiVersion0));
    const dsa = DER_VECTORS.find((i) => i.name === 'unenc-dsa-pkcs8.pub.pem');
    if (!dsa || !dsa.decoded) throw new Error('missing unenc-dsa-pkcs8.pub.pem vector');
    const dsaSpki = base64armor('PUBLIC KEY', 10, P.bytes(null)).decode(dsa.pem);
    const dsaPubAt = indexOfBytes(dsaSpki, Uint8Array.of(0x03, 0x81, 0x84, 0x00));
    if (dsaPubAt < 0) throw new Error('missing DSA subjectPublicKey bit string');
    const dsaNoParams = concatBytes(
      Uint8Array.of(
        0x30,
        0x81,
        0x92,
        0x30,
        0x09,
        0x06,
        0x07,
        0x2a,
        0x86,
        0x48,
        0xce,
        0x38,
        0x04,
        0x01
      ),
      dsaSpki.slice(dsaPubAt)
    );
    const dsaDecoded = {
      algorithm: { info: { TAG: 'DSA' as const, data: undefined } },
      publicKey: dsa.decoded.publicKey,
    };
    deepStrictEqual(SPKI.decode(dsaNoParams), dsaDecoded);
    deepStrictEqual(SPKI.encode(dsaDecoded), dsaNoParams);
    const highTagAny = Uint8Array.from([0x30, 0x03, 0x9f, 0x1f, 0x00]);
    // RFC 5280 section 4.2 leaves extension-specific fields as DER-encoded ASN.1
    // values; schema-less ANY must preserve one complete TLV without parsing children.
    deepStrictEqual(ASN1.any.decode(highTagAny), highTagAny);
    deepStrictEqual(ASN1.any.encode(highTagAny), highTagAny);
    const nonMinimalBerLen = Uint8Array.from([0x04, 0x81, 0x01, 0x00]);
    throws(() => BER.decode(nonMinimalBerLen), /DER non-minimal length encoding/);
    const normalizedBerLen = BER.decode(nonMinimalBerLen, { allowBER: true });
    deepStrictEqual(hex.encode(normalizedBerLen.der), '040100');
    deepStrictEqual(BER.encode(normalizedBerLen.nodes, normalizedBerLen.der), nonMinimalBerLen);
    const signedBoundaryTag = Uint8Array.from([0x1f, 0x88, 0x80, 0x80, 0x80, 0x00, 0x00]);
    const signedBoundary = BER.decode(signedBoundaryTag, { allowBER: true });
    deepStrictEqual(signedBoundary, {
      nodes: [
        {
          len: 0,
          lenBytes: 1,
          indefinite: false,
          bitUnused: undefined,
          children: undefined,
          cls: 0,
          tagNum: 0x80000000,
          cons: false,
        },
      ],
      der: signedBoundaryTag,
    });
    deepStrictEqual(BER.encode(signedBoundary.nodes, signedBoundary.der), signedBoundaryTag);
    const maxTag = Uint8Array.from([0x1f, 0x8f, 0xff, 0xff, 0xff, 0x7f, 0x00]);
    const max = BER.decode(maxTag, { allowBER: true });
    deepStrictEqual(max, {
      nodes: [
        {
          len: 0,
          lenBytes: 1,
          indefinite: false,
          bitUnused: undefined,
          children: undefined,
          cls: 0,
          tagNum: 0xffffffff,
          cons: false,
        },
      ],
      der: maxTag,
    });
    deepStrictEqual(BER.encode(max.nodes, max.der), maxTag);
    throws(
      () => BER.decode(Uint8Array.from([0x1f, 0x90, 0x80, 0x80, 0x80, 0x00, 0x00])),
      /BER tag number exceeds uint32/
    );
    for (const { name, type, pem, decoded, notImplemented, shouldFail } of DER_VECTORS) {
      const ARMOR = pem.split('\n')[0].replaceAll('-', '').replace('BEGIN ', '');
      const coder = base64armor(ARMOR, 10, P.bytes(null));
      const bytes = coder.decode(pem);
      // Every fixture should still be structurally parseable before the typed
      // PKCS#8/SPKI branch accepts or rejects it.
      ASN1.debug.decode(bytes);
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
          if (name === 'ed25519' || name === 'ed448') {
            const pubNoAlg = { ...pub };
            const secNoAlg = { ...sec };
            delete pubNoAlg.alg;
            delete secNoAlg.alg;
            deepStrictEqual(jwk.publicKey.decode(pubNoAlg), jwk.publicKey.decode(pub));
            deepStrictEqual(
              jwk.publicKey.decode({ ...pub, alg: 'EdDSA' }),
              jwk.publicKey.decode(pub)
            );
            deepStrictEqual(jwk.secretKey.decode(secNoAlg), jwk.secretKey.decode(sec));
            deepStrictEqual(
              jwk.secretKey.decode({ ...sec, alg: 'EdDSA' }),
              jwk.secretKey.decode(sec)
            );
          }
          if (name === 'x25519' || name === 'x448') {
            for (const alg of ['ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW']) {
              deepStrictEqual(jwk.publicKey.decode({ ...pub, alg }), jwk.publicKey.decode(pub));
              deepStrictEqual(jwk.secretKey.decode({ ...sec, alg }), jwk.secretKey.decode(sec));
            }
          }
          if (name === 'p256' || name === 'p384' || name === 'p521') {
            const alg = JWK_SIG_ALGS[name];
            deepStrictEqual(jwk.publicKey.decode({ ...pub, alg }), jwk.publicKey.decode(pub));
            deepStrictEqual(jwk.secretKey.decode({ ...sec, alg }), jwk.secretKey.decode(sec));
          }
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
          const oid = EC_CURVES[name as keyof typeof EC_CURVES];
          deepStrictEqual(der.publicKey.decode(derKey), pubUnc);
          deepStrictEqual(der.publicKey.encode(pubUnc), derKey);
          // Sec
          const derSecKey = await web.utils.convertSecretKey(keys.secretKey, 'raw', 'pkcs8');
          deepStrictEqual(der.secretKey.decode(derSecKey), keys.secretKey);
          // WebCrypto PKCS#8 from a raw EC secret omits inner publicKey and parameters.
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
          if (oid) {
            const otherOid = name === 'p256' ? EC_CURVES.p384 : EC_CURVES.p256;
            const mismatch = PKCS8.encode({
              version: 0n,
              algorithm: {
                info: { TAG: 'EC' as const, data: { TAG: 'namedCurve' as const, data: oid } },
              },
              privateKey: {
                TAG: 'struct' as const,
                data: {
                  version: 1n,
                  privateKey: keys.secretKey,
                  parameters: { TAG: 'namedCurve' as const, data: otherOid },
                },
              },
            });
            throws(() => der.secretKey.decode(mismatch));
          }
        });
      }
    });
  }
  should('P-curve ECDH JWK accepts ECDH-ES alg metadata', async () => {
    for (const name in P_ECDH_JWKS) {
      const { web, jwk } = P_ECDH_JWKS[name as keyof typeof P_ECDH_JWKS];
      const sec = await web.utils.randomSecretKey('jwk');
      const pub = await web.getPublicKey(sec, { formatSec: 'jwk', formatPub: 'jwk' });
      for (const alg of ['ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW']) {
        deepStrictEqual(jwk.publicKey.decode({ ...pub, alg }), jwk.publicKey.decode(pub));
        deepStrictEqual(jwk.secretKey.decode({ ...sec, alg }), jwk.secretKey.decode(sec));
      }
    }
  });
});

should.runWhen(import.meta.url);

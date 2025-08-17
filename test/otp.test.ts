import { hexToBytes } from '@noble/hashes/utils.js';
import { describe, should } from 'micro-should';
import { deepStrictEqual as eql, throws } from 'node:assert';
import * as otp from '../src/otp.ts';

describe('otp', () => {
  should('OTP url parser', () => {
    const INVALID = [
      'http://hello.com',
      'otpauth://totp',
      'otpauth://hotp',
      'otpauth://derp?secret=foo',
      'otpauth://totp?foo=secret',
      'otpauth://totp?digits=-1',
      'otpauth://totp/SomeIssuer:?issuer=AnotherIssuer',
      'otpauth://totp?algorithm=aes',
      'otpauth://totp?secret=Ab$:1',
      'otpauth://totp?secret=1234567890',
    ];
    for (const i of INVALID) throws(() => otp.parse(i));
    eql(otp.parse('ZYTYYE5FOAGW5ML7LRWUL4WTZLNJAMZS'), {
      algorithm: 'sha1',
      digits: 6,
      interval: 30,
      secret: hexToBytes('ce278c13a5700d6eb17f5c6d45f2d3cada903332'),
    });
    eql(
      otp.parse(
        'otpauth://totp/ACME%20Co:john@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30'
      ),
      {
        algorithm: 'sha1',
        digits: 6,
        interval: 30,
        secret: hexToBytes('3dc6caa4824a6d288767b2331e20b43166cb85d9'),
      }
    );
    eql(
      otp.buildURL(otp.parse('ZYTYYE5FOAGW5ML7LRWUL4WTZLNJAMZS')),
      'otpauth://totp/?secret=ZYTYYE5FOAGW5ML7LRWUL4WTZLNJAMZS&interval=30&digits=6&algorithm=SHA1'
    );
    eql(
      otp.buildURL(
        otp.parse(
          'otpauth://totp/ACME%20Co:john@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30'
        )
      ),
      'otpauth://totp/?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&interval=30&digits=6&algorithm=SHA1'
    );
  });
  should('OTP', () => {
    const opts1 = otp.parse('ZYTYYE5FOAGW5ML7LRWUL4WTZLNJAMZS');
    const opts2 = otp.parse('PW4YAYYZVDE5RK2AOLKUATNZIKAFQLZO');
    eql(otp.hotp(opts1, 0n), '549419');
    eql(otp.hotp(opts2, 0n), '009551');
    eql(otp.hotp(opts1, 42n), '626854');
    eql(otp.hotp(opts2, 42n), '093610');
    const opts3 = otp.parse('GEZDGNBV');
    eql(otp.hotp(opts3, 0), '734055');
    eql(otp.hotp(opts3, 1), '662488');
    eql(otp.hotp(opts3, 2), '289363');
    eql(otp.totp(opts1, 0), '549419');
    eql(otp.totp(opts2, 0), '009551');
    eql(otp.totp(opts1, 10 * 1000), '549419');
    eql(otp.totp(opts2, 10 * 1000), '009551');
    eql(otp.totp(opts1, 1260 * 1000), '626854');
    eql(otp.totp(opts2, 1260 * 1000), '093610');
    eql(otp.totp(opts1, 1270 * 1000), '626854');
    eql(otp.totp(opts2, 1270 * 1000), '093610');
    // https://datatracker.ietf.org/doc/html/rfc4226#page-32
    const optsRfc = otp.parse('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
    eql(otp.hotp(optsRfc, 0), '755224');
    eql(otp.hotp(optsRfc, 1), '287082');
    eql(otp.hotp(optsRfc, 2), '359152');
    eql(otp.hotp(optsRfc, 3), '969429');
    eql(otp.hotp(optsRfc, 4), '338314');
    eql(otp.hotp(optsRfc, 5), '254676');
    eql(otp.hotp(optsRfc, 6), '287922');
    eql(otp.hotp(optsRfc, 7), '162583');
    eql(otp.hotp(optsRfc, 8), '399871');
    eql(otp.hotp(optsRfc, 9), '520489');
    // https://datatracker.ietf.org/doc/html/rfc6238#appendix-B
    /*
      There is something strange:
      - Spec says vector should be "12345678901234567890" as hex (won't work for sha256/sha512),
        hovewer later in example code they use different keys for sha256/sha512 (with padding)
      - 1password doesn't pad (10 bytes secret with sha1 works as is, without padding)
      - https://github.com/pyauth/pyotp doesn't pad
      - https://github.com/anzerr/totp.util pads secret key until it has hash.outpuLen bytes
      */
    const optsRfc1 = otp.parse('otpauth://totp/?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8');
    const optsRfc256 = otp.parse(
      'otpauth://totp/?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&algorithm=SHA256&digits=8'
    );
    const optsRfc512 = otp.parse(
      'otpauth://totp/?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA&algorithm=SHA512&digits=8'
    );
    eql(otp.totp(optsRfc1, 59 * 1000), '94287082');
    eql(otp.totp(optsRfc256, 59 * 1000), '46119246');
    eql(otp.totp(optsRfc512, 59 * 1000), '90693936');
    eql(otp.totp(optsRfc1, 1111111109 * 1000), '07081804');
    eql(otp.totp(optsRfc256, 1111111109 * 1000), '68084774');
    eql(otp.totp(optsRfc512, 1111111109 * 1000), '25091201');
    eql(otp.totp(optsRfc1, 1111111111 * 1000), '14050471');
    eql(otp.totp(optsRfc256, 1111111111 * 1000), '67062674');
    eql(otp.totp(optsRfc512, 1111111111 * 1000), '99943326');
    eql(otp.totp(optsRfc1, 1234567890 * 1000), '89005924');
    eql(otp.totp(optsRfc256, 1234567890 * 1000), '91819424');
    eql(otp.totp(optsRfc512, 1234567890 * 1000), '93441116');
    eql(otp.totp(optsRfc1, 2000000000 * 1000), '69279037');
    eql(otp.totp(optsRfc256, 2000000000 * 1000), '90698825');
    eql(otp.totp(optsRfc512, 2000000000 * 1000), '38618901');
    eql(otp.totp(optsRfc1, 20000000000 * 1000), '65353130');
    eql(otp.totp(optsRfc256, 20000000000 * 1000), '77737706');
    eql(otp.totp(optsRfc512, 20000000000 * 1000), '47863826');
  });
});

should.runWhen(import.meta.url);

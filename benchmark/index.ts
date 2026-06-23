import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import bench from '@paulmillr/jsbt/bench.js';
import * as ipns from '../src/ipns.ts';
import * as otp from '../src/otp.ts';
import * as password from '../src/password.ts';
import * as pgp from '../src/pgp.ts';
import * as ssh from '../src/ssh.ts';
import * as tor from '../src/tor.ts';

const seed = sha256(utf8ToBytes('micro-key-producer benchmark seed'));
const checkBytes = Uint8Array.of(1, 2, 3, 4);
const otpUrl =
  'otpauth://totp/ACME:alice@example.com?secret=GEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=6&period=30';
const otpOpts = otp.parse(otpUrl);
const mask = password.mask('Cvccvc-cvccvc-cvccv1');
const masked = mask.apply(seed);
const user = 'Bench User <bench@example.com>';

(async () => {
  console.log('# OTP');
  await bench('parse', () => otp.parse(otpUrl));
  await bench('hotp', () => otp.hotp(otpOpts, 42n));
  await bench('totp', () => otp.totp(otpOpts, 1_234_567_890_000));

  console.log('# Passwords');
  await bench('mask.apply', () => mask.apply(seed));
  await bench('mask.inverse', () => mask.inverse(masked));
  await bench('secureMask.apply', () => password.secureMask.apply(seed));

  console.log('# Key formats');
  await bench('ssh.getKeys', () => ssh.getKeys(seed, 'bench@example.com', checkBytes));
  await bench('tor.getKeys', () => tor.getKeys(seed));
  await bench('ipns.getKeys', () => ipns.getKeys(seed));
  await bench('pgp.getKeys', () => pgp.getKeys(seed, user, undefined, 0));
})();

/*! micro-key-producer - MIT License (c) 2024 Paul Miller (paulmillr.com) */
import { hmac } from '@noble/hashes/hmac';
import { sha1 } from '@noble/hashes/legacy';
import { sha256, sha512 } from '@noble/hashes/sha2';
import { base32 } from '@scure/base';
import { U32BE, U64BE } from 'micro-packed';

export type OTPOpts = { algorithm: string; digits: number; interval: number; secret: Uint8Array };
function parseSecret(secret: string): Uint8Array {
  const len = Math.ceil(secret.length / 8) * 8;
  return base32.decode(secret.padEnd(len, '=').toUpperCase());
}

export function parse(otp: string): OTPOpts {
  const opts = { secret: new Uint8Array(), algorithm: 'sha1', digits: 6, interval: 30 };
  if (otp.startsWith('otpauth://totp/')) {
    // @ts-ignore
    if (typeof URL === 'undefined') throw new Error('global variable URL must be defined');
    // @ts-ignore
    const url = new URL(otp);
    if (url.protocol !== 'otpauth:' || url.host !== 'totp') throw new Error('OTP: wrong url');
    const params = url.searchParams;
    const digits = params.get('digits');
    if (digits) {
      const parsed = Number.parseInt(digits);
      if (![6, 7, 8].includes(parsed))
        throw new Error(`OTP: url should include 6, 7 or 8 digits. Got: ${digits}`);
      opts.digits = parsed;
    }
    const algo = params.get('algorithm');
    if (algo) {
      const lower = algo.toLowerCase();
      if (!['sha1', 'sha256', 'sha512'].includes(lower))
        throw new Error(`OTP: url with unsupported algorithm: ${algo}`);
      opts.algorithm = lower;
    }
    const secret = params.get('secret');
    if (!secret) throw new Error('OTP: url without secret');
    opts.secret = parseSecret(secret);
  } else {
    opts.secret = parseSecret(otp);
  }
  return opts;
}

export function buildURL(opts: OTPOpts): string {
  const sec = base32.encode(opts.secret).replace(/=/gm, '');
  const int_ = opts.interval;
  const algo = opts.algorithm.toUpperCase();
  return `otpauth://totp/?secret=${sec}&interval=${int_}&digits=${opts.digits}&algorithm=${algo}`;
}

export function hotp(opts: OTPOpts, counter: number | bigint): string {
  const hash = { sha1, sha256, sha512 }[opts.algorithm];
  if (!hash) throw new Error(`TOTP: unknown hash: ${opts.algorithm}`);
  const mac = hmac(hash, opts.secret, U64BE.encode(BigInt(counter)));
  const offset = mac[mac.length - 1]! & 0x0f;
  const num = U32BE.decode(mac.slice(offset, offset + 4)) & 0x7fffffff;
  return num.toString().slice(-opts.digits).padStart(opts.digits, '0');
}

export function totp(opts: OTPOpts, ts: number = Date.now()): string {
  return hotp(opts, Math.floor(ts / (opts.interval * 1000)));
}

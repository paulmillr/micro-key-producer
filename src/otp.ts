/*! micro-key-producer - MIT License (c) 2024 Paul Miller (paulmillr.com) */
/**
 * 2FA HOTP and TOTP codes. Conforms to {@link https://datatracker.ietf.org/doc/html/rfc6238 | RFC 6238}.
 * @module
 */
import { hmac } from '@noble/hashes/hmac.js';
import { sha1 } from '@noble/hashes/legacy.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { base32 } from '@scure/base';
import { U32BE, U64BE } from 'micro-packed';

/** HOTP/TOTP configuration. */
export type OTPOpts = {
  /** HMAC hash name: `sha1`, `sha256`, or `sha512`. */
  algorithm: string;
  /** Number of digits to keep from the generated OTP code. */
  digits: number;
  /** TOTP step size in seconds. */
  interval: number;
  /** Decoded OTP secret bytes. */
  secret: Uint8Array;
};
function parseSecret(secret: string): Uint8Array {
  const len = Math.ceil(secret.length / 8) * 8;
  return base32.decode(secret.padEnd(len, '=').toUpperCase());
}

/**
 * Parses a raw base32 secret or `otpauth://totp/...` URL.
 * @param otp - Base32 secret or otpauth URL.
 * @returns Normalized OTP settings.
 * @throws If the otpauth URL is malformed or requests unsupported OTP settings. {@link Error}
 * @example
 * Parse either a base32 secret or an otpauth URL before generating codes.
 * ```ts
 * import { parse, totp } from 'micro-key-producer/otp.js';
 * const opts = parse('JBSWY3DPEHPK3PXP');
 * totp(opts, 0);
 * ```
 */
export function parse(otp: string): OTPOpts {
  const opts = {
    secret: Uint8Array.of() as Uint8Array,
    algorithm: 'sha1',
    digits: 6,
    interval: 30,
  };
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

/**
 * Serializes OTP settings into an `otpauth://totp/...` URL.
 * @param opts - Parsed OTP settings. See {@link OTPOpts}.
 * @returns OTP URL string.
 * @example
 * Rebuild the otpauth URL after normalizing or editing the parsed settings.
 * ```ts
 * import { parse, buildURL } from 'micro-key-producer/otp.js';
 * const opts = parse('JBSWY3DPEHPK3PXP');
 * buildURL(opts);
 * ```
 */
export function buildURL(opts: OTPOpts): string {
  const sec = base32.encode(opts.secret).replace(/=/gm, '');
  const int_ = opts.interval;
  const algo = opts.algorithm.toUpperCase();
  return `otpauth://totp/?secret=${sec}&interval=${int_}&digits=${opts.digits}&algorithm=${algo}`;
}

/**
 * Computes an HOTP code for the supplied moving factor.
 * @param opts - OTP settings and secret. See {@link OTPOpts}.
 * @param counter - HOTP counter value.
 * @returns Numeric HOTP code as a zero-padded string.
 * @throws If the OTP configuration requests an unsupported hash algorithm. {@link Error}
 * @example
 * Generate an HOTP code for an explicit moving counter value.
 * ```ts
 * import { parse, hotp } from 'micro-key-producer/otp.js';
 * const opts = parse('JBSWY3DPEHPK3PXP');
 * hotp(opts, 0);
 * ```
 */
export function hotp(opts: OTPOpts, counter: number | bigint): string {
  const hash = { sha1, sha256, sha512 }[opts.algorithm];
  if (!hash) throw new Error(`TOTP: unknown hash: ${opts.algorithm}`);
  const mac = hmac(hash, opts.secret, U64BE.encode(BigInt(counter)));
  const offset = mac[mac.length - 1]! & 0x0f;
  const num = U32BE.decode(mac.slice(offset, offset + 4)) & 0x7fffffff;
  return num.toString().slice(-opts.digits).padStart(opts.digits, '0');
}

/**
 * Computes a TOTP code for the supplied timestamp.
 * @param opts - OTP settings and secret. See {@link OTPOpts}.
 * @param ts - UNIX time in milliseconds.
 * @returns Numeric TOTP code as a zero-padded string.
 * @throws If the OTP configuration requests an unsupported hash algorithm. {@link Error}
 * @example
 * Generate a TOTP code for a specific timestamp.
 * ```ts
 * import { parse, totp } from 'micro-key-producer/otp.js';
 * const opts = parse('JBSWY3DPEHPK3PXP');
 * totp(opts, 0);
 * ```
 */
export function totp(opts: OTPOpts, ts: number = Date.now()): string {
  return hotp(opts, Math.floor(ts / (opts.interval * 1000)));
}

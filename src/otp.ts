/*! micro-key-producer - MIT License (c) 2024 Paul Miller (paulmillr.com) */
/**
 * 2FA HOTP and TOTP codes. Conforms to {@link https://datatracker.ietf.org/doc/html/rfc6238 | RFC 6238}.
 * @module
 */
import { hmac } from '@noble/hashes/hmac.js';
import { sha1 } from '@noble/hashes/legacy.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { abytes, anumber } from '@noble/hashes/utils.js';
import { base32, type TArg, type TRet } from '@scure/base';
import { U32BE, U64BE, utils as packedUtils } from 'micro-packed';
import { astring } from './utils.ts';

/** HOTP/TOTP configuration. */
export type OTPOpts = {
  /** HMAC hash name: `sha1`, `sha256`, or `sha512`. */
  algorithm: string;
  /** Number of digits to keep from the generated OTP code (6 through 16). */
  digits: number;
  /** TOTP step size in seconds. */
  interval: number;
  /** Decoded OTP secret bytes. */
  secret: Uint8Array;
};
const OTP_MIN_DIGITS = 6;
const OTP_MAX_DIGITS = 16;
const OTP_MIN_SECRET_BYTES = 16;
function assertOtpDigits(digits: number, name: string): number {
  const value = anumber(digits, name);
  if (!Number.isSafeInteger(value) || value < OTP_MIN_DIGITS || value > OTP_MAX_DIGITS)
    throw new RangeError(`OTP: ${name} must be an integer from 6 to 16`);
  return value;
}
function assertOtpSecret(secret: TArg<Uint8Array>, name: string): TRet<Uint8Array> {
  const bytes = abytes(secret, undefined, name);
  // RFC 4226 §4 requires HOTP shared secrets to be at least 128 bits and
  // recommends 160 bits. TOTP inherits HOTP's construction.
  if (bytes.length < OTP_MIN_SECRET_BYTES)
    throw new RangeError(`OTP: ${name} must contain at least 128 bits`);
  return bytes;
}
function parseSecret(secret: string): TRet<Uint8Array> {
  // Accept common OTP secrets without RFC 4648 padding by normalizing to
  // uppercase and restoring the missing '=' suffix before strict base32 decode.
  const len = Math.ceil(secret.length / 8) * 8;
  return assertOtpSecret(base32.decode(secret.padEnd(len, '=').toUpperCase()), 'secret');
}

/**
 * Parses a raw base32 secret or `otpauth://totp/...` URL.
 * @param otp - Base32 secret or otpauth URL.
 * @returns Normalized OTP settings.
 * @throws If the secret is shorter than 128 bits or the URL requests unsupported settings. {@link Error}
 * @example
 * Parse either a base32 secret or an otpauth URL before generating codes.
 * ```ts
 * import { parse, totp } from 'micro-key-producer/otp.js';
 * const opts = parse('ZYTYYE5FOAGW5ML7LRWUL4WTZLNJAMZS');
 * totp(opts, 0);
 * ```
 */
export function parse(otp: string): TRet<OTPOpts> {
  otp = astring(otp, 'otp');
  const opts = {
    secret: Uint8Array.of() as Uint8Array,
    algorithm: 'sha1',
    digits: 6,
    interval: 30,
  };
  if (otp.startsWith('otpauth://totp/')) {
    if (typeof URL === 'undefined') throw new Error('global variable URL must be defined');
    const url = new URL(otp);
    if (url.protocol !== 'otpauth:' || url.host !== 'totp') throw new Error('OTP: wrong url');
    const params = url.searchParams;
    const digits = params.get('digits');
    if (digits) {
      // RFC 4226 §5.1 defines Digit as the HOTP digit-count parameter; require
      // an exact decimal token here because parseInt silently truncates suffixes.
      if (!/^\d+$/.test(digits)) throw new Error(`OTP: invalid digits: ${digits}`);
      opts.digits = assertOtpDigits(Number.parseInt(digits), 'digits');
    }
    const algo = params.get('algorithm');
    if (algo) {
      const lower = algo.toLowerCase();
      if (!['sha1', 'sha256', 'sha512'].includes(lower))
        throw new Error(`OTP: url with unsupported algorithm: ${algo}`);
      opts.algorithm = lower;
    }
    const period = params.get('period') || params.get('interval');
    if (period) {
      if (!/^\d+$/.test(period)) throw new Error(`OTP: invalid period: ${period}`);
      const parsed = Number.parseInt(period);
      // RFC 6238 §4.1 defines X as the TOTP time step in seconds, defaulting
      // to 30, so preserve non-default URL periods for later counter derivation.
      if (!Number.isSafeInteger(parsed) || parsed <= 0)
        throw new Error(`OTP: invalid period: ${period}`);
      opts.interval = parsed;
    }
    const secret = params.get('secret');
    if (!secret) throw new Error('OTP: url without secret');
    opts.secret = parseSecret(secret);
  } else {
    opts.secret = parseSecret(otp);
  }
  return opts as TRet<OTPOpts>;
}

/**
 * Serializes OTP settings into an `otpauth://totp/...` URL.
 * @param opts - Parsed OTP settings. See {@link OTPOpts}.
 * @returns OTP URL string.
 * @example
 * Rebuild the otpauth URL after normalizing or editing the parsed settings.
 * ```ts
 * import { parse, buildURL } from 'micro-key-producer/otp.js';
 * const opts = parse('ZYTYYE5FOAGW5ML7LRWUL4WTZLNJAMZS');
 * buildURL(opts);
 * ```
 */
export function buildURL(opts: TArg<OTPOpts>): string {
  if (!packedUtils.isPlainObject(opts))
    throw new TypeError('"opts" expected object, got type=' + typeof opts);
  opts.algorithm = astring(opts.algorithm, 'opts.algorithm');
  opts.digits = assertOtpDigits(opts.digits, 'opts.digits');
  anumber(opts.interval, 'opts.interval');
  opts.secret = assertOtpSecret(opts.secret, 'opts.secret');
  // OTPOpts only carries the secret/hash/digits/interval core, so serialization
  // canonicalizes back to the minimal unlabeled TOTP URL and drops any original
  // issuer/label metadata.
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
 * @throws If the secret is shorter than 128 bits or the configuration is unsupported. {@link Error}
 * @example
 * Generate an HOTP code for an explicit moving counter value.
 * ```ts
 * import { parse, hotp } from 'micro-key-producer/otp.js';
 * const opts = parse('ZYTYYE5FOAGW5ML7LRWUL4WTZLNJAMZS');
 * hotp(opts, 0);
 * ```
 */
export function hotp(opts: TArg<OTPOpts>, counter: number | bigint): string {
  if (!packedUtils.isPlainObject(opts))
    throw new TypeError('"opts" expected object, got type=' + typeof opts);
  opts.algorithm = astring(opts.algorithm, 'opts.algorithm');
  opts.digits = assertOtpDigits(opts.digits, 'opts.digits');
  anumber(opts.interval, 'opts.interval');
  opts.secret = assertOtpSecret(opts.secret, 'opts.secret');
  if (typeof counter === 'number') anumber(counter, 'counter');
  else if (typeof counter !== 'bigint')
    throw new TypeError('"counter" expected number or bigint, got type=' + typeof counter);
  const hash = { sha1, sha256, sha512 }[opts.algorithm];
  if (!hash) throw new Error(`TOTP: unknown hash: ${opts.algorithm}`);
  // RFC 4226 §5.1 defines C as the exact 8-byte counter moving factor; JS
  // numbers above MAX_SAFE_INTEGER cannot identify that counter without loss.
  if (typeof counter === 'number' && !Number.isSafeInteger(counter))
    throw new Error(`HOTP: expected safe integer counter. Got: ${counter}`);
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
 * @throws If the secret is shorter than 128 bits or the configuration is unsupported. {@link Error}
 * @example
 * Generate a TOTP code for a specific timestamp.
 * ```ts
 * import { parse, totp } from 'micro-key-producer/otp.js';
 * const opts = parse('ZYTYYE5FOAGW5ML7LRWUL4WTZLNJAMZS');
 * totp(opts, 0);
 * ```
 */
export function totp(opts: TArg<OTPOpts>, ts: number = Date.now()): string {
  if (!packedUtils.isPlainObject(opts))
    throw new TypeError('"opts" expected object, got type=' + typeof opts);
  anumber(opts.interval, 'opts.interval');
  anumber(ts, 'ts');
  // RFC 6238 uses T = floor((Unix time - T0) / X); this helper fixes T0 at 0,
  // accepts timestamps in milliseconds, and delegates the derived step counter to HOTP.
  return hotp(opts, Math.floor(ts / (opts.interval * 1000)));
}

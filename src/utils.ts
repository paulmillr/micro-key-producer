/*! micro-key-producer - MIT License (c) 2024 Paul Miller (paulmillr.com) */
/**
 * Utilities.
 * @module
 */
import { randomBytes as nobleRandomBytes } from '@noble/hashes/utils.js';
import { base64, type TArg } from '@scure/base';
import * as P from 'micro-packed';

export type { TArg, TRet } from '@scure/base';
/**
 * Secure random byte generator re-exported from `@noble/hashes/utils`.
 * @param bytesLength - Number of random bytes to return.
 * @returns Fresh random bytes.
 * @example
 * Generate fresh entropy before deriving one of the deterministic key formats.
 * ```ts
 * import { randomBytes } from 'micro-key-producer/utils.js';
 * randomBytes(32);
 * ```
 */
export const randomBytes: typeof nobleRandomBytes = nobleRandomBytes;

/**
 * Deep-freeze an exported object graph.
 * @param obj - Value to freeze.
 * @returns The same value after freezing reachable objects.
 * @example
 * Freeze a lookup table before exporting it.
 * ```ts
 * import { deepFreeze } from 'micro-key-producer/utils.js';
 * deepFreeze({ name: 'value' });
 * ```
 */
export function deepFreeze<T>(obj: T): T {
  if (!obj || typeof obj !== 'object') return obj;
  if (Object.isFrozen(obj)) return obj;
  Object.freeze(obj);
  if (Array.isArray(obj)) {
    for (const item of obj) deepFreeze(item);
  } else {
    for (const value of Object.values(obj)) deepFreeze(value);
  }
  return obj;
}
/**
 * Base64-armored values are commonly used in cryptographic applications, such as PGP and SSH.
 * @param name - The name of the armored value.
 * @param lineLen - Maximum line length for the armored value (e.g., 64 for GPG, 70 for SSH).
 * @param inner - Inner CoderType for the value.
 * @param checksum - Optional checksum function.
 * @returns Coder representing the base64-armored value.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On invalid armor names or line lengths. {@link RangeError}
 * @example
 * Wrap a packed coder in an ASCII armor envelope.
 * ```ts
 * import * as P from 'micro-packed';
 * import { base64armor } from 'micro-key-producer/utils.js';
 * base64armor('MESSAGE', 64, P.string(null)).encode('hello');
 * ```
 */
export function base64armor<T>(
  name: string,
  lineLen: number,
  inner: P.CoderType<T>,
  checksum?: TArg<(data: Uint8Array) => Uint8Array>
): P.Coder<T, string> {
  if (typeof name !== 'string') throw new TypeError('name must be a string');
  if (name.length === 0) throw new RangeError('name must be a non-empty string');
  if (typeof lineLen !== 'number') throw new TypeError('lineLen must be a number');
  if (!Number.isSafeInteger(lineLen) || lineLen <= 0)
    throw new RangeError('lineLen must be a positive integer');
  if (!P.utils.isCoder(inner)) throw new TypeError('inner must be a valid base coder');
  if (checksum !== undefined && typeof checksum !== 'function')
    throw new TypeError('checksum must be a function or undefined');
  const checksumFn = checksum as ((data: TArg<Uint8Array>) => Uint8Array) | undefined;
  const codes = { caretReset: 13, newline: 10 };
  const nl = String.fromCharCode(codes.newline);
  const r = String.fromCharCode(codes.caretReset);
  const upcase = name.toUpperCase();
  const markBegin = '-----BEGIN ' + upcase + '-----';
  const markEnd = '-----END ' + upcase + '-----';
  return {
    encode(value: T) {
      const data = inner.encode(value);
      const encoded = base64.encode(data);
      const lines = [];
      for (let i = 0; i < encoded.length; i += lineLen) {
        const s = encoded.slice(i, i + lineLen);
        if (s.length) lines.push(encoded.slice(i, i + lineLen) + nl);
      }
      let body = lines.join('');
      if (checksumFn) body += '=' + base64.encode(checksumFn(data)) + nl;
      return markBegin + nl + nl + body + markEnd + nl;
    },
    decode(s: string): T {
      if (typeof s !== 'string') throw new Error('string expected');
      const beginPos = s.indexOf(markBegin);
      const endPos = s.indexOf(markEnd);
      if (beginPos === -1 || endPos === -1 || beginPos >= endPos)
        throw new Error('invalid armor format');
      let lines = s.replace(markBegin, '').replace(markEnd, '').trim().split(nl);
      lines = lines
        .map((l) => l.replace(r, '').trim())
        .filter((l) => {
          // RFC 4880 §6.2 and RFC 9580 §6.2.2 define `Key: value` Armor
          // Headers as envelope metadata, not base64 payload.
          if (!l || /^[A-Za-z0-9-]+: /.test(l)) return false;
          return true;
        });
      if (lines.length === 0) throw new Error('no data found in armor');
      const last = lines.length - 1;
      // When a checksum callback is supplied and a trailing `=...` line exists,
      // verify it strictly. Absence remains accepted for checksumless RFC 9580
      // armor vectors; protocols requiring a checksum must enforce it above.
      if (checksumFn && lines[last].startsWith('=')) {
        const body = base64.decode(lines.slice(0, -1).join(''));
        const cs = lines[last].slice(1);
        const realCS = base64.encode(checksumFn(body));
        if (realCS !== cs) throw new Error('invalid checksum ' + cs + 'instead of ' + realCS);
        return inner.decode(body);
      }
      return inner.decode(base64.decode(lines.join('')));
    },
  };
}

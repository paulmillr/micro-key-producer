/*! micro-key-producer - MIT License (c) 2024 Paul Miller (paulmillr.com) */
/**
 * Utilities.
 * @module
 */
import { abytes, randomBytes as nobleRandomBytes } from '@noble/hashes/utils.js';
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
 * Asserts something is a string.
 * @param value - Value to validate.
 * @param title - Label included in thrown errors.
 * @returns The validated string.
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * Validate a label string.
 *
 * ```ts
 * astring('example', 'label');
 * ```
 */
export function astring(value: unknown, title: string = ''): string {
  if (typeof value !== 'string') {
    const prefix = title && `"${title}" `;
    throw new TypeError(prefix + 'expected string, got type=' + typeof value);
  }
  return value;
}

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
 * Composes two coders: `encode` runs inner then outer, `decode` runs them in reverse.
 * Replaces `utils.chain` removed from `@scure/base` 2.3.
 * @param inner - Coder applied first on encode.
 * @param outer - Coder applied second on encode.
 * @returns Combined coder.
 * @example
 * Chain a fixed-width integer coder with base64url.
 * ```ts
 * import { base64urlnopad } from '@scure/base';
 * import { chainCoders } from 'micro-key-producer/utils.js';
 * chainCoders(numCoder, base64urlnopad);
 * ```
 */
export function chainCoders<F, M, T>(
  inner: { encode: (from: F) => M; decode: (to: M) => F },
  outer: { encode: (from: M) => T; decode: (to: T) => M }
): { encode: (from: F) => T; decode: (to: T) => F } {
  return {
    encode: (from: F): T => outer.encode(inner.encode(from)),
    decode: (to: T): F => inner.decode(outer.decode(to)),
  };
}

// TEMPORARY: vendored from @scure/base (see base-base36.patch), which dropped the
// `utils.radix`/`alphabet` builders in 2.3 and does not export base36 yet. Delete this
// and `import { base36 } from '@scure/base'` once a release ships it.
// -----------
// Base conversion 256 <-> 36 done on 16-bit limbs, five base36 digits (one divmod by
// 36**5) per pass, ~10x fewer inner-loop iterations than digit-at-a-time conversion.
// Exactness: every intermediate is a non-negative integer below 2**53, so float64
// arithmetic (including Math.floor of the quotients) is exact:
// - encode: carry * 2**16 + limb < 36**5 * 2**16 < 2**42
// - decode: limb * 36**5 + carry < 2**16 * 36**5 + 2**26 < 2**42
// O(n^2) like any positional-base conversion: only for small constant-size inputs.
const B36_GROUP = 60466176; // 36**5 < 2**26; literal so bundlers can drop it as dead code
const B36_LETTERS = '0123456789abcdefghijklmnopqrstuvwxyz';

/**
 * base36: lowercase alphanumeric, big-endian positional (multibase `k` payload,
 * used by e.g. IPNS/CIDv1). Leading zero bytes map to leading `0` digits.
 * @example
 * Encode an IPNS multicodec key payload.
 * ```ts
 * import { base36 } from 'micro-key-producer/utils.js';
 * base36.decode(base36.encode(new Uint8Array([0, 1, 2])));
 * ```
 */
export const base36: {
  encode: (from: Uint8Array) => string;
  decode: (to: string) => Uint8Array;
} = {
  encode: (from: Uint8Array): string => {
    abytes(from, undefined, 'base36 bytes');
    const blen = from.length;
    if (blen === 0) return '';
    // Leading zero bytes map 1:1 to leading zero digits (at most blen-1 explicit zeros;
    // an all-zero value still contributes one digit below).
    let zeros = 0;
    while (zeros < blen - 1 && from[zeros] === 0) zeros++;
    // Pack big-endian 16-bit limbs; odd length makes the top limb a single byte.
    const nlimbs = Math.ceil(blen / 2);
    const limbs = new Uint16Array(nlimbs);
    const odd = blen & 1;
    if (odd) limbs[0] = from[0]!;
    for (let i = odd, j = odd; i < blen; i += 2, j++) limbs[j] = (from[i]! << 8) | from[i + 1]!;
    // Repeated divmod by 36**5; each pass emits one 5-digit group, least significant first.
    const groups: number[] = [];
    let pos = 0; // limbs before pos are known zero
    while (pos < nlimbs) {
      let carry = 0;
      for (let i = pos; i < nlimbs; i++) {
        const cur = carry * 0x10000 + limbs[i]!;
        const q = Math.floor(cur / B36_GROUP);
        carry = cur - q * B36_GROUP;
        limbs[i] = q;
        if (q === 0 && i === pos) pos++;
      }
      groups.push(carry);
    }
    // The top group is nonzero unless the whole value is zero, so total significant digit
    // count is 5 per full group plus the top group's own width.
    const top = groups.length - 1;
    let sig = top * 5;
    for (let v = groups[top]!; ; v = Math.floor(v / 36)) {
      sig++;
      if (v < 36) break;
    }
    const digits = new Uint8Array(zeros + sig); // leading zero digits are already 0
    let j = digits.length - 1;
    for (let g = 0; g < top; g++) {
      let v = groups[g]!;
      for (let k = 0; k < 5; k++) {
        digits[j--] = v % 36;
        v = Math.floor(v / 36);
      }
    }
    for (let v = groups[top]!; j >= zeros; v = Math.floor(v / 36)) digits[j--] = v % 36;
    let res = '';
    for (const d of digits) res += B36_LETTERS[d]!;
    return res;
  },
  decode: (to: string): Uint8Array => {
    astring(to, 'base36 string');
    const dlen = to.length;
    if (dlen === 0) return new Uint8Array(0);
    if (dlen >= 65536) throw new Error('invalid length');
    const digits = new Uint8Array(dlen);
    for (let i = 0; i < dlen; i++) {
      const d = B36_LETTERS.indexOf(to[i]!);
      if (d < 0) throw new Error(`invalid base36 character "${to[i]}"`);
      digits[i] = d;
    }
    let zeros = 0;
    while (zeros < dlen - 1 && digits[zeros] === 0) zeros++;
    // Multiply-accumulate 16-bit limbs (little-endian, `used` live) group by group, most
    // significant group first; the first group may be shorter than 5 digits, and its
    // 36**group factor falls out of the digit fold. 6 bits/digit over-allocates safely.
    const limbs = new Uint16Array(Math.ceil((dlen * 6) / 16) + 1);
    let used = 0;
    let i = 0;
    let group = dlen % 5 || 5;
    while (i < dlen) {
      let gval = 0;
      let factor = 1;
      for (const end = i + group; i < end; i++) {
        gval = gval * 36 + digits[i]!;
        factor *= 36;
      }
      group = 5;
      let carry = gval;
      for (let k = 0; k < used; k++) {
        const cur = limbs[k]! * factor + carry;
        carry = Math.floor(cur / 0x10000);
        limbs[k] = cur - carry * 0x10000;
      }
      for (; carry > 0; carry = Math.floor(carry / 0x10000)) limbs[used++] = carry % 0x10000;
    }
    // used === 0 means the value is zero: it still contributes one byte, like a lone
    // zero digit does.
    const valueBytes = used === 0 ? 1 : used * 2 - (limbs[used - 1]! < 256 ? 1 : 0);
    const res = new Uint8Array(zeros + valueBytes); // leading zero bytes are already 0
    let j = res.length - 1;
    for (let k = 0; k < used; k++) {
      const limb = limbs[k]!;
      res[j--] = limb & 0xff;
      if (j >= zeros) res[j--] = limb >> 8;
    }
    return res;
  },
};

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

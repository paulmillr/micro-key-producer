import { randomBytes } from '@noble/hashes/utils';
import { Coder, CoderType, utils as pkUtils } from 'micro-packed';
import { base64 } from '@scure/base';
export { randomBytes };

/**
 * Base64-armored values are commonly used in cryptographic applications, such as PGP and SSH.
 * @param name - The name of the armored value.
 * @param lineLen - Maximum line length for the armored value (e.g., 64 for GPG, 70 for SSH).
 * @param inner - Inner CoderType for the value.
 * @param checksum - Optional checksum function.
 * @returns Coder representing the base64-armored value.
 * @example
 * // Base64-armored value without checksum
 * const armoredValue = P.base64armor('EXAMPLE', 64, P.bytes(null));
 */
export function base64armor<T>(
  name: string,
  lineLen: number,
  inner: CoderType<T>,
  checksum?: (data: Uint8Array) => Uint8Array
): Coder<T, string> {
  if (typeof name !== 'string' || name.length === 0)
    throw new Error('name must be a non-empty string');
  if (!Number.isSafeInteger(lineLen) || lineLen <= 0)
    throw new Error('lineLen must be a positive integer');
  if (!pkUtils.isCoder(inner)) throw new Error('inner must be a valid base coder');
  if (checksum !== undefined && typeof checksum !== 'function')
    throw new Error('checksum must be a function or undefined');
  const markBegin = `-----BEGIN ${name.toUpperCase()}-----`;
  const markEnd = `-----END ${name.toUpperCase()}-----`;
  return {
    encode(value: T) {
      const data = inner.encode(value);
      const encoded = base64.encode(data);
      const lines = [];
      for (let i = 0; i < encoded.length; i += lineLen) {
        const s = encoded.slice(i, i + lineLen);
        if (s.length) lines.push(`${encoded.slice(i, i + lineLen)}\n`);
      }
      let body = lines.join('');
      if (checksum) body += `=${base64.encode(checksum(data))}\n`;
      return `${markBegin}\n\n${body}${markEnd}\n`;
    },
    decode(s: string): T {
      if (typeof s !== 'string') throw new Error('string expected');
      const beginPos = s.indexOf(markBegin);
      const endPos = s.indexOf(markEnd);
      if (beginPos === -1 || endPos === -1 || beginPos >= endPos)
        throw new Error('invalid armor format');
      let lines = s.replace(markBegin, '').replace(markEnd, '').trim().split('\n');
      if (lines.length === 0) throw new Error('no data found in armor');
      lines = lines.map((l) => l.replace('\r', '').trim());
      const last = lines.length - 1;
      if (checksum && lines[last].startsWith('=')) {
        const body = base64.decode(lines.slice(0, -1).join(''));
        const cs = lines[last].slice(1);
        const realCS = base64.encode(checksum(body));
        if (realCS !== cs) throw new Error(`invalid checksum ${cs} instead of ${realCS}`);
        return inner.decode(body);
      }
      return inner.decode(base64.decode(lines.join('')));
    },
  };
}

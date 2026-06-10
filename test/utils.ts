import { isBytes } from '@noble/hashes/utils.js';

export const deepClone = <T>(value: T): T => {
  // Bun 1.3.12 structuredClone throws on decoded packet/cert objects; tests need only data clones.
  if (isBytes(value)) return Uint8Array.from(value) as T;
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(deepClone) as T;
  const out: Record<string, unknown> = {};
  for (const k in value) {
    if (Object.prototype.hasOwnProperty.call(value, k)) out[k] = deepClone(value[k]);
  }
  return out as T;
};

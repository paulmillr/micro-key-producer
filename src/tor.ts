/*! micro-key-producer - MIT License (c) 2024 Paul Miller (paulmillr.com) */
/**
 * Deterministic producer of TOR keys + addressses.
 * @module
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { concatBytes } from '@noble/hashes/utils.js';
import { base32, base64, utf8 } from '@scure/base';

const ADDRESS_VERSION = Uint8Array.of(0x03);

/**
 * Formats a Tor v3 onion address from an ed25519 public key.
 * @param pubBytes - Raw ed25519 public key bytes.
 * @returns `.onion` address.
 * @example
 * Convert the exported Tor public key bytes into the user-facing `.onion` address.
 * ```ts
 * import { randomBytes } from '@noble/hashes/utils.js';
 * import { formatPublicKey, getKeys } from 'micro-key-producer/tor.js';
 * const seed = randomBytes(32);
 * formatPublicKey(getKeys(seed).publicKeyBytes);
 * ```
 */
export function formatPublicKey(pubBytes: Uint8Array): string {
  // checksum = H(".onion checksum" || pubkey || version)
  const checksum = sha3_256(concatBytes(utf8.decode('.onion checksum'), pubBytes, ADDRESS_VERSION));
  // onion_address = base32(pubkey || checksum || version);
  const addr = concatBytes(pubBytes, checksum.slice(0, 2), ADDRESS_VERSION);
  return `${base32.encode(addr).toLowerCase()}.onion`;
}

/**
 * Parses a Tor v3 onion address back into its public key bytes.
 * @param address - `.onion` address.
 * @returns Raw ed25519 public key bytes.
 * @throws If the onion suffix or checksum is invalid. {@link Error}
 * @example
 * Recover the raw public key bytes from the published `.onion` address.
 * ```ts
 * import { randomBytes } from '@noble/hashes/utils.js';
 * import { getKeys, parseAddress } from 'micro-key-producer/tor.js';
 * const seed = randomBytes(32);
 * parseAddress(getKeys(seed).publicKey);
 * ```
 */
export function parseAddress(address: string): Uint8Array {
  if (!address.endsWith('.onion')) throw new Error('Address must end with .onion');
  const addr = base32.decode(address.replace(/\.onion$/, '').toUpperCase());
  // skip last 3 bytes
  const skip = addr.slice(0, addr.length - 3);
  const key = formatPublicKey(skip);
  if (key !== address) throw new Error('Invalid checksum');
  return skip;
}

/**
 * Derives Tor v3 key material from an ed25519 seed.
 * @param seed - 32-byte ed25519 seed.
 * @returns Public key bytes, onion address, and Tor private key string.
 * @example
 * Start from a seed and export both the onion address and Tor private-key text.
 * ```ts
 * import { randomBytes } from '@noble/hashes/utils.js';
 * import { getKeys } from 'micro-key-producer/tor.js';
 * const seed = randomBytes(32);
 * getKeys(seed).publicKey;
 * ```
 */
export function getKeys(seed: Uint8Array): {
  publicKeyBytes: Uint8Array;
  publicKey: string;
  privateKey: string;
} {
  const { head, prefix, pointBytes } = ed25519.utils.getExtendedPublicKey(seed);
  const added = concatBytes(head, prefix);
  return {
    publicKeyBytes: pointBytes,
    publicKey: formatPublicKey(pointBytes),
    privateKey: `ED25519-V3:${base64.encode(added)}`,
  };
}

export default getKeys;

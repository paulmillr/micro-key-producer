/*! micro-key-producer - MIT License (c) 2024 Paul Miller (paulmillr.com) */
/**
 * IPNS (IPFS) key / address producer.
 * @module
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { concatBytes } from '@noble/hashes/utils.js';
import { base32, hex, utils } from '@scure/base';

const base36 = utils.chain(
  utils.radix(36),
  utils.alphabet('0123456789abcdefghijklmnopqrstuvwxyz'),
  utils.padding(0),
  utils.join('')
);

/**
 * Formats an IPNS public key into the canonical `ipns://k...` form.
 * @param pubBytes - Encoded multicodec public key bytes.
 * @returns Base36 IPNS address string.
 * @example
 * Round-trip an IPNS address string back to bytes and into the canonical display form.
 * ```ts
 * import { randomBytes } from '@noble/hashes/utils.js';
 * import { formatPublicKey, getKeys, parseAddress } from 'micro-key-producer/ipns.js';
 * const seed = randomBytes(32);
 * formatPublicKey(parseAddress(getKeys(seed).base36));
 * ```
 */
export function formatPublicKey(pubBytes: Uint8Array): string {
  return `ipns://k${base36.encode(pubBytes)}`;
}

/**
 * Takes an IPNS pubkey (address) string as input and returns bytes array of the key.
 * Supports various formats ('ipns://k', 'ipns://b', 'ipns://f').
 * Handles decoding and validation of the key before returning pubkey bytes
 * @param address - IPNS address in base36, base32, or base16 form.
 * @returns Decoded multicodec public key bytes.
 * @throws If the IPNS address format or key prefix is invalid. {@link Error}
 * @example
 * Parse any exported IPNS address back into the multicodec public-key bytes.
 * ```ts
 * import { randomBytes } from '@noble/hashes/utils.js';
 * import { getKeys, parseAddress } from 'micro-key-producer/ipns.js';
 * const seed = randomBytes(32);
 * parseAddress(getKeys(seed).base36);
 * ```
 */
export function parseAddress(address: string): Uint8Array {
  address = address.toLowerCase();
  if (address.startsWith('ipns://')) address = address.slice(7);
  let hexKey;
  if (address.startsWith('k')) {
    // Decode base-36 pubkey (after removing 'k' prefix) and encode it as a hex string
    hexKey = hex.encode(base36.decode(address.slice(1)));
  } else if (address.startsWith('b')) {
    // Decode base-32 pubkey (after removing 'b' prefix) and encode it as a hex string
    hexKey = hex.encode(base32.decode(address.slice(1).toUpperCase()));
  } else if (address.startsWith('f')) {
    hexKey = address.slice(1);
  } else throw new Error('Unsupported Base-X Format'); // Throw error if pubkey format is not supported

  // Check if hexKey has expected prefix '0172002408011220' and length of 80
  if (hexKey.startsWith('0172002408011220') && hexKey.length === 80) {
    return hex.decode(hexKey);
  }
  // Throw error if IPNS key prefix is invalid
  throw new Error('Invalid IPNS Key Prefix: ' + hexKey);
}

/** Deterministic IPNS key material in several address encodings. */
export type IpnsKeys = {
  /** Hex-encoded multicodec public key with `0x` prefix. */
  publicKey: string;
  /** Hex-encoded multicodec private key with `0x` prefix. */
  privateKey: string;
  /** Canonical base36 `ipns://k...` address. */
  base36: string;
  /** Base32 `ipns://b...` address. */
  base32: string;
  /** Base16 `ipns://f...` address. */
  base16: string;
  /** EIP-1577 contenthash form of the same key. */
  contenthash: string;
};
/**
 * Derives IPNS key material from an ed25519 seed.
 * @param seed - 32-byte ed25519 seed.
 * @returns Public and private key encodings plus multiple IPNS address formats.
 * @throws On wrong seed length. {@link TypeError}
 * @example
 * Start from a fresh Ed25519 seed and export all supported IPNS address forms.
 * ```ts
 * import { randomBytes } from '@noble/hashes/utils.js';
 * import { getKeys } from 'micro-key-producer/ipns.js';
 * const seed = randomBytes(32);
 * getKeys(seed).contenthash;
 * ```
 */
export function getKeys(seed: Uint8Array): IpnsKeys {
  //? privKey "seed" should be checked for <ed25519.curve.n?
  if (seed.length !== 32) throw new TypeError('Seed must be 32 bytes in length');
  // Generate ed25519 public key from seed
  const pubKey = ed25519.getPublicKey(seed);
  // Create public key bytes by concatenating prefix bytes and pubKey
  const pubKeyBytes = concatBytes(
    Uint8Array.from([0x01, 0x72, 0x00, 0x24, 0x08, 0x01, 0x12, 0x20]),
    pubKey
  );
  const hexKey = hex.encode(pubKeyBytes).toLowerCase();
  // Return different representations of the keys
  return {
    publicKey: `0x${hexKey}`,
    privateKey: `0x${hex.encode(
      concatBytes(Uint8Array.from([0x08, 0x01, 0x12, 0x40]), seed, pubKey)
    )}`,
    base36: `ipns://k${base36.encode(pubKeyBytes)}`,
    base32: `ipns://b${base32.encode(pubKeyBytes).toLowerCase()}`,
    base16: `ipns://f${hexKey}`,
    contenthash: `0xe501${hexKey}`,
  };
}

/**
 * Default export for deterministic IPNS key derivation.
 * @param seed - 32-byte ed25519 seed.
 * @returns Public and private key encodings plus multiple IPNS address formats.
 * @throws On wrong seed length. {@link TypeError}
 * @example
 * Use the default export when you only need the derived IPNS key bundle.
 * ```ts
 * import getKeys from 'micro-key-producer/ipns.js';
 * import { randomBytes } from '@noble/hashes/utils.js';
 * const seed = randomBytes(32);
 * getKeys(seed).base36;
 * ```
 */
export default getKeys;

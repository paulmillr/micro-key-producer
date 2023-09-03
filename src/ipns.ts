import { ed25519 } from '@noble/curves/ed25519';
import { concatBytes } from '@noble/hashes/utils';
import { hex, base32, utils } from '@scure/base';

const base36 = utils.chain(
  utils.radix(36),
  utils.alphabet('0123456789abcdefghijklmnopqrstuvwxyz'),
  utils.padding(0),
  utils.join('')
);

// Formats IPNS public key in bytes array format to 'ipns://k...' string format
export function formatPublicKey(pubBytes: Uint8Array) {
  return `ipns://k${base36.encode(pubBytes)}`;
}

// Takes an IPNS pubkey (address) string as input and returns bytes array of the key
// Supports various formats ('ipns://k', 'ipns://b', 'ipns://f')
// Handles decoding and validation of the key before returning pubkey bytes
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

// Generates an ed25519 pubkey from a seed and converts it to several IPNS pubkey formats
export async function getKeys(seed: Uint8Array) {
  //? privKey "seed" should be checked for <ed25519.curve.n?
  if (seed.length != 32) throw new TypeError('Seed must be 32 bytes in length');
  // Generate ed25519 public key from seed
  const pubKey = await ed25519.getPublicKey(seed);
  // Create public key bytes by concatenating prefix bytes and pubKey
  const pubKeyBytes = concatBytes(
    new Uint8Array([0x01, 0x72, 0x00, 0x24, 0x08, 0x01, 0x12, 0x20]),
    pubKey
  );
  const hexKey = hex.encode(pubKeyBytes).toLowerCase();
  // Return different representations of the keys
  return {
    publicKey: `0x${hexKey}`,
    privateKey: `0x${hex.encode(
      concatBytes(new Uint8Array([0x08, 0x01, 0x12, 0x40]), seed, pubKey)
    )}`,
    base36: `ipns://k${base36.encode(pubKeyBytes)}`,
    base32: `ipns://b${base32.encode(pubKeyBytes).toLowerCase()}`,
    base16: `ipns://f${hexKey}`,
    contenthash: `0xe501${hexKey}`,
  };
}

export default getKeys;

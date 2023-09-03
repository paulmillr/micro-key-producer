import { ed25519 } from '@noble/curves/ed25519';
import { sha3_256 } from '@noble/hashes/sha3';
import { concatBytes } from '@noble/hashes/utils';
import { utf8, base32, base64 } from '@scure/base';

const ADDRESS_VERSION = new Uint8Array([0x03]);

export function formatPublicKey(pubBytes: Uint8Array) {
  // checksum = H(".onion checksum" || pubkey || version)
  const checksum = sha3_256(concatBytes(utf8.decode('.onion checksum'), pubBytes, ADDRESS_VERSION));
  // onion_address = base32(pubkey || checksum || version);
  const addr = concatBytes(pubBytes, checksum.slice(0, 2), ADDRESS_VERSION);
  return `${base32.encode(addr).toLowerCase()}.onion`;
}

export function parseAddress(address: string): Uint8Array {
  if (!address.endsWith('.onion')) throw new Error('Address must end with .onion');
  const addr = base32.decode(address.replace(/\.onion$/, '').toUpperCase());
  // skip last 3 bytes
  const skip = addr.slice(0, addr.length - 3);
  const key = formatPublicKey(skip);
  if (key !== address) throw new Error('Invalid checksum');
  return skip;
}

export async function getKeys(seed: Uint8Array) {
  const { head, prefix, pointBytes } = await ed25519.utils.getExtendedPublicKey(seed);
  const added = concatBytes(head, prefix);
  return {
    publicKeyBytes: pointBytes,
    publicKey: formatPublicKey(pointBytes),
    privateKey: `ED25519-V3:${base64.encode(added)}`,
  };
}

export default getKeys;

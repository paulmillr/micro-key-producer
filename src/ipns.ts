import { ed25519 } from '@noble/curves/ed25519';
import { hex, base32 } from '@scure/base';
import { concatBytes } from 'micro-packed';

const ADDRESS_VERSION = new Uint8Array([0x03]);
//const NAMESPACE = new Uint8Array([0xe5]);

export function formatPublicKey(pubBytes: Uint8Array) {
  return `k${BigInt('0x'+hex.encode(pubBytes).toLowerCase()).toString(36)}`;
}

export function parseAddress(address: string): Uint8Array {
  if (address.startsWith('ipns://')) address = address.slice(7);
  let hexKey;
  if(address.startsWith("k")){ 
    const b36 = "0123456789abcdefghijklmnopqrstuvwxyz";
    let result = 0n;
    for (let i = 1; i < address.length;) {
      result = result * 36n + BigInt(b36.indexOf(address.charAt(i++)));
    }
    hexKey = result.toString(16).padStart(80, "0");
  }
  else if (address.startsWith('b')) 
    hexKey = hex.encode(base32.decode(address.slice(1).toUpperCase()));
  else if (address.startsWith('f')) 
    hexKey = address.slice(1);
  else 
    throw new Error('Unsupported Base-X Format');

  if (!hexKey.startsWith('0172002408011220') || hexKey.length != 80)
    throw new Error('Invalid IPNS Key Prefix: '+ hexKey);
  return hex.decode(hexKey);
}

export async function getKeys(seed: Uint8Array) {
  //? privKey "seed" should be checked for <ed25519.curve.n?
  if (seed.length != 32) throw new TypeError('Seed must be 32 bytes in length');
  const pubKey = await ed25519.getPublicKey(seed);
  // https://github.com/multiformats/multicodec/blob/master/table.csv
  // 0x01 = v1, 0x72 = libp2p-key, ?0x00240801 = ?ed25519 key/type, 0x12 = ?sha256, 0x20 = 32 bytes length
  const pubKeyBytes = concatBytes([0x01, 0x72, 0x00, 0x24, 0x08, 0x01, 0x12, 0x20], pubKey);
  const hexKey = hex.encode(pubKeyBytes).toLowerCase().padStart(80, "0");
  return {
    publicKey: `0x${hexKey}`,
    privateKey: `0x${hex.encode(concatBytes([0x08, 0x01, 0x12, 0x40], seed, pubKey))}`,
    base36: `ipns://k${BigInt('0x'+hexKey.toString()).toString(36)}`,
    base32: `ipns://b${base32.encode(pubKeyBytes).toLowerCase()}`,
    base16: `ipns://f${hexKey}`,
    contenthash: `0xe501${hexKey}`,
  };
}

export default getKeys;

import { ed25519 } from '@noble/curves/ed25519';
import {hex, base32} from '@scure/base';
import { concatBytes } from 'micro-packed';

const ADDRESS_VERSION = new Uint8Array([0x03]);
//const NAMESPACE = new Uint8Array([0xe5]);

export function formatPublicKey(pubBytes: Uint8Array) {
  // base36 is recommended for subdomain 
  // base32 is 65 chars long
  return `b${base32.encode(pubBytes).toLowerCase()}`;
}

export function parseAddress(address: string): Uint8Array {
  if(address.startsWith("ipns://")) 
    address = address.slice(7);
  let hexKey;
  // if(address.startsWith("k")){ // recommended format is base36
  //  addr = base36.decode(address.slice(1,));
  // else 
  // if(address.startsWith("5")){//?old base58 without prefix
  //  addr = base58.decode(address.slice(1,));
  // else 
  if (address.startsWith("b"))
    hexKey = hex.encode(base32.decode(address.slice(1,).toUpperCase()));
  else if (address.startsWith("f"))
    hexKey = address.slice(1,);
  else throw new Error("Unsupported IPNS Format");  
  
  if(!hexKey.startsWith("0172002408011220") || hexKey.length != 80)
    throw new Error("Invalid IPNS Key");
  return hex.decode(hexKey);
}

export async function getKeys(seed: Uint8Array) {
  //? privKey "seed" should be checked for <ed25519.curve.n?
  if (seed.length != 32) throw new TypeError("Seed must be 32 bytes in length");
  const pubKey = await ed25519.getPublicKey(seed);
  // https://github.com/multiformats/multicodec/blob/master/table.csv
  // 0x01 = v1, 0x72 = libp2p-key, ?0x00240801 = ?ed25519 key/type, 0x12 = ?sha256, 0x20 = 32 bytes length
  const pubKeyBytes = concatBytes([0x01, 0x72, 0x00, 0x24, 0x08, 0x01, 0x12, 0x20], pubKey);
  const b16 = hex.encode(pubKeyBytes).toLowerCase();
  return {
    publicKey: `0x${b16}`,
    privateKey: `0x${hex.encode(concatBytes([0x08, 0x01, 0x12, 0x40], seed, pubKey))}`,
    //b58/ old format, not recommended
    //base58: `${base58.encode(pubKeyBytes)}`,
    //b36/ subdomain safe,recommended, ??scure/base36?
    //base36: `k${base36.encode(pubKeyBytes).toLowerCase()}`, 
    //b32/ >63 char long for direct subdomain support
    base32: `b${base32.encode(pubKeyBytes).toLowerCase()}`,
    //b16/ internal hex format
    base16: `f${b16}`, 
    // Public IPFS gateway
    //gateway: `https://k${base36.encode(pubKeyBytes).toLowerCase()}.ipns.dweb.link`,
    //gateway: `https://ipfs.io/ipns/b${base32.encode(pubKeyBytes).toLowercase()`,
    contenthash: `0xe501${b16}` // ENS contenthash, 0xe5 = ipns namespace
  };
}

export default getKeys;

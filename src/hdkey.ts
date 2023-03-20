/*! micro-ed25519-hdkey - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { ed25519 } from '@noble/curves/ed25519';
import { hmac } from '@noble/hashes/hmac';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import { concatBytes, createView, hexToBytes, utf8ToBytes, bytesToHex } from '@noble/hashes/utils';
import { bytes as assertBytes } from '@noble/hashes/_assert';

export const MASTER_SECRET = utf8ToBytes('ed25519 seed');
export const HARDENED_OFFSET: number = 0x80000000;
const ZERO = new Uint8Array([0]);

type Hex = Uint8Array | string;
function ensureBytes(b: Hex, ...lengths: number[]): Uint8Array {
  if (typeof b === 'string') b = hexToBytes(b);
  assertBytes(b, ...lengths);
  return b;
}

const hash160 = (data: Uint8Array) => ripemd160(sha256(data));
const fromU32 = (data: Uint8Array) => createView(data).getUint32(0, false);
const toU32 = (n: number) => {
  if (!Number.isSafeInteger(n) || n < 0 || n > 2 ** 32 - 1) {
    throw new Error(`Invalid number=${n}. Should be from 0 to 2 ** 32 - 1`);
  }
  const buf = new Uint8Array(4);
  createView(buf).setUint32(0, n, false);
  return buf;
};

interface HDKeyOpt {
  depth?: number;
  index?: number;
  parentFingerprint?: number;
  chainCode: Uint8Array;
  privateKey: Uint8Array;
}

export class HDKey {
  get publicKeyRaw(): Uint8Array {
    return ed25519.getPublicKey(this.privateKey);
  }
  get publicKey(): Uint8Array {
    return concatBytes(ZERO, this.publicKeyRaw);
  }
  get pubHash(): Uint8Array {
    return hash160(this.publicKey);
  }
  get fingerprint(): number {
    return fromU32(this.pubHash);
  }
  get fingerprintHex(): string {
    return bytesToHex(toU32(this.fingerprint));
  }
  get parentFingerprintHex(): string {
    return bytesToHex(toU32(this.parentFingerprint));
  }

  static fromMasterSeed(seed: Hex): HDKey {
    seed = ensureBytes(seed);
    if (8 * seed.length < 128 || 8 * seed.length > 512) {
      throw new Error(
        `HDKey: wrong seed length=${seed.length}. Should be between 128 and 512 bits; 256 bits is advised)`
      );
    }
    const I = hmac(sha512, MASTER_SECRET, seed);
    return new HDKey({
      privateKey: I.slice(0, 32),
      chainCode: I.slice(32),
    });
  }

  readonly depth: number = 0;
  readonly index: number = 0;
  readonly chainCode: Uint8Array;
  readonly parentFingerprint: number = 0;
  readonly privateKey: Uint8Array;

  constructor(opt: HDKeyOpt) {
    if (!opt || typeof opt !== 'object')
      throw new Error('HDKey.constructor must not be called directly');
    assertBytes(opt.privateKey, 32);
    assertBytes(opt.chainCode, 32);
    this.depth = opt.depth || 0;
    this.index = opt.index || 0;
    this.parentFingerprint = opt.parentFingerprint || 0;
    if (!this.depth) {
      if (this.parentFingerprint || this.index)
        throw new Error('HDKey: zero depth with non-zero index/parent fingerprint');
    }
    this.chainCode = opt.chainCode;
    this.privateKey = opt.privateKey;
  }

  derive(path: string, forceHardened = false): HDKey {
    if (!/^[mM]'?/.test(path)) throw new Error('Path must start with "m" or "M"');
    if (/^[mM]'?$/.test(path)) return this;
    const parts = path.replace(/^[mM]'?\//, '').split('/');
    // tslint:disable-next-line
    let child: HDKey = this;
    for (const c of parts) {
      const m = /^(\d+)('?)$/.exec(c);
      if (!m || m.length !== 3) throw new Error(`Invalid child index: ${c}`);
      let idx = +m[1];
      if (!Number.isSafeInteger(idx) || idx >= HARDENED_OFFSET) throw new Error('Invalid index');
      // hardened key
      if (forceHardened || m[2] === "'") idx += HARDENED_OFFSET;
      child = child.deriveChild(idx);
    }
    return child;
  }

  deriveChild(index: number): HDKey {
    if (index < HARDENED_OFFSET)
      throw new Error(`Non-hardened child derivation not possible for Ed25519 (index=${index})`);
    // Hardened child: 0x00 || ser256(kpar) || ser32(index)
    const data = concatBytes(ZERO, this.privateKey, toU32(index));
    const I = hmac(sha512, this.chainCode, data);
    return new HDKey({
      chainCode: I.slice(32),
      depth: this.depth + 1,
      parentFingerprint: this.fingerprint,
      index,
      privateKey: I.slice(0, 32),
    });
  }

  sign(message: Hex): Uint8Array {
    return ed25519.sign(message, this.privateKey);
  }

  verify(message: Hex, signature: Hex): boolean {
    signature = ensureBytes(signature, 64);
    return ed25519.verify(signature, message, this.publicKeyRaw);
  }
}

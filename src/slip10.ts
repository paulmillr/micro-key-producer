/*! micro-key-producer - MIT License (c) 2024 Paul Miller (paulmillr.com) */
/**
 * Allows to work with SLIP-0010 HD keys.
 * @module
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { hmac } from '@noble/hashes/hmac.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import {
  abytes,
  bytesToHex,
  concatBytes,
  createView,
  type TRet,
  utf8ToBytes,
} from '@noble/hashes/utils.js';

// treeshake: standalone constants should not keep the derivation helpers in tiny entry bundles.
/** SLIP-0010 master secret label for ed25519 keys. */
export const MASTER_SECRET: TRet<Uint8Array> = /* @__PURE__ */ (() =>
  utf8ToBytes('ed25519 seed'))();
/** Hardened child index offset. */
export const HARDENED_OFFSET: number = 0x80000000;
// SLIP-0010 / BIP-0032 hardened private derivation prefixes ser256(kpar) with a
// literal 0x00 pad byte to reach 33 bytes.
const ZERO = /* @__PURE__ */ (() => Uint8Array.of(0))();

// BIP-0032 ser32(i) writes child numbers and parent fingerprints as unsigned
// 32-bit big-endian bytes.
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

/**
 * HD key for ed25519, SLIP-0010 format.
 * This surface is the ed25519 private-only, hardened-only subset of SLIP-0010,
 * not a full BIP-0032 xpub/xprv implementation.
 * @param opt - Internal {@link HDKeyOpt} constructor options for derived keys:
 * depth, child index, parent fingerprint, chain code, and private key.
 * @example
 * Start from a master seed, then derive the hardened child path you need.
 * ```ts
 * import { randomBytes } from '@noble/hashes/utils.js';
 * import { HDKey } from 'micro-key-producer/slip10.js';
 * const seed = randomBytes(32);
 * HDKey.fromMasterSeed(seed).derive("m/0'").fingerprintHex;
 * ```
 */
export class HDKey {
  // RFC 8032 public keys are bare 32-byte ENC(A); `publicKey` adds the
  // SLIP-0010/BIP-0032 0x00 prefix below.
  get publicKeyRaw(): Uint8Array {
    return ed25519.getPublicKey(this.privateKey);
  }
  // SLIP-0010 serializes ed25519 public keys as 0x00 || ENC(A), so expose a
  // detached prefixed form here instead of the bare RFC 8032 bytes.
  get publicKey(): Uint8Array {
    return concatBytes(ZERO, this.publicKeyRaw);
  }
  // BIP-0032 key identifiers are HASH160 values over the serialized public key;
  // `fingerprint` truncates this to the first four bytes below.
  get pubHash(): Uint8Array {
    return ripemd160(sha256(this.publicKey));
  }
  // BIP-0032 fingerprints are the unsigned first four bytes of the identifier;
  // `fingerprintHex` below preserves the canonical zero-padded hex text form.
  get fingerprint(): number {
    return createView(this.pubHash).getUint32(0, false);
  }
  // Render the 4-byte fingerprint through ser32 first so the text form stays
  // lowercase and zero-padded to 8 hex characters.
  get fingerprintHex(): string {
    return bytesToHex(toU32(this.fingerprint));
  }
  // Render the stored parent fingerprint through the same 4-byte serializer;
  // master nodes therefore stay at the canonical `00000000`.
  get parentFingerprintHex(): string {
    return bytesToHex(toU32(this.parentFingerprint));
  }

  static fromMasterSeed(seed: Uint8Array): HDKey {
    seed = abytes(seed);
    if (8 * seed.length < 128 || 8 * seed.length > 512) {
      throw new Error(
        `HDKey: wrong seed length=${seed.length}. Should be between 128 and 512 bits; 256 bits is advised)`
      );
    }
    // SLIP-0010 master key generation for ed25519 uses IL directly as the
    // 32-byte private key; unlike secp256k1/P-256 there is no retry loop here.
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
    abytes(opt.privateKey, 32);
    abytes(opt.chainCode, 32);
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
      // Path-string parsing is local convenience; for ed25519, the actual
      // normative boundary is still "derive hardened children only".
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
    // SLIP-0010 ed25519 uses IL directly as the child private key; there is no
    // scalar-add / invalid-child retry path here.
    return new HDKey({
      chainCode: I.slice(32),
      depth: this.depth + 1,
      parentFingerprint: this.fingerprint,
      index,
      privateKey: I.slice(0, 32),
    });
  }

  sign(message: Uint8Array): Uint8Array {
    // RFC 8032 signs with the current 32-byte private key bytes directly; the
    // public key is derived internally from that seed material.
    return ed25519.sign(message, this.privateKey);
  }

  verify(message: Uint8Array, signature: Uint8Array): boolean {
    signature = abytes(signature, 64);
    // RFC 8032 verification consumes the bare 32-byte public key, not the
    // SLIP-0010-prefixed 0x00 || ENC(A) form.
    return ed25519.verify(signature, message, this.publicKeyRaw);
  }
}
export default HDKey;

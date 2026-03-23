/*! micro-key-producer - MIT License (c) 2024 Paul Miller (paulmillr.com) */
/**
 * Deterministic producer of ed25519 SSH keys.
 * @module
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, randomBytes } from '@noble/hashes/utils.js';
import { base64 } from '@scure/base';
import * as P from 'micro-packed';
import { base64armor } from './utils.ts';

/**
 * SSH length-prefixed string coder.
 * @example
 * Encode the SSH string framing used by OpenSSH packets.
 * ```ts
 * import { SSHString } from 'micro-key-producer/ssh.js';
 * SSHString.encode('ssh-ed25519');
 * ```
 */
export const SSHString: P.CoderType<string> = /* @__PURE__ */ P.string(P.U32BE);
/**
 * SSH length-prefixed byte-string coder.
 * @example
 * Encode one SSH binary blob with the standard length prefix.
 * ```ts
 * import { SSHBuf } from 'micro-key-producer/ssh.js';
 * SSHBuf.encode(new Uint8Array([1, 2, 3]));
 * ```
 */
export const SSHBuf: P.CoderType<Uint8Array> = /* @__PURE__ */ P.bytes(P.U32BE);
/**
 * SSH key-type tag coder for `ssh-ed25519`.
 * @example
 * Encode the fixed OpenSSH key type tag for Ed25519 keys.
 * ```ts
 * import { SSHKeyType } from 'micro-key-producer/ssh.js';
 * SSHKeyType.encode(undefined);
 * ```
 */
export const SSHKeyType: P.CoderType<undefined> = /* @__PURE__ */ P.magic(SSHString, 'ssh-ed25519');
/**
 * SSH public-key blob coder.
 * @example
 * Encode the raw public-key blob that OpenSSH places after `ssh-ed25519`.
 * ```ts
 * import { randomBytes } from '@noble/hashes/utils.js';
 * import { PublicKey, getKeys } from 'micro-key-producer/ssh.js';
 * const seed = randomBytes(32);
 * PublicKey.encode({ pubKey: getKeys(seed).publicKeyBytes });
 * ```
 */
export const PublicKey: P.CoderType<
  P.StructInput<{
    keyType: undefined;
    pubKey: Uint8Array;
  }>
> = /* @__PURE__ */ P.struct({ keyType: SSHKeyType, pubKey: /* @__PURE__ */ P.bytes(P.U32BE) });

const PrivateKey = /* @__PURE__ */ P.padRight(
  8,
  /* @__PURE__ */ P.struct({
    check1: /* @__PURE__ */ P.bytes(4),
    check2: /* @__PURE__ */ P.bytes(4),
    keyType: SSHKeyType,
    pubKey: SSHBuf,
    privKey: SSHBuf,
    comment: SSHString,
  }),
  (i: number) => i + 1
);
// https://tools.ietf.org/html/draft-miller-ssh-agent-02#section-4.5
/**
 * SSH agent user-auth request coder.
 * @example
 * Encode the payload that SSH agents sign during public-key authentication.
 * ```ts
 * import { randomBytes } from '@noble/hashes/utils.js';
 * import { AuthData, getKeys } from 'micro-key-producer/ssh.js';
 * const seed = randomBytes(32);
 * AuthData.encode({
 *   nonce: randomBytes(32),
 *   userAuthRequest: 50,
 *   user: 'alice',
 *   conn: 'ssh-connection',
 *   auth: 'publickey',
 *   haveSig: 1,
 *   pubKey: { pubKey: getKeys(seed).publicKeyBytes },
 * });
 * ```
 */
export const AuthData: P.CoderType<
  P.StructInput<{
    nonce: Uint8Array;
    userAuthRequest: number;
    user: string;
    conn: string;
    auth: string;
    haveSig: number;
    keyType: undefined;
    pubKey: P.StructInput<{
      keyType: undefined;
      pubKey: Uint8Array;
    }>;
  }>
> = /* @__PURE__ */ P.struct({
  nonce: SSHBuf,
  userAuthRequest: P.U8, // == 50
  user: SSHString,
  conn: SSHString,
  auth: SSHString,
  haveSig: P.U8, // == 1
  keyType: SSHKeyType,
  pubKey: /* @__PURE__ */ P.prefix(P.U32BE, PublicKey),
});

/** Decoded SSH agent authentication request. */
export type AuthDataType = P.UnwrapCoder<typeof AuthData>;

/**
 * OpenSSH private-key armor coder.
 * @example
 * Decode the armored private key text that `getKeys()` emits.
 * ```ts
 * import { randomBytes } from '@noble/hashes/utils.js';
 * import { PrivateExport, getKeys } from 'micro-key-producer/ssh.js';
 * const seed = randomBytes(32);
 * PrivateExport.decode(getKeys(seed, 'alice@example.com').privateKey);
 * ```
 */
export const PrivateExport: P.Coder<
  P.StructInput<{
    magic: undefined;
    ciphername: undefined;
    kdfname: undefined;
    kdfopts: undefined;
    keys: P.StructInput<{
      pubKey: any;
      privKey: any;
    }>[];
  }>,
  string
> = /* @__PURE__ */ base64armor(
  'openssh private key',
  70,
  /* @__PURE__ */ P.struct({
    magic: /* @__PURE__ */ P.magicBytes('openssh-key-v1\0'),
    // Only decrypted ed25519 keys supported for now
    ciphername: /* @__PURE__ */ P.magic(SSHString, 'none'),
    kdfname: /* @__PURE__ */ P.magic(SSHString, 'none'),
    kdfopts: /* @__PURE__ */ P.magic(SSHString, ''),
    keys: /* @__PURE__ */ P.array(
      P.U32BE,
      /* @__PURE__ */ P.struct({
        pubKey: /* @__PURE__ */ P.prefix(P.U32BE, PublicKey),
        privKey: /* @__PURE__ */ P.prefix(P.U32BE, PrivateKey),
      })
    ),
  })
);

/**
 * Encodes an OpenSSH public key line.
 * @param bytes - Raw ed25519 public key bytes.
 * @param comment - Optional trailing comment.
 * @returns `ssh-ed25519 ...` public key line.
 * @example
 * Render the OpenSSH public key line you can paste into `authorized_keys`.
 * ```ts
 * import { randomBytes } from '@noble/hashes/utils.js';
 * import { formatPublicKey, getKeys } from 'micro-key-producer/ssh.js';
 * const seed = randomBytes(32);
 * formatPublicKey(getKeys(seed).publicKeyBytes, 'alice@example.com');
 * ```
 */
export function formatPublicKey(bytes: Uint8Array, comment?: string): string {
  const blob = PublicKey.encode({ pubKey: bytes });
  return `ssh-ed25519 ${base64.encode(blob)}${comment ? ` ${comment}` : ''}`;
}

/**
 * Computes the OpenSSH SHA-256 fingerprint for a public key.
 * @param bytes - Raw ed25519 public key bytes.
 * @returns SSH fingerprint string.
 * @example
 * Compute the fingerprint shown by `ssh-keygen -l`.
 * ```ts
 * import { randomBytes } from '@noble/hashes/utils.js';
 * import { getFingerprint, getKeys } from 'micro-key-producer/ssh.js';
 * const seed = randomBytes(32);
 * getFingerprint(getKeys(seed).publicKeyBytes);
 * ```
 */
export function getFingerprint(bytes: Uint8Array): string {
  const blob = PublicKey.encode({ pubKey: bytes });
  // ssh-keygen -l -f ~/.ssh/id_ed25519
  // 256 SHA256:+WK/Sl4XJjoxDlAWYuhq4Fl2hka9j3GOUjYczQkqnCI user@comp.local (ED25519)
  return `SHA256:${base64.encode(sha256(blob)).replace(/=$/, '')}`;
}

/**
 * Derives deterministic OpenSSH key material from an ed25519 secret key.
 * @param privateKey - 32-byte ed25519 secret key.
 * @param comment - Optional key comment.
 * @param checkBytes - Optional repeated check bytes for the private-key block.
 * @returns Public key bytes, public key text, fingerprint, and armored private key.
 * @example
 * Export both the public and private OpenSSH key material from one seed.
 * ```ts
 * import { randomBytes } from '@noble/hashes/utils.js';
 * import { getKeys } from 'micro-key-producer/ssh.js';
 * const seed = randomBytes(32);
 * getKeys(seed, 'alice@example.com').privateKey;
 * ```
 */
export function getKeys(
  privateKey: Uint8Array,
  comment?: string,
  checkBytes: Uint8Array = randomBytes(4)
): {
  publicKeyBytes: Uint8Array;
  publicKey: string;
  fingerprint: string;
  privateKey: string;
} {
  const pubKey = ed25519.getPublicKey(privateKey);
  return {
    publicKeyBytes: pubKey,
    publicKey: formatPublicKey(pubKey, comment),
    fingerprint: getFingerprint(pubKey),
    privateKey: PrivateExport.encode({
      keys: [
        {
          pubKey: { pubKey },
          privKey: {
            // Check bytes, should be same
            check1: checkBytes,
            check2: checkBytes,
            pubKey,
            privKey: concatBytes(privateKey, pubKey),
            comment: comment || '',
          },
        },
      ],
    }),
  };
}

/**
 * Signs SSH agent authentication data with an ed25519 private key.
 * @param privateKey - 32-byte ed25519 secret key.
 * @param data - SSH agent authentication payload.
 * @returns Detached signature bytes.
 * @example
 * Sign the SSH agent payload that will be verified against the exported public key.
 * ```ts
 * import { randomBytes } from '@noble/hashes/utils.js';
 * import { authSign, getKeys } from 'micro-key-producer/ssh.js';
 * const seed = randomBytes(32);
 * const keys = getKeys(seed);
 * authSign(seed, {
 *   nonce: randomBytes(32),
 *   userAuthRequest: 50,
 *   user: 'alice',
 *   conn: 'ssh-connection',
 *   auth: 'publickey',
 *   haveSig: 1,
 *   pubKey: { pubKey: keys.publicKeyBytes },
 * });
 * ```
 */
export function authSign(privateKey: Uint8Array, data: AuthDataType): Uint8Array {
  return ed25519.sign(AuthData.encode(data), privateKey);
}

export default getKeys;

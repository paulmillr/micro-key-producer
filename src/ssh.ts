/*! micro-key-producer - MIT License (c) 2024 Paul Miller (paulmillr.com) */
/**
 * Deterministic producer of ed25519 SSH keys.
 * @module
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { equalBytes } from '@noble/curves/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  abytes,
  anumber,
  concatBytes,
  randomBytes,
  type TArg,
  type TRet,
} from '@noble/hashes/utils.js';
import { ascii, base64 } from '@scure/base';
import * as P from 'micro-packed';
import { astring, base64armor, deepFreeze } from './utils.ts';

/**
 * SSH length-prefixed string coder.
 * @example
 * Encode the SSH string framing used by OpenSSH packets.
 * ```ts
 * import { SSHString } from 'micro-key-producer/ssh.js';
 * SSHString.encode('ssh-ed25519');
 * ```
 */
// RFC 4251 SSH "string" values are uint32-length-prefixed byte sequences; this
// helper intentionally exposes the UTF-8 text subset, while SSHBuf below handles
// arbitrary binary payloads.
export const SSHString: P.CoderType<string> = /* @__PURE__ */ deepFreeze(
  /* @__PURE__ */ P.string(P.U32BE)
);
/**
 * SSH length-prefixed byte-string coder.
 * @example
 * Encode one SSH binary blob with the standard length prefix.
 * ```ts
 * import { SSHBuf } from 'micro-key-producer/ssh.js';
 * SSHBuf.encode(new Uint8Array([1, 2, 3]));
 * ```
 */
// RFC 4251 uses the same uint32-length framing for arbitrary binary strings,
// including NUL bytes and other non-text octets, so keep this helper separate
// from SSHString's UTF-8 text boundary.
const SSHBufRaw: P.CoderType<Uint8Array> = /* @__PURE__ */ P.bytes(P.U32BE);
export const SSHBuf: TRet<P.CoderType<Uint8Array>> = /* @__PURE__ */ deepFreeze(
  SSHBufRaw as unknown as TRet<P.CoderType<Uint8Array>>
);
/**
 * SSH key-type tag coder for `ssh-ed25519`.
 * @example
 * Encode the fixed OpenSSH key type tag for Ed25519 keys.
 * ```ts
 * import { SSHKeyType } from 'micro-key-producer/ssh.js';
 * SSHKeyType.encode(undefined);
 * ```
 */
// RFC 8709 fixes the Ed25519 SSH algorithm identifier to the literal SSH string
// "ssh-ed25519", so this helper is just the exact tagged constant over
// SSHString framing.
export const SSHKeyType: P.CoderType<undefined> = /* @__PURE__ */ deepFreeze(
  /* @__PURE__ */ P.magic(SSHString, 'ssh-ed25519')
);
type PublicKeyValue = P.StructInput<{
  keyType: undefined;
  pubKey: Uint8Array;
}>;
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
// RFC 8709 public-key blobs are exactly `string "ssh-ed25519"` plus a second
// SSH string carrying one 32-octet RFC 8032 Ed25519 public key.
const PublicKeyRaw: P.CoderType<PublicKeyValue> = /* @__PURE__ */ P.struct({
  keyType: SSHKeyType,
  pubKey: /* @__PURE__ */ P.bytes(P.U32BE),
});
/** SSH public-key blob coder. */
const PublicKeyChecked: P.CoderType<PublicKeyValue> = /* @__PURE__ */ P.validate(
  PublicKeyRaw,
  (data) => {
    // RFC 8709 §4 defines the ssh-ed25519 public-key blob's second SSH string
    // as the 32-octet RFC 8032 Ed25519 public key, and OpenSSH rejects other
    // widths.
    if (data.pubKey.length !== 32) throw new Error('SSH public key must be 32 bytes');
    return data;
  }
);
export const PublicKey: TRet<P.CoderType<PublicKeyValue>> = /* @__PURE__ */ deepFreeze(
  PublicKeyChecked as unknown as TRet<P.CoderType<PublicKeyValue>>
);

type PrivateKeyValue = P.StructInput<{
  check1: Uint8Array;
  check2: Uint8Array;
  keyType: undefined;
  pubKey: Uint8Array;
  privKey: Uint8Array;
  comment: string;
}>;
const PrivateKeyRaw: P.CoderType<PrivateKeyValue> = /* @__PURE__ */ P.struct({
  // OpenSSH private blocks on this emitted path carry duplicated 4-byte check
  // values, then the Ed25519 public/private blobs, comment, and deterministic
  // 1..n padding.
  check1: /* @__PURE__ */ P.bytes(4),
  check2: /* @__PURE__ */ P.bytes(4),
  keyType: SSHKeyType,
  pubKey: SSHBufRaw,
  privKey: SSHBufRaw,
  comment: SSHString,
});
const privateKeyPadding = (len: number): TRet<Uint8Array> => {
  const padLen = (8 - (len % 8)) % 8;
  return Uint8Array.from({ length: padLen }, (_, i) => i + 1) as TRet<Uint8Array>;
};
const PrivateKeyChecked: P.CoderType<PrivateKeyValue> = /* @__PURE__ */ P.validate(
  PrivateKeyRaw,
  (data) => {
    // The openssh-key-v1 private envelope is not RFC-defined in the local
    // corpus; RFC 8709 §4 fixes the nested ssh-ed25519 public key to 32 octets,
    // and local OpenSSH rejects mismatched checkints or malformed Ed25519
    // private blobs.
    if (!equalBytes(data.check1, data.check2))
      throw new Error('OpenSSH private key check bytes mismatch');
    if (data.pubKey.length !== 32)
      throw new Error('OpenSSH private key public key must be 32 bytes');
    if (data.privKey.length !== 64)
      throw new Error('OpenSSH private key private blob must be 64 bytes');
    // RFC 8032 §5.1.5 derives the Ed25519 public key from the 32-octet private
    // seed, while RFC 8709 §4 serializes that public key as the ssh-ed25519 key
    // field. OpenSSH `ssh-keygen -y` tolerates inconsistent redundant copies,
    // but this decoder exposes one coherent keypair.
    const seed = data.privKey.subarray(0, 32);
    if (!equalBytes(data.privKey.subarray(32), data.pubKey))
      throw new Error('OpenSSH private key embedded public key mismatch');
    if (!equalBytes(ed25519.getPublicKey(seed), data.pubKey))
      throw new Error('OpenSSH private key seed does not match public key');
    return data;
  }
);
const PrivateKey: P.CoderType<PrivateKeyValue> = /* @__PURE__ */ P.apply(
  /* @__PURE__ */ P.struct({
    data: PrivateKeyChecked,
    padding: /* @__PURE__ */ P.bytes(null),
  }),
  {
    encode: (from) => {
      // OpenSSH's private-key envelope padding is not RFC-defined here, but
      // local `ssh-keygen -y` rejects corrupted trailing 1..n padding bytes.
      const expected = privateKeyPadding(PrivateKeyRaw.encode(from.data).length);
      if (!equalBytes(from.padding, expected))
        throw new Error('OpenSSH private key padding mismatch');
      return from.data;
    },
    decode: (data) => ({
      data,
      padding: privateKeyPadding(PrivateKeyRaw.encode(data).length),
    }),
  }
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
type AuthDataValue = P.StructInput<{
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
}>;
const AuthDataRaw: P.CoderType<AuthDataValue> = /* @__PURE__ */ P.struct({
  nonce: SSHBufRaw,
  userAuthRequest: P.U8, // == 50
  user: SSHString,
  conn: SSHString,
  auth: SSHString,
  haveSig: P.U8, // == 1
  keyType: SSHKeyType,
  pubKey: /* @__PURE__ */ P.prefix(P.U32BE, PublicKeyChecked),
});
// RFC 4252 §5 fixes USERAUTH_REQUEST=50 and requires the service/method names
// to be US-ASCII; RFC 4252 §7 fixes signed publickey auth to "publickey" and TRUE.
/** SSH agent user-auth request coder. */
export const AuthData: TRet<P.CoderType<AuthDataValue>> = /* @__PURE__ */ deepFreeze(
  /* @__PURE__ */ P.validate(AuthDataRaw, (data) => {
    if (data.userAuthRequest !== 50)
      throw new Error('SSH AuthData: expected SSH_MSG_USERAUTH_REQUEST=50');
    ascii.decode(data.conn);
    if (data.auth !== 'publickey') throw new Error('SSH AuthData: expected method name publickey');
    if (data.haveSig !== 1) throw new Error('SSH AuthData: expected publickey signature flag TRUE');
    return data;
  }) as unknown as TRet<P.CoderType<AuthDataValue>>
);

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
type PrivateExportValue = P.StructInput<{
  magic: undefined;
  ciphername: undefined;
  kdfname: undefined;
  kdfopts: undefined;
  keys: P.StructInput<{
    pubKey: PublicKeyValue;
    privKey: PrivateKeyValue;
  }>[];
}>;
const PrivateExportRaw: P.CoderType<PrivateExportValue> = /* @__PURE__ */ P.struct({
  magic: /* @__PURE__ */ P.magicBytes('openssh-key-v1\0'),
  // Only decrypted ed25519 keys supported for now
  ciphername: /* @__PURE__ */ P.magic(SSHString, 'none'),
  kdfname: /* @__PURE__ */ P.magic(SSHString, 'none'),
  kdfopts: /* @__PURE__ */ P.magic(SSHString, ''),
  keys: /* @__PURE__ */ P.array(
    P.U32BE,
    /* @__PURE__ */ P.struct({
      pubKey: /* @__PURE__ */ P.prefix(P.U32BE, PublicKeyChecked),
      privKey: /* @__PURE__ */ P.prefix(P.U32BE, PrivateKey),
    })
  ),
});
const PrivateExportSingle: P.CoderType<PrivateExportValue> = /* @__PURE__ */ P.validate(
  PrivateExportRaw,
  (data) => {
    // The OpenSSH private-key envelope is not RFC-defined in the local corpus; this package emits
    // the unencrypted single-key Ed25519 profile, and local OpenSSH rejects nkeys != 1.
    if (data.keys.length !== 1)
      throw new Error('OpenSSH private key envelope must contain exactly one key');
    // The outer public-key list is redundant with the public key inside the
    // private block; local `ssh-keygen -y` rejects mismatched copies.
    const key = data.keys[0]!;
    if (!equalBytes(key.pubKey.pubKey, key.privKey.pubKey))
      throw new Error('OpenSSH private key outer public key mismatch');
    return data;
  }
);
/** OpenSSH private-key armor coder. */
export const PrivateExport: TRet<P.Coder<PrivateExportValue, string>> = /* @__PURE__ */ deepFreeze(
  /* @__PURE__ */ base64armor('openssh private key', 70, PrivateExportSingle) as unknown as TRet<
    P.Coder<PrivateExportValue, string>
  >
);

/**
 * Encodes an OpenSSH public key line.
 * @param bytes - Raw ed25519 public key bytes.
 * @param comment - Optional trailing comment.
 * @returns `ssh-ed25519 ...` public key line.
 * @throws If the key blob or one-line comment is invalid. {@link Error}
 * @example
 * Render the OpenSSH public key line you can paste into `authorized_keys`.
 * ```ts
 * import { randomBytes } from '@noble/hashes/utils.js';
 * import { formatPublicKey, getKeys } from 'micro-key-producer/ssh.js';
 * const seed = randomBytes(32);
 * formatPublicKey(getKeys(seed).publicKeyBytes, 'alice@example.com');
 * ```
 */
export function formatPublicKey(bytes: TArg<Uint8Array>, comment?: string): string {
  bytes = abytes(bytes, 32, 'bytes');
  if (comment !== undefined) comment = astring(comment, 'comment');
  const blob = PublicKey.encode({ pubKey: bytes });
  // RFC 8709 §4 only defines the `ssh-ed25519` public-key blob; OpenSSH
  // .pub/authorized_keys records are one physical line, so reject CR/LF before
  // parsers truncate the trailing comment.
  if (comment && /[\r\n]/.test(comment))
    throw new Error('SSH public key comment cannot contain CR or LF');
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
export function getFingerprint(bytes: TArg<Uint8Array>): string {
  bytes = abytes(bytes, 32, 'bytes');
  const blob = PublicKey.encode({ pubKey: bytes });
  // OpenSSH fingerprints hash the SSH public-key blob, not the bare Ed25519
  // point bytes, and display the SHA-256 digest as unpadded base64 after
  // `SHA256:`.
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
 * @throws If the secret key, check bytes, or public-key comment is invalid. {@link Error}
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
  privateKey: TArg<Uint8Array>,
  comment?: string,
  checkBytes: TArg<Uint8Array> = randomBytes(4)
): TRet<{
  publicKeyBytes: Uint8Array;
  publicKey: string;
  fingerprint: string;
  privateKey: string;
}> {
  privateKey = abytes(privateKey, 32, 'privateKey');
  if (comment !== undefined) comment = astring(comment, 'comment');
  checkBytes = abytes(checkBytes, 4, 'checkBytes');
  const pubKey = ed25519.getPublicKey(privateKey);
  // This wrapper must keep the OpenSSH public line, fingerprint, and
  // private-key armor derived from the same Ed25519 secret so downstream tools
  // see one consistent keypair.
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
export function authSign(privateKey: TArg<Uint8Array>, data: TArg<AuthDataType>): TRet<Uint8Array> {
  privateKey = abytes(privateKey, 32, 'privateKey');
  if (!P.utils.isPlainObject(data))
    throw new TypeError('"data" expected object, got type=' + typeof data);
  abytes((data as AuthDataType).nonce, undefined, 'data.nonce');
  anumber((data as AuthDataType).userAuthRequest, 'data.userAuthRequest');
  if ((data as AuthDataType).userAuthRequest !== 50)
    throw new Error('"data.userAuthRequest" expected SSH_MSG_USERAUTH_REQUEST=50');
  (data as AuthDataType).user = astring((data as AuthDataType).user, 'data.user');
  (data as AuthDataType).conn = astring((data as AuthDataType).conn, 'data.conn');
  (data as AuthDataType).auth = astring((data as AuthDataType).auth, 'data.auth');
  if ((data as AuthDataType).auth !== 'publickey')
    throw new Error('"data.auth" expected method name publickey');
  anumber((data as AuthDataType).haveSig, 'data.haveSig');
  if ((data as AuthDataType).haveSig !== 1)
    throw new Error('"data.haveSig" expected publickey signature flag TRUE');
  if (!P.utils.isPlainObject((data as AuthDataType).pubKey))
    throw new TypeError(
      '"data.pubKey" expected object, got type=' + typeof (data as AuthDataType).pubKey
    );
  abytes((data as AuthDataType).pubKey.pubKey, 32, 'data.pubKey.pubKey');
  // This helper returns the naked 64-byte RFC 8032 Ed25519 signature over the
  // encoded auth payload. Callers that need the SSH wire signature wrapper must
  // add `string "ssh-ed25519"` plus `string signature` themselves.
  return ed25519.sign(AuthData.encode(data as AuthDataType), privateKey);
}

export default getKeys;

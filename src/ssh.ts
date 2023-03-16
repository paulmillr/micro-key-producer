import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { concatBytes } from 'micro-packed';
import * as P from 'micro-packed';
import { base64 } from '@scure/base';
import { randomBytes } from '@noble/hashes/utils';

export const SSHString = P.string(P.U32BE);
export const SSHBuf = P.bytes(P.U32BE);
export const SSHKeyType = P.magic(SSHString, 'ssh-ed25519');
export const PublicKey = P.struct({ keyType: SSHKeyType, pubKey: P.bytes(P.U32BE) });

const PrivateKey = P.padRight(
  8,
  P.struct({
    check1: P.bytes(4),
    check2: P.bytes(4),
    keyType: SSHKeyType,
    pubKey: SSHBuf,
    privKey: SSHBuf,
    comment: SSHString,
  }),
  (i: number) => i + 1
);
// https://tools.ietf.org/html/draft-miller-ssh-agent-02#section-4.5
export const AuthData = P.struct({
  nonce: SSHBuf,
  userAuthRequest: P.U8, // == 50
  user: SSHString,
  conn: SSHString,
  auth: SSHString,
  haveSig: P.U8, // == 1
  keyType: SSHKeyType,
  pubKey: P.prefix(P.U32BE, PublicKey),
});

export type AuthDataType = P.UnwrapCoder<typeof AuthData>;

export const PrivateExport = P.base64armor(
  'openssh private key',
  70,
  P.struct({
    magic: P.magicBytes('openssh-key-v1\0'),
    // Only decrypted ed25519 keys supported for now
    ciphername: P.magic(SSHString, 'none'),
    kdfname: P.magic(SSHString, 'none'),
    kdfopts: P.magic(SSHString, ''),
    keys: P.array(
      P.U32BE,
      P.struct({
        pubKey: P.prefix(P.U32BE, PublicKey),
        privKey: P.prefix(P.U32BE, PrivateKey),
      })
    ),
  })
);

export function formatPublicKey(bytes: Uint8Array, comment?: string): string {
  const blob = PublicKey.encode({ pubKey: bytes });
  return `ssh-ed25519 ${base64.encode(blob)}${comment ? ` ${comment}` : ''}`;
}

export function getFingerprint(bytes: Uint8Array): string {
  const blob = PublicKey.encode({ pubKey: bytes });
  // ssh-keygen -l -f ~/.ssh/id_ed25519
  // 256 SHA256:+WK/Sl4XJjoxDlAWYuhq4Fl2hka9j3GOUjYczQkqnCI user@comp.local (ED25519)
  return `SHA256:${base64.encode(sha256(blob)).replace(/=$/, '')}`;
}

// For determenistic generation in tests
export async function getKeys(
  privateKey: Uint8Array,
  comment?: string,
  checkBytes = randomBytes(4)
) {
  const pubKey = await ed25519.getPublicKey(privateKey);
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

// For SSH Agents
export function authSign(privateKey: Uint8Array, data: AuthDataType): Uint8Array {
  return ed25519.sign(AuthData.encode(data), privateKey);
}

export default getKeys;

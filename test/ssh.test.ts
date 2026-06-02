import { describe, should } from '@paulmillr/jsbt/test.js';
import { concatBytes } from '@noble/hashes/utils.js';
import { hex } from '@scure/base';
import { deepStrictEqual, throws } from 'node:assert';
import * as ssh from '../src/ssh.ts';

// Real key from the internet
const realKey = `-----BEGIN OPENSSH PRIVATE KEY-----

b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACC2h/5eqGvaiEUKTBE0zCp32ry2KvPvhyVXHV2PjxNlKgAAAJDhCJGi4QiR
ogAAAAtzc2gtZWQyNTUxOQAAACC2h/5eqGvaiEUKTBE0zCp32ry2KvPvhyVXHV2PjxNlKg
AAAEBuiKVsRW9rjAjpLI+tVm8DuQ8/RCxj0G1Ncsvl446uQbaH/l6oa9qIRQpMETTMKnfa
vLYq8++HJVcdXY+PE2UqAAAAB3BjQGRpc2gBAgMEBQY=
-----END OPENSSH PRIVATE KEY-----
`;
const EXPECTED = {
  publicKey:
    'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBeMouB+U+QahY9rCua02H2ZfRXMpxDFtyqW+wBm0iji user@pc',
  publicKeyBytes: hex.decode('178ca2e07e53e41a858f6b0ae6b4d87d997d15cca710c5b72a96fb0066d228e2'),
  fingerprint: 'SHA256:idyrSmuk43TgiEwEtOFsaPybfUARlaLPQUGuazLcm94',
  privateKey: `-----BEGIN OPENSSH PRIVATE KEY-----

b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAXjKLgflPkGoWPawrmtNh9mX0VzKcQxbcqlvsAZtIo4gAAAJDDRvFKw0bx
SgAAAAtzc2gtZWQyNTUxOQAAACAXjKLgflPkGoWPawrmtNh9mX0VzKcQxbcqlvsAZtIo4g
AAAEBx5yKwd8AH1K4mMoeHigv/GBbJn5PPjc3dmVvM79HXoxeMouB+U+QahY9rCua02H2Z
fRXMpxDFtyqW+wBm0ijiAAAAB3VzZXJAcGMBAgMEBQY=
-----END OPENSSH PRIVATE KEY-----
`,
};
const AUTH_NONCE = Uint8Array.from({ length: 32 }, (_, i) => i);
const authData = {
  nonce: AUTH_NONCE,
  userAuthRequest: 50,
  user: 'alice',
  conn: 'ssh-connection',
  auth: 'publickey',
  haveSig: 1,
  pubKey: { pubKey: EXPECTED.publicKeyBytes },
};
const authPayload = (overrides: Partial<typeof authData> = {}) => {
  const data = { ...authData, ...overrides };
  return concatBytes(
    ssh.SSHBuf.encode(data.nonce),
    Uint8Array.of(data.userAuthRequest),
    ssh.SSHString.encode(data.user),
    ssh.SSHString.encode(data.conn),
    ssh.SSHString.encode(data.auth),
    Uint8Array.of(data.haveSig),
    ssh.SSHKeyType.encode(undefined),
    ssh.SSHBuf.encode(ssh.PublicKey.encode(data.pubKey))
  );
};
describe('ssh', () => {
  should('pack & unpack ssh privkeys should be the same', () => {
    deepStrictEqual(realKey, ssh.PrivateExport.encode(ssh.PrivateExport.decode(realKey)));
  });
  should('PrivateExport rejects multi-key OpenSSH private input objects', () => {
    const decoded = ssh.PrivateExport.decode(realKey);
    throws(() =>
      ssh.PrivateExport.encode({ ...decoded, keys: [decoded.keys[0]!, decoded.keys[0]!] })
    );
  });
  should('PrivateKey rejects malformed OpenSSH private block values', () => {
    const mismatchedCheck = ssh.PrivateExport.decode(realKey);
    mismatchedCheck.keys[0]!.privKey.check2 = Uint8Array.from(
      mismatchedCheck.keys[0]!.privKey.check2
    );
    mismatchedCheck.keys[0]!.privKey.check2[0] ^= 1;
    throws(() => ssh.PrivateExport.encode(mismatchedCheck));

    const shortPub = ssh.PrivateExport.decode(realKey);
    shortPub.keys[0]!.privKey.pubKey = shortPub.keys[0]!.privKey.pubKey.slice(0, 31);
    throws(() => ssh.PrivateExport.encode(shortPub));

    const shortPriv = ssh.PrivateExport.decode(realKey);
    shortPriv.keys[0]!.privKey.privKey = shortPriv.keys[0]!.privKey.privKey.slice(0, 63);
    throws(() => ssh.PrivateExport.encode(shortPriv));

    const mismatchedAppendedPub = ssh.PrivateExport.decode(realKey);
    mismatchedAppendedPub.keys[0]!.privKey.privKey = Uint8Array.from(
      mismatchedAppendedPub.keys[0]!.privKey.privKey
    );
    mismatchedAppendedPub.keys[0]!.privKey.privKey[63] ^= 1;
    throws(() => ssh.PrivateExport.encode(mismatchedAppendedPub));

    const wrongSeed = ssh.PrivateExport.decode(realKey);
    wrongSeed.keys[0]!.privKey.privKey = Uint8Array.from(wrongSeed.keys[0]!.privKey.privKey);
    wrongSeed.keys[0]!.privKey.privKey[0] ^= 1;
    throws(() => ssh.PrivateExport.encode(wrongSeed));
  });
  should('PublicKey rejects non-32-byte ssh-ed25519 blobs', () => {
    const short = EXPECTED.publicKeyBytes.slice(0, 31);
    const long = concatBytes(EXPECTED.publicKeyBytes, Uint8Array.of(0));
    deepStrictEqual(
      ssh.PublicKey.encode({ pubKey: EXPECTED.publicKeyBytes }),
      concatBytes(ssh.SSHKeyType.encode(undefined), ssh.SSHBuf.encode(EXPECTED.publicKeyBytes))
    );
    throws(() => ssh.PublicKey.encode({ pubKey: short }));
    throws(() => ssh.PublicKey.encode({ pubKey: long }));
    for (const pubKey of [short, long])
      throws(() =>
        ssh.PublicKey.decode(
          concatBytes(ssh.SSHKeyType.encode(undefined), ssh.SSHBuf.encode(pubKey))
        )
      );
  });
  should('return correct key from seed', () => {
    const priv = hex.decode('71e722b077c007d4ae263287878a0bff1816c99f93cf8dcddd995bccefd1d7a3');
    const comment = 'user@pc';
    const checkBytes = hex.decode('c346f14a');
    deepStrictEqual(ssh.getKeys(priv, comment, checkBytes), EXPECTED);
  });
  should('formatPublicKey rejects comments that would split one-line OpenSSH records', () => {
    deepStrictEqual(ssh.formatPublicKey(EXPECTED.publicKeyBytes, 'user@pc'), EXPECTED.publicKey);
    throws(() => ssh.formatPublicKey(EXPECTED.publicKeyBytes, 'user\nother'));
    throws(() => ssh.formatPublicKey(EXPECTED.publicKeyBytes, 'user\rother'));
  });
  should('AuthData enforces RFC 4252 publickey auth fields', () => {
    const valid = authPayload();
    deepStrictEqual(ssh.AuthData.encode(authData), valid);
    deepStrictEqual(ssh.AuthData.decode(valid), {
      ...authData,
      keyType: undefined,
      pubKey: { keyType: undefined, pubKey: EXPECTED.publicKeyBytes },
    });
    for (const bad of [
      { userAuthRequest: 51 },
      { auth: 'password' },
      { haveSig: 0 },
      { conn: 'ssh-cönnection' },
    ]) {
      throws(() => ssh.AuthData.encode({ ...authData, ...bad }));
      throws(() => ssh.AuthData.decode(authPayload(bad)));
    }
  });
});

should.runWhen(import.meta.url);

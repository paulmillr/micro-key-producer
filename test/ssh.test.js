import { deepStrictEqual } from 'node:assert';
import { describe, should } from 'micro-should';
import * as ssh from '../esm/ssh.js';
import { hex } from '@scure/base';

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
describe('ssh', () => {
  should('pack & unpack ssh privkeys should be the same', () => {
    deepStrictEqual(realKey, ssh.PrivateExport.encode(ssh.PrivateExport.decode(realKey)));
  });
  should('return correct key from seed', () => {
    const priv = hex.decode('71e722b077c007d4ae263287878a0bff1816c99f93cf8dcddd995bccefd1d7a3');
    const comment = 'user@pc';
    const checkBytes = hex.decode('c346f14a');
    deepStrictEqual(ssh.getKeys(priv, comment, checkBytes), EXPECTED);
  });
});

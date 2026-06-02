import { describe, should } from '@paulmillr/jsbt/test.js';
import { concatBytes } from '@noble/hashes/utils.js';
import { base64, hex } from '@scure/base';
import { execFileSync, spawnSync } from 'node:child_process';
import { deepStrictEqual, throws } from 'node:assert';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as ssh from '../src/ssh.ts';

// Run directly; this is intentionally not imported by test/index.ts because it needs local OpenSSH ssh-keygen.
const seed = hex.decode('71e722b077c007d4ae263287878a0bff1816c99f93cf8dcddd995bccefd1d7a3');
const check = hex.decode('c346f14a');
const tmp = <T>(fn: (dir: string) => T): T => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mkp-ssh-'));
  fs.chmodSync(dir, 0o700);
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
};
const sshEnv = (home: string) => {
  const { SSH_AUTH_SOCK, SSH_AGENT_PID, ...env } = process.env;
  return { ...env, HOME: home };
};
const sshKeygen = (home: string, args: string[]): string =>
  execFileSync('ssh-keygen', args, {
    encoding: 'utf8',
    env: sshEnv(home),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
const U32BE = (n: number) => Uint8Array.of(n >>> 24, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
const readU32BE = (bytes: Uint8Array, pos: number) =>
  bytes[pos]! * 2 ** 24 + bytes[pos + 1]! * 2 ** 16 + bytes[pos + 2]! * 2 ** 8 + bytes[pos + 3]!;
const readSSHField = (bytes: Uint8Array, pos: number): [Uint8Array, number] => {
  const len = readU32BE(bytes, pos);
  const end = pos + 4 + len;
  return [bytes.subarray(pos, end), end];
};
const replaceSSHField = (bytes: Uint8Array, pos: number, value: Uint8Array): Uint8Array => {
  const [, end] = readSSHField(bytes, pos);
  return concatBytes(bytes.subarray(0, pos), U32BE(value.length), value, bytes.subarray(end));
};
const rawArmor = (armor: string): Uint8Array =>
  base64.decode(
    armor
      .trim()
      .split('\n')
      .filter((line) => line && !line.startsWith('-----'))
      .join('')
  );
const wrapArmor = (raw: Uint8Array): string => {
  const body = base64.encode(raw);
  const lines = [];
  for (let i = 0; i < body.length; i += 70) lines.push(body.slice(i, i + 70));
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n\n${lines.join('\n')}\n-----END OPENSSH PRIVATE KEY-----\n`;
};
const envelopeParts = (armor: string) => {
  const raw = rawArmor(armor);
  let pos = 'openssh-key-v1\0'.length;
  const [, afterCipher] = readSSHField(raw, pos);
  const [, afterKdf] = readSSHField(raw, afterCipher);
  const [, afterKdfopts] = readSSHField(raw, afterKdf);
  pos = afterKdfopts + 4;
  const [pub, afterPub] = readSSHField(raw, pos);
  const [priv, end] = readSSHField(raw, afterPub);
  if (end !== raw.length)
    throw new Error('OpenSSH test fixture expected one public key and one private block');
  return { raw, afterKdfopts, pub, priv, afterPub, end };
};
const duplicatePrivateEnvelope = (armor: string): string => {
  const { raw, afterKdfopts, pub, priv } = envelopeParts(armor);
  return wrapArmor(concatBytes(raw.subarray(0, afterKdfopts), U32BE(2), pub, priv, pub, priv));
};
type PrivateBlock = {
  check1: Uint8Array;
  check2: Uint8Array;
  pubKey: Uint8Array;
  privKey: Uint8Array;
  comment: string;
};
const padding = (len: number): Uint8Array => {
  const padLen = (8 - (len % 8)) % 8;
  return Uint8Array.from({ length: padLen }, (_, i) => i + 1);
};
const privateBlock = (armor: string, mutate: (block: PrivateBlock) => void): Uint8Array => {
  const data = ssh.PrivateExport.decode(armor);
  const key = data.keys[0]!;
  const block: PrivateBlock = {
    check1: Uint8Array.from(key.privKey.check1),
    check2: Uint8Array.from(key.privKey.check2),
    pubKey: Uint8Array.from(key.privKey.pubKey),
    privKey: Uint8Array.from(key.privKey.privKey),
    comment: key.privKey.comment,
  };
  mutate(block);
  const body = concatBytes(
    block.check1,
    block.check2,
    ssh.SSHKeyType.encode(undefined),
    ssh.SSHBuf.encode(block.pubKey),
    ssh.SSHBuf.encode(block.privKey),
    ssh.SSHString.encode(block.comment)
  );
  return concatBytes(body, padding(body.length));
};
const mutatePrivateBlock = (armor: string, mutate: (block: PrivateBlock) => void): string => {
  const { raw, afterPub } = envelopeParts(armor);
  const block = privateBlock(armor, mutate);
  return wrapArmor(replaceSSHField(raw, afterPub, block));
};
const mutatePrivateBlockRaw = (armor: string, mutate: (block: Uint8Array) => void): string => {
  const { raw, afterPub } = envelopeParts(armor);
  const [field] = readSSHField(raw, afterPub);
  const block = Uint8Array.from(field.subarray(4));
  mutate(block);
  return wrapArmor(replaceSSHField(raw, afterPub, block));
};
const mutateOuterPublicKey = (armor: string, mutate: (pubKey: Uint8Array) => void): string => {
  const { raw, afterKdfopts } = envelopeParts(armor);
  const pos = afterKdfopts + 4;
  const [field] = readSSHField(raw, pos);
  const pubKey = Uint8Array.from(ssh.PublicKey.decode(field.subarray(4)).pubKey);
  mutate(pubKey);
  return wrapArmor(replaceSSHField(raw, pos, ssh.PublicKey.encode({ pubKey })));
};
const sshKeygenPrivate = (armor: string) =>
  tmp((dir) => {
    const file = path.join(dir, 'key');
    fs.writeFileSync(file, armor, { mode: 0o600 });
    // -P keeps malformed-key checks non-interactive even when OpenSSH guesses encryption.
    const res = spawnSync('ssh-keygen', ['-y', '-P', '', '-f', file], {
      encoding: 'utf8',
      env: sshEnv(dir),
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return {
      status: res.status,
      stdout: res.stdout,
      stderr: res.stderr.replaceAll(file, '<key>'),
    };
  });
const publicBlob = (pubKey: Uint8Array): Uint8Array =>
  concatBytes(ssh.SSHKeyType.encode(undefined), ssh.SSHBuf.encode(pubKey));
const sshKeygenPublic = (pubKey: Uint8Array) =>
  tmp((dir) => {
    const file = path.join(dir, 'key.pub');
    fs.writeFileSync(file, `ssh-ed25519 ${base64.encode(publicBlob(pubKey))} user@pc\n`);
    const res = spawnSync('ssh-keygen', ['-l', '-E', 'sha256', '-f', file], {
      encoding: 'utf8',
      env: sshEnv(dir),
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return {
      status: res.status,
      stdout: res.stdout,
      stderr: res.stderr.replaceAll(file, '<pub>'),
    };
  });

describe('ssh openssh', () => {
  should('OpenSSH accepts locally generated private and public keys', () => {
    const keys = ssh.getKeys(seed, 'user@pc', check);
    tmp((dir) => {
      const key = path.join(dir, 'id_ed25519');
      const pub = `${key}.pub`;
      fs.writeFileSync(key, keys.privateKey);
      fs.chmodSync(key, 0o600);
      fs.writeFileSync(pub, `${keys.publicKey}\n`);
      const fingerprint = `256 ${keys.fingerprint} user@pc (ED25519)\n`;
      deepStrictEqual(
        {
          publicFromPrivate: sshKeygen(dir, ['-y', '-P', '', '-f', key]),
          privateFingerprint: sshKeygen(dir, ['-l', '-E', 'sha256', '-f', key]),
          publicFingerprint: sshKeygen(dir, ['-l', '-E', 'sha256', '-f', pub]),
        },
        {
          publicFromPrivate: `${keys.publicKey}\n`,
          privateFingerprint: fingerprint,
          publicFingerprint: fingerprint,
        }
      );
    });
  });
  should('decodes OpenSSH-generated ed25519 private keys', () => {
    tmp((dir) => {
      const key = path.join(dir, 'id_ed25519');
      sshKeygen(dir, ['-q', '-t', 'ed25519', '-N', '', '-C', 'openssh@example.com', '-f', key]);
      const decoded = ssh.PrivateExport.decode(fs.readFileSync(key, 'utf8'));
      const publicKey = fs.readFileSync(`${key}.pub`, 'utf8');
      const first = decoded.keys[0]!;
      const fingerprint = sshKeygen(dir, ['-l', '-E', 'sha256', '-f', key]).split(' ')[1]!;
      deepStrictEqual(
        {
          keyCount: decoded.keys.length,
          privateBlobLength: first.privKey.privKey.length,
          comment: first.privKey.comment,
          publicKey: `${ssh.formatPublicKey(first.pubKey.pubKey, first.privKey.comment)}\n`,
          fingerprint: ssh.getFingerprint(first.pubKey.pubKey),
        },
        {
          keyCount: 1,
          privateBlobLength: 64,
          comment: 'openssh@example.com',
          publicKey,
          fingerprint,
        }
      );
    });
  });
  should('decodes OpenSSH-generated UTF-8 private-key comments', () => {
    tmp((dir) => {
      const key = path.join(dir, 'id_ed25519');
      const comment = 'openssh-\u00e9@example.com';
      sshKeygen(dir, ['-q', '-t', 'ed25519', '-N', '', '-C', comment, '-f', key]);
      const decoded = ssh.PrivateExport.decode(fs.readFileSync(key, 'utf8'));
      const first = decoded.keys[0]!;
      deepStrictEqual(
        {
          comment: first.privKey.comment,
          publicKey: `${ssh.formatPublicKey(first.pubKey.pubKey, first.privKey.comment)}\n`,
        },
        {
          comment,
          publicKey: fs.readFileSync(`${key}.pub`, 'utf8'),
        }
      );
    });
  });
  should('OpenSSH encrypted private keys stay explicitly unsupported locally', () => {
    tmp((dir) => {
      const key = path.join(dir, 'id_ed25519');
      sshKeygen(dir, ['-q', '-t', 'ed25519', '-N', 'passphrase', '-C', 'encrypted', '-f', key]);
      const pub = fs.readFileSync(`${key}.pub`, 'utf8');
      deepStrictEqual(sshKeygen(dir, ['-y', '-P', 'passphrase', '-f', key]), pub);
      // OpenSSH's private-key envelope encryption format is outside this
      // package's current no-decrypt Ed25519 profile; keep this as an explicit
      // compatibility boundary for generated encrypted keys.
      throws(() => ssh.PrivateExport.decode(fs.readFileSync(key, 'utf8')));
    });
  });
  should('OpenSSH and local decoder reject multi-key private envelopes', () => {
    const keys = ssh.getKeys(seed, 'user@pc', check);
    const multi = duplicatePrivateEnvelope(keys.privateKey);
    throws(() => ssh.PrivateExport.decode(multi));
    deepStrictEqual(sshKeygenPrivate(multi), {
      status: 255,
      stdout: '',
      stderr: 'Load key "<key>": error in libcrypto\r\n',
    });
  });
  should('OpenSSH and local decoder reject mismatched outer private-envelope public key', () => {
    const keys = ssh.getKeys(seed, 'user@pc', check);
    const mismatch = mutateOuterPublicKey(keys.privateKey, (pubKey) => {
      pubKey[0] ^= 1;
    });
    throws(() => ssh.PrivateExport.decode(mismatch));
    deepStrictEqual(sshKeygenPrivate(mismatch), {
      status: 255,
      stdout: '',
      stderr: 'Load key "<key>": error in libcrypto\r\n',
    });
  });
  should('compares malformed private block handling with OpenSSH', () => {
    const keys = ssh.getKeys(seed, 'user@pc', check);
    const cases = {
      mismatchedCheck: mutatePrivateBlock(keys.privateKey, (block) => {
        block.check2[0] ^= 1;
      }),
      shortPub: mutatePrivateBlock(keys.privateKey, (block) => {
        block.pubKey = block.pubKey.slice(0, 31);
      }),
      shortPriv: mutatePrivateBlock(keys.privateKey, (block) => {
        block.privKey = block.privKey.slice(0, 63);
      }),
      mismatchedAppendedPub: mutatePrivateBlock(keys.privateKey, (block) => {
        block.privKey[63] ^= 1;
      }),
      wrongSeed: mutatePrivateBlock(keys.privateKey, (block) => {
        block.privKey[0] ^= 1;
      }),
      badPadding: mutatePrivateBlockRaw(keys.privateKey, (block) => {
        block[block.length - 1] ^= 0xff;
      }),
    };
    const res: Record<string, { decThrows: boolean; ssh: ReturnType<typeof sshKeygenPrivate> }> =
      {};
    for (const name in cases) {
      try {
        ssh.PrivateExport.decode(cases[name as keyof typeof cases]);
        res[name] = { decThrows: false, ssh: sshKeygenPrivate(cases[name as keyof typeof cases]) };
      } catch {
        res[name] = { decThrows: true, ssh: sshKeygenPrivate(cases[name as keyof typeof cases]) };
      }
    }
    deepStrictEqual(res, {
      mismatchedCheck: {
        decThrows: true,
        ssh: {
          status: 255,
          stdout: '',
          stderr: 'Load key "<key>": incorrect passphrase supplied to decrypt private key\r\n',
        },
      },
      shortPub: {
        decThrows: true,
        ssh: { status: 255, stdout: '', stderr: 'Load key "<key>": error in libcrypto\r\n' },
      },
      shortPriv: {
        decThrows: true,
        ssh: { status: 255, stdout: '', stderr: 'Load key "<key>": error in libcrypto\r\n' },
      },
      mismatchedAppendedPub: {
        decThrows: true,
        ssh: { status: 0, stdout: `${keys.publicKey}\n`, stderr: '' },
      },
      wrongSeed: {
        decThrows: true,
        ssh: { status: 0, stdout: `${keys.publicKey}\n`, stderr: '' },
      },
      badPadding: {
        decThrows: true,
        ssh: { status: 255, stdout: '', stderr: 'Load key "<key>": error in libcrypto\r\n' },
      },
    });
  });
  should('OpenSSH and local decoder reject non-32-byte public-key blobs', () => {
    const cases = {
      short: seed.slice(0, 31),
      long: concatBytes(seed, Uint8Array.of(0)),
    };
    const res: Record<string, { decThrows: boolean; ssh: ReturnType<typeof sshKeygenPublic> }> = {};
    for (const name in cases) {
      const pubKey = cases[name as keyof typeof cases];
      try {
        ssh.PublicKey.decode(publicBlob(pubKey));
        res[name] = { decThrows: false, ssh: sshKeygenPublic(pubKey) };
      } catch {
        res[name] = { decThrows: true, ssh: sshKeygenPublic(pubKey) };
      }
    }
    deepStrictEqual(res, {
      short: {
        decThrows: true,
        ssh: { status: 255, stdout: '', stderr: '<pub> is not a public key file.\r\n' },
      },
      long: {
        decThrows: true,
        ssh: { status: 255, stdout: '', stderr: '<pub> is not a public key file.\r\n' },
      },
    });
  });
  should('OpenSSH truncates one-line public-key comments at CR and LF', () => {
    const keys = ssh.getKeys(seed, 'user@pc', check);
    const [type, blob] = keys.publicKey.split(' ');
    tmp((dir) => {
      const lf = path.join(dir, 'lf.pub');
      const cr = path.join(dir, 'cr.pub');
      fs.writeFileSync(lf, `${type} ${blob} user\nother\n`);
      fs.writeFileSync(cr, `${type} ${blob} user\rother\n`);
      const truncated = `256 ${keys.fingerprint} user (ED25519)\n`;
      deepStrictEqual(
        {
          lf: sshKeygen(dir, ['-l', '-E', 'sha256', '-f', lf]),
          cr: sshKeygen(dir, ['-l', '-E', 'sha256', '-f', cr]),
        },
        {
          lf: truncated,
          cr: truncated,
        }
      );
    });
  });
});

should.runWhen(import.meta.url);

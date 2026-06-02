import { randomBytes } from '@noble/hashes/utils.js';
import { should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { getKeys } from '../src/pgp.ts';

// Warning: this test will execute system command `gpg` inside an isolated temporary GNUPGHOME.

const ROOT = mkdtempSync(join(tmpdir(), 'mkp-gpgkp2-'));
const GNUPGHOME = join(ROOT, 'gnupg');
const PUB_PATH = join(ROOT, 'key.pub');
const PRIV_PATH = join(ROOT, 'key.priv');
mkdirSync(GNUPGHOME, { mode: 0o700 });
const gpgEnv = () => ({ ...process.env, GNUPGHOME, HOME: ROOT });
const launchAgent = () => {
  const { status, stderr } = spawnSync(
    'gpgconf',
    ['--homedir', GNUPGHOME, '--launch', 'gpg-agent'],
    {
      env: gpgEnv(),
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    }
  );
  if (status) throw new Error(stderr);
};
const cleanup = () => {
  spawnSync('gpgconf', ['--homedir', GNUPGHOME, '--kill', 'gpg-agent'], { stdio: 'ignore' });
  rmSync(ROOT, { recursive: true, force: true });
};
process.once('exit', cleanup);
const RUN_AGENT = process.argv.includes('--agent');

function cmdArgs(command) {
  const [cmd, ...args] = command.split(' ');
  return { cmd, args };
}

function exec(command, opt = {}) {
  const { cmd, args } = cmdArgs(command);
  const { status, stdout, stderr } = spawnSync(cmd, args, {
    env: gpgEnv(),
    stdio: ['pipe', 'pipe', 'pipe'],
    input: opt && opt.input,
    encoding: 'utf8',
  });
  if (!(opt && opt.ignoreStatus) && status)
    throw new Error(`Wrong status code for ${command}: ${status}\n${stderr}`);
  return { status, stdout, stderr };
}

if (!RUN_AGENT)
  should.skip('basic requires gpg-agent: pass --agent to run this integration test', () => {});
else
  should('basic', () => {
    // Deterministic via scrypt
    const seed = randomBytes();
    let { publicKey, privateKey, keyId } = getKeys(seed, 'user', 'password');
    const SECRET_KEY_OPT = `--no-options --no-autostart --no-tty --batch --yes --pinentry-mode loopback --trust-model always --passphrase password`;
    launchAgent();

    const cleanKeys = () => {
      exec(`gpg --no-options --delete-secret-and-public-key ${keyId}`, { ignoreStatus: true });
      rmSync(PUB_PATH, { force: true });
      rmSync(PRIV_PATH, { force: true });
    };
    writeFileSync(PUB_PATH, publicKey);
    writeFileSync(PRIV_PATH, privateKey);
    try {
      exec(`gpg ${SECRET_KEY_OPT} --import ${PRIV_PATH}`, { status: true });
      exec(`gpg ${SECRET_KEY_OPT} --import ${PUB_PATH}`, { status: true });
      const signed = exec(
        `gpg ${SECRET_KEY_OPT} --default-key ${keyId.toUpperCase()} --recipient ${keyId.toUpperCase()} --encrypt --sign --armor`,
        {
          input: 'test message',
        }
      ).stdout;
      const { stdout: decrypted, stderr: decryptedInfo } = exec(
        `gpg ${SECRET_KEY_OPT} --default-key ${keyId} --decrypt`,
        {
          input: signed,
        }
      );
      deepStrictEqual(decrypted, 'test message');
      console.log('T', decryptedInfo);
      deepStrictEqual(decryptedInfo.includes('Good signature from "user"'), true);
    } finally {
      cleanKeys();
    }
  });

should.runWhen(import.meta.url);

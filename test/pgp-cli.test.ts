/*
!!! DANGER !!!
!!! THIS WILL ASK LOTS OF QUESTIONS IN INTERACTIVE MODE, DON'T INCLUDE IN './index.js' !!!

- The 'gpgkp bin' tests run headless (no git/gnupg/TTY) but need `npm run build` first,
  since the bin imports the compiled ../pgp.js. The gpg-agent tests require git and gnupg.
- Tests use an isolated temporary GNUPGHOME/HOME and remove it on process exit.
- Run using password `123456789`: `node test/pgp-cli.test.ts --agent`
*/

import { describe, it } from '@paulmillr/jsbt/test.js';
import { hex } from '@scure/base';
import { deepStrictEqual } from 'node:assert';
import { execSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import { tmpdir } from 'node:os';
import path, { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as pgp from '../src/pgp.ts';
import { RUN_AGENT, killGpgAgent, launchGpgAgent, tmpDir } from './integration-utils.ts';

const BIN = 'gpgkp.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SIGNER = resolve(join(__dirname, '..', 'bin', BIN));
// Created lazily in setup() so importing this file (e.g. from test/integration.ts
// without --agent) has no side effects.
let ROOT = '';
let PATH = '';
let GNUPGHOME = '';
const setup = () => {
  ROOT = fs.mkdtempSync(join(tmpdir(), 'mkp-gpgkp-'));
  PATH = join(ROOT, 'work');
  GNUPGHOME = join(ROOT, 'gnupg');
  fs.mkdirSync(GNUPGHOME, { mode: 0o700 });
  fs.mkdirSync(PATH);
  process.once('exit', cleanup);
};
const testEnv = () => ({ ...process.env, GNUPGHOME, HOME: ROOT });
const run = (cmd: string, opts: Parameters<typeof execSync>[1] = {}) =>
  execSync(cmd, { ...opts, env: { ...testEnv(), ...opts.env } });
const cleanup = () => {
  killGpgAgent(GNUPGHOME);
  fs.rmSync(ROOT, { recursive: true, force: true });
};

const PGP_PASSWORD = '123456789';
const CREATED_AT = 1637429480;
const NAME1 = 'John Doe';
const NAME2 = 'Bob Doe';
const EMAIL1 = 'example@example.com';
const EMAIL2 = 'test@test.com';

const FULL_NAME1 = `${NAME1} <${EMAIL1}>`;
const FULL_NAME2 = `${NAME2} <${EMAIL2}>`;

function execIgnore(cmd, opts) {
  try {
    return run(cmd, opts);
  } catch (e) {
    console.log(`[ERR] ${cmd}: ${e}`);
  }
}

function gpgDeleteKey(keyId) {
  // ignore in case key not exists yet
  execIgnore(`gpg --no-options --no-autostart --delete-secret-key ${keyId}`, {
    stdio: 'inherit',
  });
  execIgnore(`gpg --no-options --no-autostart --delete-key ${keyId}`, { stdio: 'inherit' });
}

function gitRepo(repo) {
  fs.mkdirSync(repo);
  run('git init', { cwd: repo, stdio: 'inherit' });
  fs.writeFileSync(join(repo, 'file.txt'), 'hello\n');
}

function gitSign(repo, keyId, name, email) {
  run(`git config user.signingkey ${keyId}`, { cwd: repo });
  run('git config commit.gpgsign true', { cwd: repo });
  run(`git config user.name "${name}"`, { cwd: repo });
  run(`git config user.email "${email}"`, { cwd: repo });
  run(`git config gpg.program "${SIGNER}"`, { cwd: repo });
}

function gitCommit(repo, env) {
  run('git add file.txt', { cwd: repo, stdio: 'inherit' });
  run('git commit -s -m "Initial commit"', {
    cwd: repo,
    stdio: 'inherit',
    env,
  });
  // First verify with signer
  run('git verify-commit HEAD --raw', {
    cwd: repo,
    stdio: 'inherit',
    env,
  });
  // Then real gpg
  run(`git config --unset gpg.program`, { cwd: repo, stdio: 'inherit' });
  run('git verify-commit HEAD --raw', { cwd: repo, stdio: 'inherit' });
}

function pgpInt() {
  describe('PGP Integrations', () => {
    const KEYS_TO_DELETE: string[] = [];
    it.serial('Import (password)', () => {
      const seed = hex.decode('29f47c314ee8b1c77a0b7e4c0043a04a20af46f10132855b79f9ff6c4f8a8ed9');
      // `protection: 'legacy'`: GnuPG <= 2.4 cannot import our default Argon2+AEAD keys.
      const keys = pgp.getKeys(seed, FULL_NAME1, PGP_PASSWORD, CREATED_AT, {
        protection: 'legacy',
      });
      const privateFile = join(PATH, 'privatePass.key');
      console.log('ADD', keys.keyId);
      fs.writeFileSync(privateFile, keys.privateKey);
      gpgDeleteKey(keys.keyId);
      KEYS_TO_DELETE.push(keys.keyId);
      run(
        `gpg --no-options --no-autostart --batch --pinentry-mode loopback --passphrase ${PGP_PASSWORD} --import ${privateFile}`,
        { stdio: 'inherit' }
      );
    });
    it.serial('Import (no password)', () => {
      const seed = hex.decode('39f47c314ee8b1c77a0b7e4c0043a04a20af46f10132855b79f9ff6c4f8a8ed9');
      const keys = pgp.getKeys(seed, FULL_NAME2, undefined, CREATED_AT);
      console.log('ADD', keys.keyId);
      const privateFile = join(PATH, 'privateNopass.key');
      fs.writeFileSync(privateFile, keys.privateKey);
      gpgDeleteKey(keys.keyId);
      KEYS_TO_DELETE.push(keys.keyId);
      run(`gpg --no-options --no-autostart --import ${privateFile}`, { stdio: 'inherit' });
    });
    describe('micro-gpg-signer', () => {
      it.serial('password', () => {
        const repo = join(PATH, 'test-password');
        gitRepo(repo);
        gitSign(repo, '21B287CDD55ACB9F', NAME1, EMAIL1);
        gitCommit(repo, { GPGKP_KEY: join(PATH, 'privatePass.key') });
      });
      it.serial('no password', () => {
        const repo = join(PATH, 'test-no-password');
        gitRepo(repo);
        gitSign(repo, '8061EFFF72C8FD15', NAME2, EMAIL2);
        gitCommit(repo, { GPGKP_KEY: join(PATH, 'privateNopass.key') });
      });
    });
    it.serial('Delete keys', () => {
      for (const k of KEYS_TO_DELETE) {
        gpgDeleteKey(k);
      }
    });
  });
}

// Headless checks for the gpgkp bin itself: passwordless key, no gpg, no TTY.
// Piped stdio is deliberate; it covers the `--status-fd` non-TTY regression.
describe('gpgkp bin', () => {
  const USER = 'Alice Wonder <alice@example.org>';
  const COMMIT = 'tree abc\nauthor A <a@b> 1637429480 +0000\n\ntest commit\n';
  const gpgkp = (key: string, args: string[], input: string) =>
    spawnSync('node', [SIGNER, ...args], {
      input,
      encoding: 'utf8',
      env: { ...process.env, GPGKP_KEY: key },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  const binSeed = hex.decode('39f47c314ee8b1c77a0b7e4c0043a04a20af46f10132855b79f9ff6c4f8a8ed9');
  const withKey = <T>(fn: (keyFile: string, keyId: string, dir: string) => T): T =>
    tmpDir('mkp-gpgkp-bin-', (dir) => {
      const keys = pgp.getKeys(binSeed, USER, undefined, 0);
      const keyFile = join(dir, 'key.asc');
      fs.writeFileSync(keyFile, keys.privateKey);
      return fn(keyFile, keys.keyId.toUpperCase(), dir);
    });
  it('signs and verifies with piped status-fd', () => {
    withKey((keyFile, keyId, dir) => {
      const signed = gpgkp(keyFile, ['--status-fd=2', '-bsau', keyId], COMMIT);
      deepStrictEqual(signed.status, 0, signed.stderr);
      deepStrictEqual(signed.stderr.includes('[GNUPG:] SIG_CREATED D 22 10 00 '), true);
      deepStrictEqual(signed.stdout.startsWith('-----BEGIN PGP SIGNATURE-----'), true);
      const sigFile = join(dir, 'sig.asc');
      fs.writeFileSync(sigFile, signed.stdout);
      const verified = gpgkp(
        keyFile,
        ['--keyid-format=long', '--status-fd=1', '--verify', sigFile, '-'],
        COMMIT
      );
      deepStrictEqual(verified.status, 0, verified.stdout);
      deepStrictEqual(verified.stdout.includes(`[GNUPG:] GOODSIG ${keyId} ${USER}`), true);
      deepStrictEqual(verified.stdout.includes('[GNUPG:] VALIDSIG '), true);
      const corrupted = gpgkp(keyFile, ['--status-fd=1', '--verify', sigFile, '-'], `${COMMIT}x`);
      deepStrictEqual(corrupted.status, 1);
    });
  });
  it('refuses to sign with a mismatched key id', () => {
    withKey((keyFile) => {
      const signed = gpgkp(keyFile, ['--status-fd=2', '-bsau', 'DEADBEEFDEADBEEF'], COMMIT);
      deepStrictEqual(signed.status, 1);
      deepStrictEqual(signed.stderr.includes('does not match GPGKP_KEY'), true);
    });
  });
  it('resolves relative GPGKP_KEY against cwd', () => {
    withKey((keyFile, keyId, dir) => {
      const res = spawnSync('node', [SIGNER, '--status-fd=2', '-bsau', keyId], {
        input: COMMIT,
        encoding: 'utf8',
        cwd: dir,
        env: { ...process.env, GPGKP_KEY: 'key.asc' },
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      deepStrictEqual(res.status, 0, res.stderr);
    });
  });
});

if (!RUN_AGENT)
  it.skip('PGP integrations require gpg-agent: pass --agent to run this integration test', () => {});
else {
  setup();
  launchGpgAgent(GNUPGHOME, { env: testEnv() });
  pgpInt();
}

it.runWhen(import.meta.url);

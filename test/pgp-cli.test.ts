/*
!!! DANGER !!!
!!! THIS WILL ASK LOTS OF QUESTIONS IN INTERACTIVE MODE, DON'T INCLUDE IN './index.js' !!!

- The tests require git, gnupg installed.
- Tests use an isolated temporary GNUPGHOME/HOME and remove it on process exit.
- Run using password `123456789`: `npm run test:gpgkp -- --agent`
*/

import { describe, should } from '@paulmillr/jsbt/test.js';
import { hex } from '@scure/base';
import { execSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import { tmpdir } from 'node:os';
import path, { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as pgp from '../src/pgp.ts';

const BIN = 'gpgkp.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = fs.mkdtempSync(join(tmpdir(), 'mkp-gpgkp-'));
const PATH = join(ROOT, 'work');
const GNUPGHOME = join(ROOT, 'gnupg');
const SIGNER = resolve(join(__dirname, '..', 'bin', BIN));
fs.mkdirSync(GNUPGHOME, { mode: 0o700 });
const testEnv = () => ({ ...process.env, GNUPGHOME, HOME: ROOT });
const run = (cmd: string, opts: Parameters<typeof execSync>[1] = {}) =>
  execSync(cmd, { ...opts, env: { ...testEnv(), ...opts.env } });
const launchAgent = () => {
  const { status, stderr } = spawnSync(
    'gpgconf',
    ['--homedir', GNUPGHOME, '--launch', 'gpg-agent'],
    {
      env: testEnv(),
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    }
  );
  if (status) throw new Error(stderr);
};
const cleanup = () => {
  spawnSync('gpgconf', ['--homedir', GNUPGHOME, '--kill', 'gpg-agent'], { stdio: 'ignore' });
  fs.rmSync(ROOT, { recursive: true, force: true });
};
process.once('exit', cleanup);
const RUN_AGENT = process.argv.includes('--agent');

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
    console.log(`[ERR] ${cmd}: e`);
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

async function pgpInt() {
  fs.mkdirSync(PATH);
  describe('PGP Integrations', () => {
    const KEYS_TO_DELETE: string[] = [];
    should('Import (password)', () => {
      const seed = hex.decode('29f47c314ee8b1c77a0b7e4c0043a04a20af46f10132855b79f9ff6c4f8a8ed9');
      const keys = pgp.getKeys(seed, FULL_NAME1, PGP_PASSWORD, CREATED_AT);
      const privateFile = join(PATH, 'privatePass.key');
      console.log('ADD', keys.keyId);
      fs.writeFileSync(privateFile, keys.privateKey);
      gpgDeleteKey(keys.keyId);
      KEYS_TO_DELETE.push(keys.keyId);
      run(`gpg --no-options --no-autostart --import ${privateFile}`, { stdio: 'inherit' });
    });
    should('Import (no password)', () => {
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
      should('password', () => {
        const repo = join(PATH, 'test-password');
        gitRepo(repo);
        gitSign(repo, '21B287CDD55ACB9F', NAME1, EMAIL1);
        gitCommit(repo, { GPGKP_KEY: join(PATH, 'privatePass.key') });
      });
      should('no password', () => {
        const repo = join(PATH, 'test-no-password');
        gitRepo(repo);
        gitSign(repo, '8061EFFF72C8FD15', NAME2, EMAIL2);
        gitCommit(repo, { GPGKP_KEY: join(PATH, 'privateNopass.key') });
      });
    });
    should('Delete keys', () => {
      for (const k of KEYS_TO_DELETE) {
        gpgDeleteKey(k);
      }
    });
  });
}

if (!RUN_AGENT)
  should.skip(
    'PGP integrations require gpg-agent: pass --agent to run this integration test',
    () => {}
  );
else {
  launchAgent();
  pgpInt();
}

should.run(true); // no parallel tests here

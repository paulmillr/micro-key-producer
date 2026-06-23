import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual, strictEqual } from 'node:assert';
import { spawnSync } from 'node:child_process';
import {
  copyFileSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  truncateSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const BIN = resolve(join(__dirname, '..', 'bin', 'aesscr.js'));
const ROOT = mkdtempSync(join(tmpdir(), 'mkp-aesscr-'));
const PASSWORD = 'abcdefabcdef12';
const AES_GCM_MAX_BYTES = 2 ** 36 - 32;
const AES_GCM_OVERHEAD = 28;

process.once('exit', () => rmSync(ROOT, { recursive: true, force: true }));

function cleanEnv(extra = {}) {
  const env = { ...process.env };
  delete env.AES_PASSWORD;
  return { ...env, ...extra };
}

function runAesscr(args, opts = {}) {
  const res = spawnSync(process.execPath, [BIN, ...args], {
    cwd: ROOT,
    env: cleanEnv(opts.env),
    input: opts.input,
    encoding: 'utf8',
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  if (res.error) throw res.error;
  return res;
}

function shellQuote(value) {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function hasUtilLinuxScript() {
  const res = spawnSync('script', ['--version'], { encoding: 'utf8' });
  return res.status === 0 && `${res.stdout}${res.stderr}`.includes('util-linux');
}

function runAesscrInPty(args, input) {
  const command = [process.execPath, BIN, ...args].map(shellQuote).join(' ');
  const res = spawnSync('script', ['-q', '-e', '-c', command, '/dev/null'], {
    cwd: ROOT,
    env: cleanEnv(),
    input,
    encoding: 'utf8',
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  if (res.error) throw res.error;
  return res;
}

function assertOk(res) {
  strictEqual(res.status, 0, `${res.stderr}${res.stdout}`);
}

describe('aesscr CLI', () => {
  should('encrypts and decrypts using AES_PASSWORD', () => {
    const plain = join(ROOT, 'env.txt');
    const ref = join(ROOT, 'env.ref');
    const encrypted = `${plain}.aesscr`;
    writeFileSync(plain, 'env password round trip\n'.repeat(1000));
    copyFileSync(plain, ref);

    assertOk(runAesscr(['encrypt', plain], { env: { AES_PASSWORD: PASSWORD } }));
    strictEqual(existsSync(encrypted), true);
    strictEqual(readFileSync(encrypted).length, readFileSync(ref).length + 28);

    rmSync(plain);
    assertOk(runAesscr(['decrypt', encrypted], { env: { AES_PASSWORD: PASSWORD } }));
    deepStrictEqual(readFileSync(plain), readFileSync(ref));
  });

  should('rejects positional passwords', () => {
    const plain = join(ROOT, 'positional.txt');
    writeFileSync(plain, 'positional password must not be accepted\n');
    const res = runAesscr(['encrypt', plain, PASSWORD]);
    strictEqual(res.status, 1);
    strictEqual(res.stdout.includes('aesscr encrypt file.zip'), true);
    strictEqual(existsSync(`${plain}.aesscr`), false);
  });

  should('requires AES_PASSWORD or TTY in non-interactive mode', () => {
    const plain = join(ROOT, 'no-password.txt');
    writeFileSync(plain, 'no password\n');
    const res = runAesscr(['encrypt', plain]);
    strictEqual(res.status, 1);
    strictEqual(res.stderr.includes('Provide AES_PASSWORD env variable or run from a TTY'), true);
    strictEqual(existsSync(`${plain}.aesscr`), false);
  });

  should('rejects plaintext files too large for AES-GCM', () => {
    const plain = join(ROOT, 'too-large-plain.bin');
    writeFileSync(plain, '');
    truncateSync(plain, AES_GCM_MAX_BYTES + 1);

    const res = runAesscr(['encrypt', plain], { env: { AES_PASSWORD: PASSWORD } });
    strictEqual(res.status, 1);
    strictEqual(res.stderr.includes('plaintext is too large for aes-256-gcm'), true);
    strictEqual(existsSync(`${plain}.aesscr`), false);
  });

  should('rejects ciphertext files too large for AES-GCM', () => {
    const encrypted = join(ROOT, 'too-large-cipher.bin.aesscr');
    writeFileSync(encrypted, '');
    truncateSync(encrypted, AES_GCM_MAX_BYTES + AES_GCM_OVERHEAD + 1);

    const res = runAesscr(['decrypt', encrypted], { env: { AES_PASSWORD: PASSWORD } });
    strictEqual(res.status, 1);
    strictEqual(res.stderr.includes('ciphertext is too large for aes-256-gcm'), true);
    strictEqual(existsSync(encrypted.replace(/\.aesscr$/, '')), false);
  });

  const shouldPrompt = hasUtilLinuxScript() ? should : should.skip;
  shouldPrompt('uses a hidden TTY prompt when AES_PASSWORD is absent', () => {
    const plain = join(ROOT, 'prompt.txt');
    const ref = join(ROOT, 'prompt.ref');
    const encrypted = `${plain}.aesscr`;
    writeFileSync(plain, 'hidden prompt round trip\n'.repeat(1000));
    copyFileSync(plain, ref);

    const enc = runAesscrInPty(['encrypt', plain], `${PASSWORD}\n`);
    assertOk(enc);

    rmSync(plain);
    const dec = runAesscrInPty(['decrypt', encrypted], `${PASSWORD}\n`);
    assertOk(dec);
    deepStrictEqual(readFileSync(plain), readFileSync(ref));
  });
});

should.run(true);

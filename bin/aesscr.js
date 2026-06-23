#!/usr/bin/env node
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  scrypt as nodeScrypt,
} from 'node:crypto';
import { closeSync, constants, createReadStream, createWriteStream, openSync } from 'node:fs';
import { open, rename, rm, stat } from 'node:fs/promises';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { ReadStream, WriteStream } from 'node:tty';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

const scryptAsync = promisify(nodeScrypt);

const ENV_PASSWORD = 'AES_PASSWORD';
const EXTENSION = '.aesscr';
const EXTENSION_RE = /\.aesscr$/;
const MIN_CHARS = 14;
const NL = '\n';

// Protocol constants intentionally match sample.js.
const SALT = Buffer.from('aes-1234-scr-5678-gcm', 'utf8');
const SCRYPT_OPTS = {
  N: 2 ** 19,
  r: 8,
  p: 1,
  maxmem: 1024 ** 3 + 1024,
};
const KEY_LEN = 32;
const IV_LEN = 12;
const TAG_LEN = 16;
const ALGORITHM = 'aes-256-gcm';
const AES_GCM_MAX_BYTES = 2 ** 36 - 32;

function ensurePassword(password) {
  if (typeof password !== 'string' || password.length < MIN_CHARS)
    throw new Error(`PASSWORD must be ${MIN_CHARS} or more characters`);
}

function ensureBytes(bytes, name) {
  if (!(bytes instanceof Uint8Array)) throw new Error(`${name} must be Uint8Array`);
}

function formatSize(bytes) {
  return `${bytes} bytes`;
}

function ensureAesGcmSize(size, name) {
  if (size > AES_GCM_MAX_BYTES)
    throw new Error(
      `${name} is too large for ${ALGORITHM}: ${formatSize(size)} > ${formatSize(AES_GCM_MAX_BYTES)}`
    );
}

function openTTY() {
  if (process.stdin.isTTY && process.stdout.isTTY) {
    return {
      input: process.stdin,
      output: process.stdout,
      owned: false,
    };
  }
  const inputPath = process.platform === 'win32' ? 'CONIN$' : '/dev/tty';
  const outputPath = process.platform === 'win32' ? 'CONOUT$' : '/dev/tty';
  const noCtty = process.platform === 'win32' ? 0 : constants.O_NOCTTY;
  const inputFd = openSync(inputPath, constants.O_RDONLY | noCtty);
  const outputFd = openSync(outputPath, constants.O_WRONLY);
  return {
    input: new ReadStream(inputFd),
    output: new WriteStream(outputFd),
    inputFd,
    outputFd,
    owned: true,
  };
}

function closeFd(fd) {
  try {
    closeSync(fd);
  } catch {}
}

function askPasswordHidden(prompt = 'PASSWORD') {
  let tty;
  try {
    tty = openTTY();
  } catch {
    throw new Error(`Provide ${ENV_PASSWORD} env variable or run from a TTY`);
  }
  tty.input.setEncoding('utf8');
  return new Promise((resolve, reject) => {
    let input = '';
    let done = false;
    let isRaw = false;
    let escapeState = 'NORMAL';
    const cleanup = () => {
      tty.input.removeListener('data', onData);
      tty.input.removeListener('error', onError);
      tty.output.removeListener('error', onError);
      if (isRaw) {
        try {
          tty.input.setRawMode(false);
        } catch {}
      }
      if (tty.owned) {
        tty.input.destroy();
        tty.output.destroy();
        closeFd(tty.inputFd);
        closeFd(tty.outputFd);
      } else {
        tty.input.pause();
      }
    };
    const finish = (error, value = '') => {
      if (done) return;
      done = true;
      tty.output.write(NL, () => {
        cleanup();
        if (error) reject(error);
        else resolve(value);
      });
    };
    const onError = (error) => finish(error);
    const onData = (chunk) => {
      for (const c of chunk) {
        const code = c.charCodeAt(0);
        if (escapeState === 'START') {
          escapeState = c === '[' || c === 'O' ? 'PROCESS' : 'NORMAL';
          continue;
        }
        if (escapeState === 'PROCESS') {
          if (code >= 0x40 && code <= 0x7e) escapeState = 'NORMAL';
          continue;
        }
        if (c === '\x1B') {
          escapeState = 'START';
          continue;
        }
        if (['\u0004', '\r', NL].includes(c)) {
          finish(undefined, input.replace(/\r$/, ''));
          return;
        }
        if (c === '\u0003') {
          finish(new Error('ctrl-c'));
          return;
        }
        if (code === 127 || code === 8) {
          input = input.slice(0, -1);
          continue;
        }
        if (c.length === 1 && code < 32 && code !== 9) continue;
        input += c;
      }
    };
    tty.input.on('data', onData);
    tty.input.on('error', onError);
    tty.output.on('error', onError);
    try {
      tty.input.setRawMode(true);
      isRaw = true;
    } catch {
      finish(new Error('TTY raw mode unavailable'));
      return;
    }
    tty.output.write(`${prompt}: `);
    tty.input.resume();
  });
}

async function resolvePassword() {
  if (typeof process.env[ENV_PASSWORD] === 'string') return process.env[ENV_PASSWORD];
  return askPasswordHidden('PASSWORD');
}

export async function scr(password) {
  ensurePassword(password);
  return new Uint8Array(
    await scryptAsync(Buffer.from(password, 'utf8'), SALT, KEY_LEN, SCRYPT_OPTS)
  );
}

export async function encrypt(password, plaintext) {
  ensureBytes(plaintext, 'plaintext');
  ensureAesGcmSize(plaintext.length, 'plaintext');
  const key = await scr(password);
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: TAG_LEN });
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return new Uint8Array(Buffer.concat([iv, ciphertext, cipher.getAuthTag()]));
}

export async function decrypt(password, ciphertext) {
  ensureBytes(ciphertext, 'ciphertext');
  if (ciphertext.length < IV_LEN + TAG_LEN) throw new Error('ciphertext is too short');
  ensureAesGcmSize(ciphertext.length - IV_LEN - TAG_LEN, 'ciphertext');
  const key = await scr(password);
  const iv = ciphertext.subarray(0, IV_LEN);
  const tag = ciphertext.subarray(ciphertext.length - TAG_LEN);
  const body = ciphertext.subarray(IV_LEN, ciphertext.length - TAG_LEN);
  const decipher = createDecipheriv(ALGORITHM, key, iv, { authTagLength: TAG_LEN });
  decipher.setAuthTag(tag);
  return new Uint8Array(Buffer.concat([decipher.update(body), decipher.final()]));
}

function usage() {
  console.log(`usage:
  aesscr encrypt file.zip
  aesscr decrypt file.zip.aesscr
  PASSWORD must be 14 or more characters
  PASSWORD can be supplied in ${ENV_PASSWORD} env variable:
  AES_PASSWORD='abcdefabcdef1234' aesscr encrypt file.zip
  If ${ENV_PASSWORD} is not supplied, a hidden TTY prompt is used.
`);
  process.exit(1);
}

function checksumTransform(hash) {
  return new Transform({
    transform(chunk, _encoding, callback) {
      hash.update(chunk);
      callback(null, chunk);
    },
  });
}

function appendAuthTagTransform(cipher) {
  return new Transform({
    transform(chunk, _encoding, callback) {
      callback(null, chunk);
    },
    flush(callback) {
      try {
        callback(null, cipher.getAuthTag());
      } catch (error) {
        callback(error);
      }
    },
  });
}

async function writeChunk(stream, chunk) {
  if (stream.write(chunk)) return;
  await new Promise((resolve, reject) => {
    stream.once('drain', resolve);
    stream.once('error', reject);
  });
}

function tempPathFor(filePath) {
  return `${filePath}.${process.pid}.${Date.now()}.${randomBytes(6).toString('hex')}.tmp`;
}

async function cleanupTemp(tempPath, stream) {
  if (stream && !stream.destroyed) stream.destroy();
  if (tempPath) await rm(tempPath, { force: true }).catch(() => {});
}

async function readRange(filePath, position, length) {
  const fh = await open(filePath, 'r');
  try {
    const buffer = Buffer.allocUnsafe(length);
    let offset = 0;
    while (offset < length) {
      const { bytesRead } = await fh.read(buffer, offset, length - offset, position + offset);
      if (bytesRead === 0) throw new Error(`could not read ${length} bytes from ${filePath}`);
      offset += bytesRead;
    }
    return buffer;
  } finally {
    await fh.close();
  }
}

function printSum(hash) {
  console.log(`plaintext sha256 checksum: ${hash.digest('hex')}`);
}

async function encryptFile(password, filePath) {
  const inputStat = await stat(filePath);
  ensureAesGcmSize(inputStat.size, 'plaintext');
  const key = await scr(password);
  const iv = randomBytes(IV_LEN);
  const hash = createHash('sha256');
  const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: TAG_LEN });
  const encFilePath = `${filePath}${EXTENSION}`;
  const tempPath = tempPathFor(encFilePath);
  const output = createWriteStream(tempPath);
  try {
    await writeChunk(output, iv);
    await pipeline(
      createReadStream(filePath),
      checksumTransform(hash),
      cipher,
      appendAuthTagTransform(cipher),
      output
    );
    printSum(hash);
    await rename(tempPath, encFilePath);
    console.log(`saved to ${encFilePath}`);
  } catch (error) {
    await cleanupTemp(tempPath, output);
    throw error;
  }
}

async function decryptFile(password, filePath) {
  if (!filePath.endsWith(EXTENSION))
    throw new Error(`filename must end with ${EXTENSION}: abcdef.zip${EXTENSION}`);
  const inputStat = await stat(filePath);
  if (inputStat.size < IV_LEN + TAG_LEN) throw new Error('ciphertext is too short');
  ensureAesGcmSize(inputStat.size - IV_LEN - TAG_LEN, 'ciphertext');
  const key = await scr(password);
  const iv = await readRange(filePath, 0, IV_LEN);
  const tag = await readRange(filePath, inputStat.size - TAG_LEN, TAG_LEN);
  const decFilePath = `${filePath.replace(EXTENSION_RE, '')}`;
  const tempPath = tempPathFor(decFilePath);
  const output = createWriteStream(tempPath);
  const hash = createHash('sha256');
  const decipher = createDecipheriv(ALGORITHM, key, iv, { authTagLength: TAG_LEN });
  decipher.setAuthTag(tag);
  const ciphertextLen = inputStat.size - IV_LEN - TAG_LEN;
  const ciphertext =
    ciphertextLen === 0
      ? Readable.from([])
      : createReadStream(filePath, { start: IV_LEN, end: inputStat.size - TAG_LEN - 1 });
  try {
    await pipeline(ciphertext, decipher, checksumTransform(hash), output);
    printSum(hash);
    await rename(tempPath, decFilePath);
    console.log(`saved to ${decFilePath}`);
  } catch (error) {
    await cleanupTemp(tempPath, output);
    throw error;
  }
}

async function runAction(action, password, filePath) {
  if (action === 'encrypt') return encryptFile(password, filePath);
  if (action === 'decrypt') return decryptFile(password, filePath);
  usage();
}

async function main() {
  const action = process.argv[2];
  const filePath = process.argv[3];
  if (!['encrypt', 'decrypt'].includes(action) || typeof filePath !== 'string') usage();
  if (process.argv.length > 4) usage();
  const password = await resolvePassword();
  if (typeof password !== 'string' || password.length < MIN_CHARS) usage();
  await runAction(action, password, filePath);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(`[ERROR] ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  });
}

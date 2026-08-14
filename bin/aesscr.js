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
import { promisify } from 'node:util';

const scryptAsync = promisify(nodeScrypt);

const ENV_PASSWORD = 'AES_PASSWORD';
const EXTENSION = '.aesscr';
const MIN_CHARS = 14;

// File format: salt(32) || ciphertext || tag(16). A fresh random salt is
// generated per file; scrypt(password, salt) derives both key and iv, so
// key and iv uniqueness are guaranteed by salt uniqueness. Every byte of
// the file is indistinguishable from random: no magic, no version marker.
const SCRYPT_OPTS = {
  N: 2 ** 20,
  r: 8,
  p: 1,
  maxmem: 2 * 1024 ** 3,
};
const SALT_LEN = 32;
const KEY_LEN = 32;
const IV_LEN = 12;
const TAG_LEN = 16;
const ALGORITHM = 'aes-256-gcm';
const AES_GCM_MAX_BYTES = 2 ** 36 - 32;
// 64KiB default stream chunks cost ~20% throughput on large files.
const CHUNK_SIZE = 8 * 1024 * 1024;

function ensureAesGcmSize(size, name) {
  if (size > AES_GCM_MAX_BYTES)
    throw new Error(
      `${name} is too large for ${ALGORITHM}: ${size} bytes > ${AES_GCM_MAX_BYTES} bytes`
    );
}

function openTTY() {
  if (process.stdin.isTTY && process.stdout.isTTY) {
    return { input: process.stdin, output: process.stdout, owned: false };
  }
  const isWin = process.platform === 'win32';
  const noCtty = isWin ? 0 : constants.O_NOCTTY;
  const inputFd = openSync(isWin ? 'CONIN$' : '/dev/tty', constants.O_RDONLY | noCtty);
  const outputFd = openSync(isWin ? 'CONOUT$' : '/dev/tty', constants.O_WRONLY);
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
      tty.output.write('\n', () => {
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
        if (['\u0004', '\r', '\n'].includes(c)) {
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

async function scr(password, salt) {
  const okm = await scryptAsync(Buffer.from(password, 'utf8'), salt, KEY_LEN + IV_LEN, SCRYPT_OPTS);
  return { key: okm.subarray(0, KEY_LEN), iv: okm.subarray(KEY_LEN) };
}

function usage() {
  console.log(`usage:
  aesscr encrypt file.zip
  aesscr decrypt file.zip.aesscr
  --sum also prints plaintext sha256 checksum (slower;
  integrity is always verified via GCM tag regardless)
  PASSWORD must be ${MIN_CHARS} or more characters
  PASSWORD can be supplied in ${ENV_PASSWORD} env variable:
  AES_PASSWORD='abcdefabcdef1234' aesscr encrypt file.zip
  If ${ENV_PASSWORD} is not supplied, a hidden TTY prompt is used.
`);
  process.exit(1);
}

// Returns [] when disabled so it can be spread into a pipeline.
function checksumTransform(hash) {
  if (!hash) return [];
  return [
    new Transform({
      transform(chunk, _encoding, callback) {
        hash.update(chunk);
        callback(null, chunk);
      },
    }),
  ];
}

// Wraps cipher output into the file format: salt || ciphertext || tag.
function gcmFrameTransform(salt, cipher) {
  let first = true;
  return new Transform({
    transform(chunk, _encoding, callback) {
      if (first) {
        first = false;
        this.push(salt);
      }
      callback(null, chunk);
    },
    flush(callback) {
      if (first) this.push(salt);
      try {
        callback(null, cipher.getAuthTag());
      } catch (error) {
        callback(error);
      }
    },
  });
}

// Streams through a temp file, renames into place on success, cleans up on error.
async function writeAtomic(destPath, streams) {
  const tempPath = `${destPath}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
  const output = createWriteStream(tempPath, { highWaterMark: CHUNK_SIZE });
  try {
    await pipeline(...streams, output);
    await rename(tempPath, destPath);
  } catch (error) {
    if (!output.destroyed) output.destroy();
    await rm(tempPath, { force: true }).catch(() => {});
    throw error;
  }
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
  if (hash) console.log(`plaintext sha256 checksum: ${hash.digest('hex')}`);
}

async function encryptFile(password, filePath, withSum) {
  const { size } = await stat(filePath);
  ensureAesGcmSize(size, 'plaintext');
  const salt = randomBytes(SALT_LEN);
  const { key, iv } = await scr(password, salt);
  const hash = withSum ? createHash('sha256') : null;
  const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: TAG_LEN });
  const encFilePath = `${filePath}${EXTENSION}`;
  await writeAtomic(encFilePath, [
    createReadStream(filePath, { highWaterMark: CHUNK_SIZE }),
    ...checksumTransform(hash),
    cipher,
    gcmFrameTransform(salt, cipher),
  ]);
  printSum(hash);
  console.log(`saved to ${encFilePath}`);
}

async function decryptFile(password, filePath, withSum) {
  if (!filePath.endsWith(EXTENSION))
    throw new Error(`filename must end with ${EXTENSION}: abcdef.zip${EXTENSION}`);
  const { size } = await stat(filePath);
  if (size < SALT_LEN + TAG_LEN) throw new Error('ciphertext is too short');
  const bodyLen = size - SALT_LEN - TAG_LEN;
  ensureAesGcmSize(bodyLen, 'ciphertext');
  const salt = await readRange(filePath, 0, SALT_LEN);
  const tag = await readRange(filePath, size - TAG_LEN, TAG_LEN);
  const { key, iv } = await scr(password, salt);
  const decipher = createDecipheriv(ALGORITHM, key, iv, { authTagLength: TAG_LEN });
  decipher.setAuthTag(tag);
  const hash = withSum ? createHash('sha256') : null;
  const decFilePath = filePath.slice(0, -EXTENSION.length);
  const body =
    bodyLen === 0
      ? Readable.from([])
      : createReadStream(filePath, {
          start: SALT_LEN,
          end: size - TAG_LEN - 1,
          highWaterMark: CHUNK_SIZE,
        });
  await writeAtomic(decFilePath, [body, decipher, ...checksumTransform(hash)]);
  printSum(hash);
  console.log(`saved to ${decFilePath}`);
}

async function main() {
  const argv = process.argv.slice(2);
  const withSum = argv.includes('--sum');
  const [action, filePath, ...rest] = argv.filter((a) => a !== '--sum');
  if (!['encrypt', 'decrypt'].includes(action) || typeof filePath !== 'string' || rest.length > 0)
    usage();
  const password = await resolvePassword();
  if (typeof password !== 'string' || password.length < MIN_CHARS) usage();
  if (action === 'encrypt') await encryptFile(password, filePath, withSum);
  else await decryptFile(password, filePath, withSum);
}

main().catch((error) => {
  console.error(`[ERROR] ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});

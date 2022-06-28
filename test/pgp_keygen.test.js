const cp = require('child_process');
const fs = require('fs');
const { randomBytes } = require('@noble/hashes/utils');
const pgp = require('../lib/pgp');
const { deepStrictEqual } = require('assert');
const { should } = require('micro-should');

// Warning: this test will execute system command `gpg`

const PUB_PATH = `${__dirname}/key.pub`;
const PRIV_PATH = `${__dirname}/key.priv`;

function cmdArgs(command) {
  const [cmd, ...args] = command.split(' ');
  return { cmd, args };
}

function exec(command, opt = {}) {
  const { cmd, args } = cmdArgs(command);
  const { status, stdout, stderr } = cp.spawnSync(cmd, args, {
    stdio: ['pipe', 'pipe', 'pipe'],
    input: opt && opt.input,
    shell: true,
    encoding: 'utf8',
  });
  if (!(opt && opt.ignoreStatus) && status)
    throw new Error(`Wrong status code for ${command}: ${status}`);
  return { status, stdout, stderr };
}

should('basic', async () => {
  // Deterministic via scrypt
  const seed = randomBytes();
  let { publicKey, privateKey, keyId } = await pgp.getKeys(seed, 'user', 'password');
  const SECRET_KEY_OPT = `--no-tty --batch --yes --passphrase "password"`;

  const cleanKeys = () => {
    exec(`gpg  --delete-secret-and-public-key ${keyId}`, { ignoreStatus: true });
    fs.rmSync(PUB_PATH);
    fs.rmSync(PRIV_PATH);
  };
  fs.writeFileSync(PUB_PATH, publicKey);
  fs.writeFileSync(PRIV_PATH, privateKey);
  try {
    exec(`gpg ${SECRET_KEY_OPT} --import ${PRIV_PATH}`, { status: true });
    exec(`gpg ${SECRET_KEY_OPT} --import ${PUB_PATH}`, { status: true });
    const signed = exec(
      `gpg ${SECRET_KEY_OPT} --default-key ${keyId.toUpperCase()} -r --encrypt --sign --armor`,
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
    deepStrictEqual(decryptedInfo.includes('Good signature from "user" [uncertain]'), true);
  } finally {
    cleanKeys();
  }
});

if (require.main === module) should.run();

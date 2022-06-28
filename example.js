(async () => {
  console.log('SSH');
  const ssh = require('./lib/ssh');
  const { randomBytes } = require('./lib/utils');
  const sseed = randomBytes(32);
  const skeys = await ssh.getKeys(sseed, 'user@example.com');
  console.log(skeys.fingerprint);
  console.log(skeys.privateKey);
  console.log(skeys.publicKey);

  console.log('\n\n\nPGP');
  const pgp = require('./lib/pgp');
  // const { randomBytes } = require('ed25519-keygen/utils');
  const pseed = randomBytes(32);
  const pkeys = await pgp.getKeys(pseed, 'user@example.com', 'password');
  console.log(pkeys.keyId);
  console.log(pkeys.privateKey);
  console.log(pkeys.publicKey);

  console.log('\n\n\nTOR');
  const tor = require('./lib/tor');
  // const { randomBytes } = require('ed25519-keygen/utils');
  const tseed = randomBytes(32);
  const tkeys = await tor.getKeys(tseed);
  console.log(tkeys.privateKey);
  console.log(tkeys.publicKey);
})();

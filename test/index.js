import { should } from 'micro-should';

import './ssh.test.js';
import './tor.test.js';
import './bls.test.js';
import './password.test.js';
import './otp.test.js';
import './ipns.test.js';
import './pgp.test.js';
import './slip10/index.test.mjs';
// Not enabled by default because requires gpg installed && interactive commands
//require('./pgp_keygen.test.js');

import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}

import { should } from 'micro-should';

import './ssh.test.js';
import './tor.test.js';
import './ipns.test.js';
import './pgp.test.js';
import './hdkey/index.test.mjs';
// Not enabled by default because requires gpg installed && interactive commands
//require('./pgp_keygen.test.js');

should.run();

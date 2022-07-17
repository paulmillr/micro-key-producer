import { should } from 'micro-should';

import './ssh.test.js';
import './tor.test.js';
import './pgp.test.js';
// Not enabled by default because requires gpg installed && interactive commands
//require('./pgp_keygen.test.js');

should.run();

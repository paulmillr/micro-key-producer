import { should } from '@paulmillr/jsbt/test.js';

import './bls.test.ts';
import './convert.test.ts';
import './ipns.test.ts';
import './otp.test.ts';
import './password.test.ts';
import './pgp.test.ts';
import './slip10/index.test.mjs';
import './ssh.test.ts';
import './tor.test.ts';

// Not enabled by default because requires gpg installed && interactive commands
//require('./pgp-keygen.test.ts');

should.runWhen(import.meta.url);

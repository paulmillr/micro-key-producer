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
import './x509-nist.test.ts';
import './x509.test.ts';

// Not enabled by default: these require local command-line tools or are very slow.
// Use `npm run test:gpg` for `pgp-gpg.test.ts`.
// Add `-- --agent` to opt into private-key/passphrase GnuPG checks.
// Use `npm run test:openssl` for `x509-openssl.test.ts`.
// Use `npm run test:ssh` for `ssh-openssh.test.ts`.
// Use `node --experimental-strip-types --no-warnings test/password-slow.test.ts`
// for entropy sanity.

should.runWhen(import.meta.url);

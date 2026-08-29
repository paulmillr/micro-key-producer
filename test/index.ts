import { should } from '@paulmillr/jsbt/test.js';

import './convert.test.ts';
import './ipns.test.ts';
import './otp.test.ts';
import './password.test.ts';
import './pgp.test.ts';
import './slip10/index.test.mjs';
import './ssh.test.ts';
import './tor.test.ts';
import './utils.test.ts';
import './x509-nist.test.ts';
import './x509.test.ts';

// Not enabled by default: these require local command-line tools or are very slow.
// Use `npm run test:integration` for gpg/openssl/ssh-keygen/CLI tests (see test/integration.ts).
// Add `-- --agent` to opt into private-key/passphrase GnuPG checks.
// Use `node --experimental-strip-types --no-warnings test/password-slow.test.ts`
// for entropy sanity.

should.runWhen(import.meta.url);

import { should } from '@paulmillr/jsbt/test.js';

// Tests requiring local command-line tools (gpg, openssl, ssh-keygen) or the
// package's own bins. Each file skips itself when the tool is unavailable.
// Add `-- --agent` to opt into private-key/passphrase GnuPG checks.
import './pgp-cli.test.ts';
import './pgp-gpg.test.ts';
import './ssh-openssh.test.ts';
import './x509-openssl.test.ts';

should.runWhen(import.meta.url);

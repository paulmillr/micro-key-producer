const { should } = require('micro-should');

require('./ssh.test.js');
require('./tor.test.js');
require('./pgp.test.js');
// Not enabled by default because requires gpg installed && interactive commands
//require('./pgp_keygen.test.js');

should.run();

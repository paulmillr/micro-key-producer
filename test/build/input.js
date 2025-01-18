import ssh from 'micro-key-producer/ssh.js';
import pgp from 'micro-key-producer/pgp.js';
import * as pwd from 'micro-key-producer/password.js';
import * as otp from 'micro-key-producer/otp.js';
import tor from 'micro-key-producer/tor.js';
import ipns from 'micro-key-producer/ipns.js';
import slip10 from 'micro-key-producer/slip10.js';
import { randomBytes } from 'micro-key-producer/utils.js';

const utils = { randomBytes };
export { ssh, pgp, pwd, otp, tor, ipns, slip10, utils };

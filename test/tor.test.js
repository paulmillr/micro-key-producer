import { deepStrictEqual } from 'node:assert';
import { describe, should } from 'micro-should';
import * as tor from '../esm/tor.js';
import { hex } from '@scure/base';

describe('tor', () => {
  should('basic', () => {
    const seed = hex.decode('87e09c06a31743bb594cd0d6294c358883fb3ef2269f6e48816339eccb0d6489');
    const pub = hex.decode('b858d727e5f97d316dc2089cc1cc3d9966146526213557daec62097b914f88b4');
    const addr = 'xbmnoj7f7f6tc3ocbcomdtb5tftbizjgee2vpwxmmiexxekprc2o76yd.onion';
    deepStrictEqual(tor.getKeys(seed), {
      publicKey: addr,
      publicKeyBytes: pub,
      privateKey:
        'ED25519-V3:QP35WyM1BIJZyos8sqwGmEnrlWWo55YA3ihmYoS1LFWp8m1L0NTpiiHH2H4K9cSz7RMN82YKi8YPgqUD7P+sdA==',
    });
    const parsed = tor.parseAddress(addr);
    deepStrictEqual(tor.formatPublicKey(parsed), addr);
  });
});

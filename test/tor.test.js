const { deepStrictEqual } = require('assert');
const { should } = require('micro-should');
const tor = require('../lib/tor');
const { hex } = require('@scure/base');

should('tor: basic', async () => {
  const seed = hex.decode('87e09c06a31743bb594cd0d6294c358883fb3ef2269f6e48816339eccb0d6489');
  const PUB = 'xbmnoj7f7f6tc3ocbcomdtb5tftbizjgee2vpwxmmiexxekprc2o76yd.onion';

  deepStrictEqual(await tor.getKeys(seed), {
    publicKey: PUB,
    privateKey:
      'ED25519-V3:QP35WyM1BIJZyos8sqwGmEnrlWWo55YA3ihmYoS1LFWp8m1L0NTpiiHH2H4K9cSz7RMN82YKi8YPgqUD7P+sdA==',
  });
  deepStrictEqual(await tor.formatPublicKey(await tor.parseAddress(PUB)), PUB);
});

if (require.main === module) should.run();

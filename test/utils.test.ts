import { it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { Buffer } from 'node:buffer';
import { base36 } from '../src/utils.ts';

const hexToArray = (hex: string) => Uint8Array.from(Buffer.from(hex, 'hex'));

// base36 is re-exported from @scure/base 2.4.0; these vectors guard the re-export's
// leading-zero and alphabet behavior that IPNS addresses depend on.
const VECTORS: [string, string][] = [
  ['', ''],
  ['00', '0'],
  ['0000', '00'],
  ['01', '1'],
  ['24', '10'],
  ['68656c6c6f20776f726c64', 'fuvrsivvnfrbjwajo'],
  ['000068656c6c6f20776f726c64', '00fuvrsivvnfrbjwajo'],
  ['516b6fcd0f', '4gnba1hr'],
  [
    '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
    'wjzlh5yt3uk0mzpcor0i12ol0rrpxdydzggt4b2fvr8yealc',
  ],
  [
    // IPNS address payload: CIDv1 libp2p-key of an ed25519 pubkey
    '017200240801122012c8299ec2c51dffbbcb4f9fccadcee1424cb237e9b30d3cd72d47c18103689d',
    '51qzi5uqu5dgnfwbc46une4upw1vc9hxznymyeykmg6rev1513yrnbyrwmmql',
  ],
];

it('base36: vectors', () => {
  for (const [hex, encoded] of VECTORS) {
    eql(base36.encode(hexToArray(hex)), encoded);
    eql(base36.decode(encoded), hexToArray(hex));
  }
});

it('base36: invalid input', () => {
  throws(() => base36.decode('ABC')); // uppercase is not in the alphabet
  throws(() => base36.decode('a-b'));
  throws(() => base36.decode(1 as any));
  throws(() => base36.encode('str' as any));
});

it.runWhen(import.meta.url);

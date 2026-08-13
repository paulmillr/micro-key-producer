import { it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { Buffer } from 'node:buffer';
import { base36 } from '../src/utils.ts';

const hexToArray = (hex: string) => Uint8Array.from(Buffer.from(hex, 'hex'));

// Vendored base36; drop these along with the implementation once @scure/base ships it.
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

it('base36: parity with bigint reference', () => {
  const letters = '0123456789abcdefghijklmnopqrstuvwxyz';
  const refEncode = (bytes: Uint8Array) => {
    let zeros = 0;
    while (zeros < bytes.length - 1 && bytes[zeros] === 0) zeros++;
    let num = 0n;
    for (const b of bytes) num = (num << 8n) | BigInt(b);
    let res = '';
    for (; num > 0n; num /= 36n) res = letters[Number(num % 36n)] + res;
    if (!res && bytes.length) res = '0';
    return letters[0].repeat(zeros) + res;
  };
  let seed = 0x2f6e2b1;
  const rand = () => (seed = (seed * 48271) % 0x7fffffff) & 0xff;
  for (let len = 0; len < 130; len++) {
    const bytes = new Uint8Array(len).map(() => rand());
    if (len > 2) {
      bytes[0] = 0;
      bytes[1] = 0;
    }
    const encoded = base36.encode(bytes);
    eql(encoded, refEncode(bytes));
    eql(base36.decode(encoded), bytes);
  }
});

it('base36: invalid input', () => {
  throws(() => base36.decode('ABC')); // uppercase is not in the alphabet
  throws(() => base36.decode('a-b'));
  throws(() => base36.decode(1 as any));
  throws(() => base36.encode('str' as any));
});

it.runWhen(import.meta.url);

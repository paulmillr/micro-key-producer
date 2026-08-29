import { ed25519 } from '@noble/curves/ed25519.js';
import { describe, it } from '@paulmillr/jsbt/test.js';
import { hex } from '@scure/base';
import { deepStrictEqual, throws } from 'node:assert';
import * as tor from '../src/tor.ts';

const seed = hex.decode('87e09c06a31743bb594cd0d6294c358883fb3ef2269f6e48816339eccb0d6489');
const pub = hex.decode('b858d727e5f97d316dc2089cc1cc3d9966146526213557daec62097b914f88b4');
const addr = 'xbmnoj7f7f6tc3ocbcomdtb5tftbizjgee2vpwxmmiexxekprc2o76yd.onion';
const shortAddr = 'aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaenjiay=.onion';
const longAddr = 'aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqdbgpam======.onion';

describe('tor', () => {
  it('basic', () => {
    deepStrictEqual(tor.getKeys(seed), {
      publicKey: addr,
      publicKeyBytes: pub,
      privateKey:
        'ED25519-V3:QP35WyM1BIJZyos8sqwGmEnrlWWo55YA3ihmYoS1LFWp8m1L0NTpiiHH2H4K9cSz7RMN82YKi8YPgqUD7P+sdA==',
    });
    const parsed = tor.parseAddress(addr);
    deepStrictEqual(tor.formatPublicKey(parsed), addr);
  });
  it('reject malformed Tor v3 public key payload lengths', () => {
    const bytes = pub.slice();
    deepStrictEqual(tor.formatPublicKey(bytes), addr);
    deepStrictEqual(bytes, pub);
    throws(() => tor.formatPublicKey(pub.slice(0, 31)));
    throws(() => tor.formatPublicKey(new Uint8Array([...pub, 0])));
    throws(() => tor.parseAddress(shortAddr));
    throws(() => tor.parseAddress(longAddr));
  });
  it('rejects weak Ed25519 signing identities', () => {
    const identity = new Uint8Array(32);
    identity[0] = 1;
    const noncanonicalIdentity = new Uint8Array(32).fill(0xff);
    noncanonicalIdentity[0] = 0xee;
    noncanonicalIdentity[31] = 0x7f;
    const torsion = ed25519.Point.fromBytes(new Uint8Array(32), false);
    const mixedOrder = ed25519.Point.BASE.add(torsion).toBytes();
    for (const weak of [identity, noncanonicalIdentity, new Uint8Array(32), mixedOrder])
      throws(() => tor.formatPublicKey(weak), /weak Ed25519 public key/);
  });
});

it.runWhen(import.meta.url);

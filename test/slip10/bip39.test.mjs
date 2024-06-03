import {
  TEST_MNEMONIC_12,
  TEST_MNEMONIC_12_SET,
  TEST_MNEMONIC_24,
  TEST_MNEMONIC_24_PUBLIC_KEY,
  TEST_MNEMONIC_24_SECRET_KEY,
  TEST_MNEMONIC_24_SET,
  TEST_MNEMONIC_24_SECRET_BYTEARRAY,
  TEST_PUBLIC_KEY,
  TEST_SECRET_BYTEARRAY,
  TEST_SECRET_KEY,
} from './bip39.fixture.mjs';
import { should } from 'micro-should';
import { deepStrictEqual } from 'node:assert';

import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { Keypair as SolanaKeypair, PublicKey as SolanaPublicKey } from '@solana/web3.js';
import { base58 as bs58 } from '@scure/base';
import { HDKey } from '../../hdkey.js';

export class Keypair {
  constructor(secretKey) {
    this.solanaKeypair = SolanaKeypair.fromSecretKey(bs58.decode(secretKey));
    this.publicKey = this.solanaKeypair.publicKey.toBase58();
    this.secretKey = bs58.encode(this.solanaKeypair.secretKey);
  }

  get solana() {
    return this.solanaKeypair;
  }

  get solanaPublicKey() {
    return this.solanaKeypair.publicKey;
  }

  get solanaSecretKey() {
    return this.solanaKeypair.secretKey;
  }

  static fromByteArray(byteArray) {
    return this.fromSecretKey(bs58.encode(Uint8Array.from(byteArray)));
  }

  static fromMnemonicSeed(mnemonic) {
    const seed = bip39.mnemonicToSeedSync(mnemonic, '');

    return this.fromSeed(Buffer.from(seed).slice(0, 32));
  }

  static fromMnemonic(mnemonic) {
    return this.fromMnemonicSet(mnemonic)[0];
  }

  static fromMnemonicSet(mnemonic, from = 0, to = 10) {
    // Always start with zero as minimum
    from = from < 0 ? 0 : from;
    // Always generate at least 1
    to = to <= from ? 1 : to;

    const seed = bip39.mnemonicToSeedSync(mnemonic, '');
    const keys = [];

    for (let i = from; i < to; i++) {
      const path = `m/44'/501'/${i}'/0'`;
      const kp = this.derive(Buffer.from(seed), path);
      kp.mnemonic = mnemonic;
      keys.push(kp);
    }
    return keys;
  }

  static derive(seed, path) {
    const hd = HDKey.fromMasterSeed(seed.toString('hex'));
    return Keypair.fromSeed(hd.derive(path).privateKey);
  }

  static fromSeed(seed) {
    return this.fromSecretKey(bs58.encode(SolanaKeypair.fromSeed(seed).secretKey));
  }

  static fromSecretKey(secretKey) {
    return new Keypair(secretKey);
  }

  static random() {
    const mnemonic = this.generateMnemonic();
    const [kp] = this.fromMnemonicSet(mnemonic);

    return kp;
  }

  static generateMnemonic(strength = 128) {
    return bip39.generateMnemonic(wordlist, strength);
  }
}

should('import from a mnemonic (12)', () => {
  const keypair = Keypair.fromMnemonicSeed(TEST_MNEMONIC_12);
  deepStrictEqual(keypair.secretKey, TEST_SECRET_KEY);
  deepStrictEqual(keypair.solanaSecretKey.toString(), TEST_SECRET_BYTEARRAY.toString());
  deepStrictEqual(keypair.solanaPublicKey.toBase58(), TEST_PUBLIC_KEY);
  deepStrictEqual(keypair.publicKey, TEST_PUBLIC_KEY);
});

should('import from a mnemonic (24)', () => {
  const keypair = Keypair.fromMnemonicSeed(TEST_MNEMONIC_24);
  deepStrictEqual(keypair.secretKey, TEST_MNEMONIC_24_SECRET_KEY);
  deepStrictEqual(keypair.solanaSecretKey.toString(), TEST_MNEMONIC_24_SECRET_BYTEARRAY.toString());
  deepStrictEqual(keypair.solanaPublicKey.toBase58(), TEST_MNEMONIC_24_PUBLIC_KEY);
  deepStrictEqual(keypair.publicKey, TEST_MNEMONIC_24_PUBLIC_KEY);
});

should('import multiple from a mnemonic (12 chars)', () => {
  const set = Keypair.fromMnemonicSet(TEST_MNEMONIC_12);
  const keys = set.map(({ mnemonic, secretKey, publicKey }) => ({
    mnemonic,
    secretKey,
    publicKey,
  }));

  deepStrictEqual(
    keys.map(({ mnemonic, publicKey, secretKey }) => ({ mnemonic, publicKey, secretKey })),
    TEST_MNEMONIC_12_SET
  );
});

should('import multiple from a mnemonic (24 chars)', () => {
  const set = Keypair.fromMnemonicSet(TEST_MNEMONIC_24);
  const keys = set.map(({ mnemonic, secretKey, publicKey }) => ({
    mnemonic,
    secretKey,
    publicKey,
  }));

  deepStrictEqual(
    keys.map(({ mnemonic, publicKey, secretKey }) => ({ mnemonic, publicKey, secretKey })),
    TEST_MNEMONIC_24_SET
  );
});

// should.run();

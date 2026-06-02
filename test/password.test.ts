import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import * as pwd from '../src/password.ts';

describe('password', () => {
  should('Set utils', () => {
    const a = new Set([1, 2, 3, 4]);
    const b = new Set([2, 3, 4, 5]);
    const c = new Set([3, 4, 5, 6]);
    eql(pwd.utils.and(a, b, c), new Set([3, 4]));
    eql(pwd.utils.or(a, b, c), new Set([1, 2, 3, 4, 5, 6]));

    const aa = new Set('abc');
    const bb = new Set('def');
    const cc = new Set('qr');
    // prettier-ignore
    eql(pwd.utils.product(aa, bb, cc), new Set([
      'adq', 'adr', 'aeq', 'aer', 'afq', 'afr',
      'bdq', 'bdr', 'beq', 'ber', 'bfq', 'bfr',
      'cdq', 'cdr', 'ceq', 'cer', 'cfq', 'cfr',
    ]));
    eql(pwd.utils.DATE.y, 365 * pwd.utils.DATE.d);
    eql(pwd.utils.formatDuration(2 * 365 * pwd.utils.DATE.d), '2y');
  });
  should('Mask utils', () => {
    eql(pwd.mask('11').cardinality, 100n);
    eql(pwd.mask('aa').cardinality, 26n * 26n);
    eql(pwd.mask('aaaa-aaaa').cardinality, 26n ** 8n);
    throws(() => pwd.mask(''), /expected non-empty mask/);
    const compiled = pwd.mask('a');
    const stableEntropy = new Uint8Array([0, 0]);
    const stable = compiled.apply(stableEntropy);
    eql(Object.isFrozen(pwd.alphabet), true);
    eql(Object.isFrozen(pwd.alphabet.a), true);
    eql(compiled.apply(stableEntropy), stable);
    // len(bin(100).replace('0b',''))-1 (since last bit is not fully used if number is not power of two)
    eql(pwd.utils.cardinalityBits(100n), 6);
    eql(pwd.utils.cardinalityBits(64n), 6);
    eql(pwd.utils.cardinalityBits(63n), 5);
    eql(pwd.utils.cardinalityBits(31n), 4);
    eql(pwd.utils.cardinalityBits(0xffff_ffff_ffff_ffffn), 63);
    eql(pwd.utils.cardinalityBits(0xffff_ffff_ffff_fff0n), 63);
    eql(pwd.utils.cardinalityBits(0x1fff_ffff_ffff_fff0n), 60);
    throws(() => pwd.utils.cardinalityBits(0n), RangeError);
    throws(() => pwd.utils.cardinalityBits(-1n), RangeError);
    const entropy = sha256(utf8ToBytes('hello world'));
    // Inverse works
    for (const m of ['@Ss-ss-ss', '************', 'AaAa+AaA11..@@@@'])
      eql(pwd.mask(m).inverse(pwd.mask(m).apply(entropy)), entropy);
    // Just for research
    eql(pwd.mask('aa').entropy, 9);
    eql(pwd.mask('Aaaaaa@1').entropy, 36);
    eql(pwd.mask('********').entropy, 52);
    eql(pwd.mask('****-****-*').entropy, 58);
    eql(pwd.mask('****-****-**').entropy, 65);
    eql(pwd.mask('****-****-***').entropy, 72);
    eql(pwd.mask('****-****-****').entropy, 78);
    eql(pwd.mask('@Ss-ss-ss').entropy, 46);
    eql(pwd.mask('Sss-sss-ssc1').entropy, 62);
    eql(pwd.mask('Cvccvc-cvccvc-cvccv1').entropy, 66);
  });
  should('checkPassword', () => {
    eql(pwd.checkPassword('aa'), false);
    eql(pwd.checkPassword('aaaaaaaa'), false);
    eql(pwd.checkPassword('Aaaaaaaa'), false);
    eql(pwd.checkPassword('Aaaaaa3a'), false);
    eql(pwd.checkPassword('Aaaaaa3!'), true);
    eql(pwd.checkPassword('Aa1!\u{1f604}\u{1f604}'), false);
  });
  should('Mask generator is reversible', () => {
    const entropy = sha256(utf8ToBytes('hello world'));
    // Inverse works
    for (const m of [
      '@Ss-ss-ss',
      '************',
      'AaAa+AaA11..@@@@',
      '1111111-11111-1111-11-1',
      '*1*AnSs@Nl',
    ]) {
      eql(pwd.mask(m).inverse(pwd.mask(m).apply(entropy)), entropy);
    }
    eql('*Tavy-qyjy-vemo', pwd.mask('@Ss-ss-ss').apply(entropy).password);
    // Adding more symbols to mask doesn't change previous
    eql('*Tavy-qyjy-vemo-pysu', pwd.mask('@Ss-ss-ss-ss').apply(entropy).password);
    eql('Mavysa-dobywi-nuwem2', pwd.mask('Sss-sss-ssc1').apply(entropy).password);
    eql('Mavmuq-xadgys-poqsa5', pwd.mask('Cvccvc-cvccvc-cvccv1').apply(entropy).password);
    eql('mavysa', pwd.mask('cvcvcv').apply(entropy).password);
    eql('Mav-muq-xad', pwd.mask('Cvc-cvc-cvc').apply(entropy).password);
  });
  should('Secure mask', () => {
    // Basic sanity check that masks looks like safari secure password
    const vectors = [
      'kudpoh-6zyvis-nozsyB',
      'vicmyn-5xatit-Wuwzol',
      'fyfdap-2fikUb-huvcyc',
      'Xejfaw-cobfy0-morvus',
      'vimpur-donjiB-3nilon',
      'zucnAl-8holem-mutmeg',
      'Dytxe8-zocwes-wasbin',
      '4lyqyJ-jyfvyk-bibmuv',
      'higqop-nanba7-Vommas',
      'zuJzig-0maraz-lizpyz',
    ];
    for (let i = 0; i < 10; i++) {
      const entropy = sha256(utf8ToBytes(`hello world${i}`));
      eql(pwd.secureMask.apply(entropy).password, vectors[i]);
      eql(pwd.secureMask.inverse(pwd.secureMask.apply(entropy)), entropy);
    }
    const leading = new Uint8Array(32);
    leading[1] = 1;
    leading[31] = 23;
    eql(pwd.secureMask.inverse(pwd.secureMask.apply(leading)), leading);
    const sparse = new Uint8Array(32);
    sparse[16] = 1;
    sparse[31] = 23;
    eql(pwd.secureMask.inverse(pwd.secureMask.apply(sparse)), sparse);
    throws(() => pwd.secureMask.apply(Uint8Array.of(1)), /expected Uint8Array of length 32/);
  });
  should('Estimates', () => {
    // Manually  sanity checked via zxcvbn && recalc
    eql(pwd.mask('1').estimate().costs, {
      luks: 3.117676864901788e-8,
      filevault2: 4.693824276642289e-9,
      macos: 6.967971085714072e-10,
      pbkdf2: 2.344432896659112e-10,
    });
    eql(pwd.mask('cvcvcv').estimate(), {
      score: 'somewhat guessable',
      guesses: {
        online_throttling: '1y 11mo 25d',
        online: '2d',
        slow: '2min 52sec',
        fast: '0 sec',
      },
      costs: {
        luks: 0.005387345622550289,
        filevault2: 0.0008110928350037875,
        macos: 0.00012040654036113917,
        pbkdf2: 0.000040511800454269456,
      },
    });
    eql(pwd.mask('Cvc-cvc-cvc').estimate(), {
      score: 'very unguessable',
      guesses: {
        online_throttling: 'centuries',
        online: '43y 10mo 5d',
        slow: '16d',
        fast: '1sec',
      },
      costs: {
        luks: 43.098764980402315,
        filevault2: 6.488742680030301,
        macos: 0.9632523228891134,
        pbkdf2: 0.3240944036341557,
      },
    });
    eql(pwd.mask('Cvccvc-cvccvc-cvccv1').estimate(), {
      score: 'very unguessable',
      guesses: {
        online_throttling: 'centuries',
        online: 'centuries',
        slow: 'centuries',
        fast: 'centuries',
      },
      costs: {
        luks: 297898663544.54083,
        filevault2: 44850189404.36944,
        macos: 6658000055.809552,
        pbkdf2: 2240140517.919284,
      },
    });
  });
});

should.runWhen(import.meta.url);

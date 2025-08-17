import { should } from 'micro-should';
import assert from 'node:assert';
import crypto from 'node:crypto';
import * as pwd from '../src/password.ts';

const randomBytes = (len) => Uint8Array.from(crypto.randomBytes(len));
const ITERS = 10000000;
const percent = (n) => Math.ceil(n * 100);

function genPasswords(mask) {
  const res = Array.from({ length: mask.length }, () => ({}));
  for (let i = 0; i < ITERS; i++) {
    const password = mask.apply(randomBytes(32)).password;
    for (let i = 0; i < password.length; i++) {
      const c = password[i];
      if (!res[i][c]) res[i][c] = 0;
      res[i][c]++;
    }
  }
  return res;
}

function verifyLengths(mask, res) {
  const len = mask.sets.map((s, idx) => ({
    set: s.size,
    real: Object.keys(res[idx]).length,
  }));
  // check that all symbols produced
  for (const i of len) assert.deepStrictEqual(i.real, i.set);
}

function verifyEntropy(res) {
  for (const k in res) {
    const vals = Object.values(res[k]).map((i) => i / ITERS);
    let stats = { min: Math.min(...vals), max: Math.max(...vals) };
    stats.avg = (stats['min'] + stats['max']) / 2;
    stats.percent = percent((stats['max'] - stats['min']) / stats['avg']);
    console.log('ENTROPY', stats);
    // should be 1-2 percent, but can be up to 5. More iterations will probably reduce to zero, but will take too much time.
    if (stats.percent >= 5) console.log('T', res[k]);
    assert.deepStrictEqual(stats.percent < 5, true);
  }
}

// Very slow, but verifies that password generation is reasonable and there is no significant deviations in
// probability of each symbol in alphabet
should('Entropy sanity check', () => {
  const mask = pwd.mask('AaVvCc1@nl*');
  const res = genPasswords(mask);
  verifyLengths(mask, res);
  verifyEntropy(res);
});
should('Entropy sanity check for Cvccvc-cvccvc-cvccv1', () => {
  const mask = pwd.mask('Cvccvc-cvccvc-cvccv1');
  const res = genPasswords(mask);
  verifyLengths(mask, res);
  verifyEntropy(res);
});

should.runWhen(import.meta.url);

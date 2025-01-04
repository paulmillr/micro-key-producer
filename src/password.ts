/*! micro-key-producer - MIT License (c) 2024 Paul Miller (paulmillr.com) */
import { bytesToNumberBE, numberToVarBytesBE } from '@noble/curves/abstract/utils';

export function zip<A, B>(a: A[], b: B[]): [A, B][] {
  let res: [A, B][] = [];
  for (let i = 0; i < Math.max(a.length, b.length); i++) res.push([a[i], b[i]]);
  return res;
}

// set utils
export function or<T>(...sets: Set<T>[]): Set<T> {
  return sets.reduce((acc, i) => new Set([...acc, ...i]), new Set());
}

export function and<T>(...sets: Set<T>[]): Set<T> {
  return sets.reduce((acc, i) => new Set(Array.from(acc).filter((j) => i.has(j))));
}

export function product(...sets: Set<string>[]): Set<string> {
  return sets.reduce(
    (acc, i) =>
      new Set(
        Array.from(acc)
          .map((j) => Array.from(i).map((k) => j + k))
          .flat()
      )
  );
}

export const DATE: Record<string, number> = { sec: 1000 };
DATE.min = 60 * DATE.sec;
DATE.h = 60 * DATE.min;
DATE.d = 24 * DATE.h;
DATE.mo = 30 * DATE.d;
DATE.y = 365 * DATE.mo;

export function formatDuration(dur: number): string {
  if (Number.isNaN(dur)) return 'never';
  if (dur > DATE.y * 100) return 'centuries';
  let parts = [];
  for (let [name, period] of Object.entries(DATE).reverse()) {
    if (dur < period) continue;
    let value = Math.floor(dur / period);
    parts.push(`${value}${name}`);
    dur -= value * period;
  }
  return parts.length > 0 ? parts.join(' ') : '0 sec';
}

// NOTE: all items inside alphabet size should have same size
export const alphabet: Record<string, Set<string>> = {};
// Digits
alphabet['1'] = new Set('0123456789');
// Symbols
alphabet['@'] = new Set('!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~');
// Vowels
alphabet['v'] = new Set('aeiouy');
// Consonant
alphabet['c'] = new Set('bcdfghjklmnpqrstvwxz');
// V+C
alphabet['a'] = or(alphabet['v'], alphabet['c']);
// Uppercase variants
for (const v of 'vca')
  alphabet[v.toUpperCase()] = new Set(Array.from(alphabet[v]).map((i: string) => i.toUpperCase()));
// uppercase+lowercase (letter?)
alphabet['l'] = or(alphabet['a'], alphabet['A']);
// uppercase+lowercase+digits (alpha(N)umeric?)
alphabet['n'] = or(alphabet['l'], alphabet['1']);
// uppercase+lowercase+digits+symbols
alphabet['*'] = or(alphabet['n'], alphabet['@']);

const TEMPLATES: Record<string, string> = {
  // Syllable (Consonant+vowel)
  s: 'cv',
  // uppercase consonant + vowel
  S: 'Cv',
};

// Mask utils
function idx<T>(arr: Array<T> | Set<T>, i: number): T {
  if (!Array.isArray(arr)) arr = Array.from(arr);
  if (i < 0 || i >= arr.length) throw new Error('Out of bounds index access');
  return arr[i];
}

/**
 * Check if password is correct for rules in design rationale.
 */
export function checkPassword(pwd: string): boolean {
  if (pwd.length < 8) return false;
  const s = new Set(pwd);
  for (const c of 'aA1@') if (!and(s, alphabet[c]).size) return false;
  return true;
}

/**
 * Like base convertInt, but with variable size alphabet.
 */
function splitEntropy(lengths: number[], entropy: Uint8Array) {
  let entropyLeft = bytesToNumberBE(entropy);
  let values = [];
  for (const c of lengths) {
    const sz = BigInt(c);
    values.push(Number(entropyLeft % sz));
    entropyLeft /= sz;
  }
  return { values, entropyLeft };
}

export function cardinalityBits(cardinality: bigint): number {
  let i = 0;
  for (let c = cardinality; c; i++, c >>= 1n);
  return i - 1;
}

// Estimates
function guessTime(cardinality: bigint, perSec: number): string {
  return formatDuration((Number(cardinality) / perSec) * 1000);
}

function passwordScore(cardinality: bigint) {
  const scores: [number, string][] = [
    [1e3 + 5, 'too guessable'],
    [1e6 + 5, 'very guessable'],
    [1e8 + 5, 'somewhat guessable'],
    [1e10 + 5, 'safely unguessable'],
  ];
  let res = 'very unguessable';
  for (const [i, v] of scores) {
    if (cardinality <= BigInt(i)) {
      res = v;
      break;
    }
  }
  return res;
}

export type PassEstimate = {
  // Score/guesses based on zxcvbn, it is pretty bad model, but will be ok for now
  score: string;
  guesses: {
    online_throttling: string;
    online: string;
    slow: string;
    fast: string;
  };
  // Password is assumed salted.
  // Non-salted passwords allow multi-target attacks which significantly reduces costs.
  // Values taken from hashcat 6.1.1 on RTX 3080
  // https://gist.github.com/Chick3nman/bb22b28ec4ddec0cb5f59df97c994db4
  costs: {
    luks: number;
    filevault2: number;
    macos: number;
    pbkdf2: number;
  };
};

/**
 * Estimate attack price for a password.
 * @returns `{ luks, filevault2, macos, pbkdf2 }`
 */
function estimateAttack(cardinality: bigint) {
  // Time estimates are not correct: we don't know how much hardware an attacker
  // has, it is better to estimate price of an attack. We do napkin math of TCO
  // (total cost of ownership) of a rig and calculate attack price based on it.

  // Full price of single GPU with included price CPU/MB/PSU
  // (but each card of rig takes only part of these costs)
  // Based on: https://bitcoinmerch.com/products/ready-to-mine™-6-x-nvidia-rtx-3080-non-lhr-complete-mining-rig-assembled
  const GPU_PRICE = 20500 / 6;
  // Cost of 1s of GPU time, assuming card will be used at least for 2 years
  const GPU_COST = GPU_PRICE / (2 * (DATE.y / 1000));
  // NOTE: you can probably sell rig at 30-50% of price after 2 years

  // https://lambdalabs.com/blog/deep-learning-hardware-deep-dive-rtx-30xx/
  const GPU_POWER = 320; // RTX 3080 – 320W (28% more than RTX 2080 Ti)
  const GPU_POWER_RIG = (80 + 280 + 6 * GPU_POWER) / 6; // Assuming 6x cards per rig +CPU+MB
  // 0.12$ per kWh https://www.techarp.com/computer/cybercafe-rtx-3080-cryptomining/
  const KWH_PRICE = 0.12;
  // +33% for cooling needs (AC)
  const KWH_COOLING = KWH_PRICE + KWH_PRICE * 0.33;
  // Price of kw per hour -> price of watt per sec
  const WS = KWH_COOLING / 60 / 1000;
  const ENERGY_COST = GPU_POWER_RIG * WS;
  const TOTAL_GPU_COST = ENERGY_COST + GPU_COST;
  const calcCost = (hashes: number) => Number(cardinality / BigInt(hashes)) * TOTAL_GPU_COST;
  return {
    // Score/guesses based on zxcvbn, it is pretty bad model, but will be ok for now
    score: passwordScore(cardinality),
    guesses: {
      online_throttling: guessTime(cardinality, 100 / (DATE.h / 1000)), // 100 per hour
      online: guessTime(cardinality, 10), // 10 per sec
      slow: guessTime(cardinality, 10000),
      fast: guessTime(cardinality, 10000000000),
    },
    // Password is assumed salted.
    // Non-salted passwords allow multi-target attacks which significantly reduces costs.
    // Values taken from hashcat 6.1.1 on RTX 3080
    // https://gist.github.com/Chick3nman/bb22b28ec4ddec0cb5f59df97c994db4
    costs: {
      luks: calcCost(22779), // linux FDE
      filevault2: calcCost(151300), // macOS FDE
      macos: calcCost(1019200), // macOS v10.8+ (PBKDF2-SHA512), password?
      pbkdf2: calcCost(3029200), // PBKDF2-HMAC-SHA256
    },
  };
}

type ApplyResult = { password: string; entropyLeft: bigint };

class Mask {
  private chars: string[];
  private sets: Set<string>[];
  private lengths: number[]; // sizes of sets
  readonly cardinality: bigint;
  readonly entropy: number;
  readonly length: number;
  constructor(mask: string) {
    mask = mask
      .split('')
      .map((i) => TEMPLATES[i] || i)
      .join('');
    this.chars = mask.split('');
    this.length = this.chars.length;
    this.sets = this.chars.map((i) => alphabet[i] || new Set([i]));
    this.lengths = this.sets.map((i) => i.size);
    this.cardinality = this.sets.reduce((acc, i) => acc * BigInt(i.size), 1n);
    this.entropy = cardinalityBits(this.cardinality);
  }
  apply(entropy: Uint8Array): ApplyResult {
    // There should be at least x2 more bits in entropy than required for mask to avoid modulo bias, since
    // it basically (% this.cardinality)
    if (this.cardinality >= 2n ** BigInt((8 * entropy.length) / 2))
      throw new Error('Not enough entropy');
    const { entropyLeft, values } = splitEntropy(this.lengths, entropy);
    const password = zip(this.sets, values)
      .map(([s, v]) => idx(s, v))
      .join('');
    return { password, entropyLeft };
  }
  inverse({ password, entropyLeft }: ApplyResult): Uint8Array {
    const values = zip(this.sets, password.split('')).map(([s, c]) => Array.from(s).indexOf(c));
    const num = zip(this.sets, values).reduceRight(
      (acc, [s, v]) => acc * BigInt(s.size) + BigInt(v),
      0n
    );
    return numberToVarBytesBE(entropyLeft * this.cardinality + num);
  }
  estimate(): PassEstimate {
    return estimateAttack(this.cardinality);
  }
}

export const mask = (mask: string): Mask => new Mask(mask);

/*
'Safari Keychain Secure Password'-like password:
- good because of user-base, no fignerprinting, also passes all requirements and still readable
- mask: 'cvccvc-cvccvc-cvccvc' (20 chars, 18 non-constant chars)
- digit inserted in first or last position of group: '1cvccv' or 'cvcvc1'
- only one non-numeric char is upper-cased
- uses dashes to bypass special symbol requirement, but still copyable (some other symbols will break select on click)
- hard to verify entropy in tests :(
*/
const secureMasks: string[] = [];
for (let upper = 0; upper < 17; upper++) {
  for (let digitPos = 0; digitPos < 3; digitPos++) {
    for (let digitLeft = 0; digitLeft < 2; digitLeft++) {
      const groups = ['cvccvc', 'cvccvc', 'cvccvc'];
      groups[digitPos] = digitLeft ? '1cvcvc' : 'cvccv1';
      const mask = groups.join('-');
      let res;
      for (let i = 0, sI = 0; i < mask.length; i++) {
        const chr = mask[i];
        if (!['c', 'v'].includes(chr)) continue;
        if (sI === upper) res = mask.slice(0, i) + chr.toUpperCase() + mask.slice(i + 1);
        sI++;
      }
      if (!res) throw new Error('Cannot find uppercase syllable index');
      secureMasks.push(res);
    }
  }
}

export type MaskType = { [K in keyof Mask]: Mask[K] };

export const secureMask: MaskType = (() => {
  const size = BigInt(secureMasks.length);
  const cardinality = mask(secureMasks[0]).cardinality * size;
  return {
    length: 20,
    cardinality,
    entropy: cardinalityBits(cardinality),
    estimate: () => estimateAttack(cardinality),
    apply: (entropy: Uint8Array): ApplyResult => {
      let entropyLeft = bytesToNumberBE(entropy);
      const idx = Number(entropyLeft % size);
      return mask(secureMasks[idx]).apply(numberToVarBytesBE(entropyLeft / size));
    },
    inverse(res: ApplyResult) {
      const chars = res.password.split('');
      const maskStr = chars
        .map((i) => {
          const possibleValues = Object.entries(alphabet)
            .filter(([c, _]) => ['c', 'v', 'C', 'V', '1'].includes(c))
            .map(([c, v]): [string, Set<string>] => [c, and(v, new Set([i]))])
            .filter(([_, v]) => v.size > 0);
          if (possibleValues.length > 1)
            throw new Error('Too much possible values, cannot detect mask.');
          return possibleValues.length ? possibleValues[0][0] : i;
        })
        .join('');
      const idx = secureMasks.indexOf(maskStr);
      if (idx < 0) throw new Error('Unknown mask');
      const entropy = mask(secureMasks[idx]).inverse(res);
      const entropyNum = bytesToNumberBE(entropy);
      return numberToVarBytesBE(entropyNum * size + BigInt(idx));
    },
  };
})();

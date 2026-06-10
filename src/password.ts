/*! micro-key-producer - MIT License (c) 2024 Paul Miller (paulmillr.com) */
/**
 * Allows to create secure passwords, using masks.
 * Supports iOS / macOS Safari Secure Password from Keychain.
 * Optional zxcvbn score for password bruteforce estimation.
 * @module
 */
import {
  abytes,
  bytesToNumberBE,
  numberToBytesBE,
  numberToVarBytesBE,
} from '@noble/curves/utils.js';
import { type TArg, type TRet } from '@scure/base';
import { astring, deepFreeze } from './utils.ts';

const _0n = /* @__PURE__ */ BigInt(0);
const _1n = /* @__PURE__ */ BigInt(1);
const _2n = /* @__PURE__ */ BigInt(2);

function zip<A, B>(a: A[], b: B[]): [A, B][] {
  // Zip to the longer input so callers preserve missing positions as
  // `undefined` instead of silently truncating uneven mask/value pairs.
  let res: [A, B][] = [];
  for (let i = 0; i < Math.max(a.length, b.length); i++) res.push([a[i], b[i]]);
  return res;
}

// set utils
function or<T>(...sets: Set<T>[]): Set<T> {
  // Build unions without mutating the source sets so the base alphabet classes
  // can be safely reused in larger composites.
  return sets.reduce((acc, i) => new Set([...acc, ...i]), new Set());
}

function and<T>(...sets: Set<T>[]): Set<T> {
  // Single-input intersections intentionally alias that input Set to avoid
  // allocation; callers that need an isolated result must copy first.
  return sets.reduce((acc, i) => new Set(Array.from(acc).filter((j) => i.has(j))));
}

function product(...sets: Set<string>[]): Set<string> {
  // Without an explicit seed, a single-input product returns that original Set
  // instance; callers that need an isolated result must copy first.
  return sets.reduce(
    (acc, i) =>
      new Set(
        Array.from(acc)
          .map((j) => Array.from(i).map((k) => j + k))
          .flat()
      )
  );
}

const DATE: Record<string, number> = { sec: 1000 };
// Duration formatting and attack estimates assume these helpers compose
// hierarchically from milliseconds up to about a 365-day year.
DATE.min = 60 * DATE.sec;
DATE.h = 60 * DATE.min;
DATE.d = 24 * DATE.h;
DATE.mo = 30 * DATE.d;
DATE.y = 365 * DATE.d;

function formatDuration(dur: number): string {
  if (Number.isNaN(dur)) return 'never';
  if (dur > DATE.y * 100) return 'centuries';
  let parts = [];
  // DATE is populated from the smallest unit upward above; reversing that
  // insertion order keeps rendered durations in largest-to-smallest chunks.
  for (let [name, period] of Object.entries(DATE).reverse()) {
    if (dur < period) continue;
    let value = Math.floor(dur / period);
    parts.push(`${value}${name}`);
    dur -= value * period;
  }
  return parts.length > 0 ? parts.join(' ') : '0 sec';
}

/** Character classes used by password masks. */
// NOTE: all items inside alphabet size should have same size
// Alphabet entries are shared live Sets: keeping them stable matters because Mask
// caches lengths/cardinality separately from later set iteration order.
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
deepFreeze(alphabet);

const TEMPLATES: Record<string, string> = {
  // Expand these shorthands once during mask compilation so the later mask logic
  // only sees concrete alphabet symbols.
  // Syllable (Consonant+vowel)
  s: 'cv',
  // uppercase consonant + vowel
  S: 'Cv',
};

// Mask utils
function idx<T>(arr: Array<T> | Set<T>, i: number): T {
  // Set inputs are copied to an array first so selection follows insertion
  // order without mutating the source collection.
  if (!Array.isArray(arr)) arr = Array.from(arr);
  if (i < 0 || i >= arr.length) throw new Error('Out of bounds index access');
  return arr[i];
}

/** Low-level password mask helpers. */
// Export the same live helpers used internally so callers and tests exercise
// the exact mask behavior, including the shared DATE table.
export const utils = {
  zip: zip as typeof zip,
  or: or as typeof or,
  and: and as typeof and,
  product: product as typeof product,
  cardinalityBits: cardinalityBits as typeof cardinalityBits,
  formatDuration: formatDuration as typeof formatDuration,
  DATE: DATE as typeof DATE,
};
deepFreeze(utils);

/**
 * Check if password is correct for rules in design rationale.
 * @param pwd - Candidate password string.
 * @returns Whether the password satisfies the built-in strength rules.
 * @example
 * Validate that a candidate password covers the required character classes.
 * ```ts
 * import { checkPassword } from 'micro-key-producer/password.js';
 * checkPassword('Aa1!aaaa');
 * ```
 */
export function checkPassword(pwd: string): boolean {
  pwd = astring(pwd, 'pwd');
  // The README minimum is 8 password characters; string iteration counts code
  // points instead of UTF-16 surrogate halves.
  if (Array.from(pwd).length < 8) return false;
  const s = new Set(pwd);
  for (const c of 'aA1@') if (!and(s, alphabet[c]).size) return false;
  return true;
}

function cardinalityBits(cardinality: bigint): number {
  // Only positive search-space sizes have a meaningful highest-used-bit width here.
  if (cardinality <= _0n) throw new RangeError(`expected positive cardinality, got ${cardinality}`);
  let i = 0;
  for (let c = cardinality; c; i++, c >>= _1n);
  return i - 1;
}

// Estimates
function guessTime(cardinality: bigint, perSec: number): string {
  // Human-readable time buckets are approximate; very large bigint cardinalities
  // eventually saturate to `centuries`.
  return formatDuration((Number(cardinality) / perSec) * 1000);
}

function passwordScore(cardinality: bigint) {
  // This is a small local guess-count bucket table, not a full zxcvbn scoring port.
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

/** Estimated password guessing effort. */
export type PassEstimate = {
  /** Human-readable strength label derived from the estimated search space. */
  // Score/guesses based on zxcvbn, it is pretty bad model, but will be ok for now
  score: string;
  /** Time-to-guess estimates for a few attacker models. */
  guesses: {
    /** Online attack with strict throttling such as account lockouts. */
    online_throttling: string;
    /** Online attack without meaningful throttling. */
    online: string;
    /** Slow offline attack. */
    slow: string;
    /** Fast offline attack. */
    fast: string;
  };
  /** Approximate hardware cost of exhaustive attacks against several KDF targets. */
  // Password is assumed salted.
  // Non-salted passwords allow multi-target attacks which significantly reduces costs.
  // Values taken from hashcat 6.1.1 on RTX 3080
  // https://gist.github.com/Chick3nman/bb22b28ec4ddec0cb5f59df97c994db4
  costs: {
    /** Estimated attack cost against LUKS-style targets. */
    luks: number;
    /** Estimated attack cost against FileVault 2. */
    filevault2: number;
    /** Estimated attack cost against macOS PBKDF2-SHA512. */
    macos: number;
    /** Estimated attack cost against PBKDF2-HMAC-SHA256. */
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
  // Convert price per kWh to price per watt-second: 1 kWh = 1000 W * 3600 s.
  const WS = KWH_COOLING / 3600 / 1000;
  const ENERGY_COST = GPU_POWER_RIG * WS;
  const TOTAL_GPU_COST = ENERGY_COST + GPU_COST;
  // Exhaustive cost should stay positive for any non-empty search space; rounding
  // away sub-second work loses that.
  const calcCost = (hashes: number) => (Number(cardinality) / hashes) * TOTAL_GPU_COST;
  return deepFreeze({
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
  });
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
    // No local RFC/EIP defines password masks; the local policy is that a mask
    // must select at least one password character instead of treating all input
    // entropy as leftover.
    if (!mask.length) throw new Error('expected non-empty mask');
    this.chars = mask.split('');
    this.length = this.chars.length;
    // No local RFC/EIP defines password masks; the local API invariant is that
    // compiled masks snapshot alphabets because lengths/cardinality are cached here.
    this.sets = this.chars.map((i) => new Set(alphabet[i] || [i]));
    this.lengths = this.sets.map((i) => i.size);
    this.cardinality = this.sets.reduce((acc, i) => acc * BigInt(i.size), _1n);
    this.entropy = cardinalityBits(this.cardinality);
  }
  apply(entropy: TArg<Uint8Array>): ApplyResult {
    // There should be at least x2 more bits in entropy than required for mask to avoid modulo bias, since
    // it basically (% this.cardinality)
    if (this.cardinality >= _2n ** BigInt((8 * entropy.length) / 2))
      throw new Error('Not enough entropy');
    // Generic masks treat entropy as a canonical big-endian integer; leading zero
    // bytes are not part of that value.
    let entropyLeft = bytesToNumberBE(entropy);
    const values: number[] = [];
    for (const c of this.lengths) {
      const sz = BigInt(c);
      values.push(Number(entropyLeft % sz));
      entropyLeft /= sz;
    }
    const password = zip(this.sets, values)
      .map(([s, v]) => idx(s, v))
      .join('');
    return { password, entropyLeft };
  }
  inverse({ password, entropyLeft }: ApplyResult): Uint8Array {
    const values = zip(this.sets, password.split('')).map(([s, c]) => Array.from(s).indexOf(c));
    const num = zip(this.sets, values).reduceRight(
      (acc, [s, v]) => acc * BigInt(s.size) + BigInt(v),
      _0n
    );
    // Return the minimal big-endian encoding for the reconstructed entropy
    // integer, not the caller's original byte width.
    return numberToVarBytesBE(entropyLeft * this.cardinality + num);
  }
  estimate(): PassEstimate {
    return estimateAttack(this.cardinality);
  }
}

/**
 * Compiles a password mask into an object that can apply or invert entropy.
 * @param mask - Password mask expression.
 * @returns Compiled password mask.
 * @example
 * Compile a password mask into an object that can apply or invert entropy.
 * ```ts
 * import { mask } from 'micro-key-producer/password.js';
 * mask('cv1').apply(new Uint8Array(8)).password;
 * ```
 */
export const mask = (mask: string): TRet<Mask> => new Mask(mask) as unknown as TRet<Mask>;

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
// One digit replaces one of the original 18 syllable characters, so only 17 c/v
// slots remain for uppercase placement.
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

/** Public shape of a compiled password mask. */
export type MaskType = { [K in keyof Mask]: Mask[K] };

/**
 * Secure password mask, iOS keychain format.
 * @example
 * Generate an iOS-style password from random bytes.
 * ```ts
 * import { secureMask } from 'micro-key-producer/password.js';
 * import { randomBytes } from '@noble/hashes/utils.js';
 * const seed = randomBytes(32);
 * const pass = secureMask.apply(seed).password;
 * ```
 */
export const secureMask: TRet<MaskType> = /* @__PURE__ */ (() => {
  const size = BigInt(secureMasks.length);
  const cardinality = mask(secureMasks[0]).cardinality * size;
  const seedLen = 32;
  return deepFreeze({
    length: 20,
    cardinality,
    entropy: cardinalityBits(cardinality),
    estimate: () => estimateAttack(cardinality),
    apply: (entropy: TArg<Uint8Array>): ApplyResult => {
      // No local RFC/EIP defines secureMask; the README API uses a fixed
      // randomBytes(32) seed, so preserve that width instead of dropping leading zero bytes.
      entropy = abytes(entropy, seedLen, 'entropy');
      let entropyLeft = bytesToNumberBE(entropy);
      // Split the entropy integer into {variant index mod 102, quotient} so every
      // concrete secure mask keeps the same inner cardinality.
      const idx = Number(entropyLeft % size);
      return mask(secureMasks[idx]).apply(numberToBytesBE(entropyLeft / size, seedLen));
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
      return numberToBytesBE(entropyNum * size + BigInt(idx), seedLen);
    },
  }) as unknown as TRet<MaskType>;
})();

/**
 * ======================================================================
 * EXPLAINSEC PHASE 2 — SEEDED RANDOM GENERATOR (PRNG)
 * ======================================================================
 * Mulberry32 PRNG implementation for deterministic event streams,
 * Playwright E2E automated testing, and repeatable classroom demos.
 * ======================================================================
 */

function stringToSeed(str) {
  let hash = 0;
  const s = String(str);
  for (let i = 0; i < s.length; i++) {
    hash = Math.imul(31, hash) + s.charCodeAt(i) | 0;
  }
  return hash;
}

export class SeededRandom {
  constructor(seed = null) {
    this.seedValue = seed;
    this.state = seed !== null ? (typeof seed === "number" ? seed : stringToSeed(seed)) : Math.floor(Math.random() * 0x7fffffff);
  }

  /**
   * Resets PRNG to a specified seed or original seed value.
   */
  reset(newSeed = null) {
    if (newSeed !== null) {
      this.seedValue = newSeed;
    }
    this.state = this.seedValue !== null 
      ? (typeof this.seedValue === "number" ? this.seedValue : stringToSeed(this.seedValue))
      : Math.floor(Math.random() * 0x7fffffff);
  }

  /**
   * Generates a float between 0 (inclusive) and 1 (exclusive).
   */
  nextFloat() {
    if (this.seedValue === null) {
      return Math.random();
    }
    let t = (this.state += 0x6d2b79f5);
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }

  /**
   * Generates an integer in range [min, max] inclusive.
   */
  nextInt(min, max) {
    return Math.floor(this.nextFloat() * (max - min + 1)) + min;
  }

  /**
   * Pick a random item from an array.
   */
  choice(array) {
    if (!array || array.length === 0) return null;
    const index = Math.floor(this.nextFloat() * array.length);
    return array[index];
  }

  /**
   * Shuffles an array in place deterministically.
   */
  shuffle(array) {
    const copy = [...array];
    for (let i = copy.length - 1; i > 0; i--) {
      const j = Math.floor(this.nextFloat() * (i + 1));
      [copy[i], copy[j]] = [copy[j], copy[i]];
    }
    return copy;
  }
}

export const globalPRNG = new SeededRandom();

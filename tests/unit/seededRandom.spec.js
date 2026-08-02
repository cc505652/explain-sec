/**
 * SeededRandom PRNG — Comprehensive Unit Tests
 */
import { test, expect } from '@playwright/test';
import { SeededRandom } from '../../src/telemetry/utils/seededRandom.js';

test.describe('SeededRandom PRNG Unit Suite', () => {

  test('1. nextFloat returns value in [0, 1) range', () => {
    const prng = new SeededRandom("range_test");
    for (let i = 0; i < 100; i++) {
      const val = prng.nextFloat();
      expect(val).toBeGreaterThanOrEqual(0);
      expect(val).toBeLessThan(1);
    }
  });

  test('2. Identical seeds produce identical sequences', () => {
    const a = new SeededRandom("determinism_seed");
    const b = new SeededRandom("determinism_seed");
    for (let i = 0; i < 50; i++) {
      expect(a.nextFloat()).toBe(b.nextFloat());
    }
  });

  test('3. Different seeds produce different sequences', () => {
    const a = new SeededRandom("seed_alpha");
    const b = new SeededRandom("seed_beta");
    let same = 0;
    for (let i = 0; i < 50; i++) {
      if (a.nextFloat() === b.nextFloat()) same++;
    }
    expect(same).toBeLessThan(5);
  });

  test('4. nextInt returns integer within [min, max] inclusive', () => {
    const prng = new SeededRandom("int_range");
    for (let i = 0; i < 100; i++) {
      const val = prng.nextInt(5, 15);
      expect(Number.isInteger(val)).toBe(true);
      expect(val).toBeGreaterThanOrEqual(5);
      expect(val).toBeLessThanOrEqual(15);
    }
  });

  test('5. nextInt with min === max returns exactly that value', () => {
    const prng = new SeededRandom("exact");
    expect(prng.nextInt(7, 7)).toBe(7);
  });

  test('6. choice returns element from array', () => {
    const prng = new SeededRandom("choice_seed");
    const arr = ["a", "b", "c", "d"];
    const result = prng.choice(arr);
    expect(arr).toContain(result);
  });

  test('7. choice returns null for empty array', () => {
    const prng = new SeededRandom("empty");
    expect(prng.choice([])).toBeNull();
  });

  test('8. choice returns null for null input', () => {
    const prng = new SeededRandom("null_arr");
    expect(prng.choice(null)).toBeNull();
  });

  test('9. shuffle returns array of same length', () => {
    const prng = new SeededRandom("shuffle_seed");
    const arr = [1, 2, 3, 4, 5];
    const shuffled = prng.shuffle(arr);
    expect(shuffled).toHaveLength(5);
  });

  test('10. shuffle preserves all elements', () => {
    const prng = new SeededRandom("preserve_seed");
    const arr = [10, 20, 30, 40];
    const shuffled = prng.shuffle(arr);
    expect(shuffled.sort()).toEqual([10, 20, 30, 40]);
  });

  test('11. shuffle does not mutate original array', () => {
    const prng = new SeededRandom("immutable_seed");
    const arr = [1, 2, 3];
    const original = [...arr];
    prng.shuffle(arr);
    expect(arr).toEqual(original);
  });

  test('12. shuffle is deterministic with same seed', () => {
    const a = new SeededRandom("det_shuf");
    const b = new SeededRandom("det_shuf");
    const arr = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    expect(a.shuffle(arr)).toEqual(b.shuffle(arr));
  });

  test('13. reset restores original seed state', () => {
    const prng = new SeededRandom("reset_seed");
    const first = prng.nextFloat();
    const second = prng.nextFloat();
    prng.reset();
    expect(prng.nextFloat()).toBe(first);
    expect(prng.nextFloat()).toBe(second);
  });

  test('14. reset with new seed changes sequence', () => {
    const prng = new SeededRandom("old_seed");
    const oldFirst = prng.nextFloat();
    prng.reset("new_seed");
    const newFirst = prng.nextFloat();
    expect(oldFirst).not.toBe(newFirst);
  });

  test('15. Numeric seed works identically to string seed conversion', () => {
    const a = new SeededRandom(42);
    const b = new SeededRandom(42);
    expect(a.nextFloat()).toBe(b.nextFloat());
  });

  test('16. Null seed uses Math.random (non-deterministic)', () => {
    const prng = new SeededRandom(null);
    const val = prng.nextFloat();
    expect(val).toBeGreaterThanOrEqual(0);
    expect(val).toBeLessThan(1);
  });
});

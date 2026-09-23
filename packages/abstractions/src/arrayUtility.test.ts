import { describe, expect, it } from 'vitest';
import { isNullOrEmpty, zeroMemory } from './arrayUtility.js';

describe('isNullOrEmpty', () => {
  it('is true for an empty buffer', () => {
    expect(isNullOrEmpty(Buffer.alloc(0))).toBe(true);
  });

  it('is true for an all-zero buffer', () => {
    expect(isNullOrEmpty(Buffer.alloc(8))).toBe(true);
  });

  it('is false when any byte is non-zero', () => {
    expect(isNullOrEmpty(Buffer.from([0, 0, 1, 0]))).toBe(false);
  });
});

describe('zeroMemory', () => {
  it('overwrites every byte with zero, in place', () => {
    const data = Buffer.from([1, 2, 3, 4]);

    zeroMemory(data);

    expect(data).toEqual(Buffer.alloc(4));
  });
});

import { describe, expect, it } from 'vitest';
import { getBinaryLength, isBase64 } from './base64ConversionUtility.js';

describe('isBase64', () => {
  it('accepts an empty string', () => {
    expect(isBase64('')).toBe(true);
  });

  it.each(['aGVsbG8=', 'aGVsbG8h', 'YQ==', '////'])('accepts %s', (value) => {
    expect(isBase64(value)).toBe(true);
  });

  it.each(['not base64!', 'aGVsbG8', 'a===', 'ab=c'])('rejects %s', (value) => {
    expect(isBase64(value)).toBe(false);
  });
});

describe('getBinaryLength', () => {
  it('returns 0 for an empty string', () => {
    expect(getBinaryLength('')).toBe(0);
  });

  it('accounts for padding', () => {
    expect(getBinaryLength('aGVsbG8=')).toBe(5);
    expect(getBinaryLength('YQ==')).toBe(1);
    expect(getBinaryLength('////')).toBe(3);
  });

  it('throws when the length is not a multiple of 4', () => {
    expect(() => getBinaryLength('abc')).toThrow('Base64 input length must be a multiple of 4.');
  });
});

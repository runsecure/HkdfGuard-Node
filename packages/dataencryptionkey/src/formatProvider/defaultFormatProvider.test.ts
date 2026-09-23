import { describe, expect, it } from 'vitest';
import { DefaultFormatProvider } from './defaultFormatProvider.js';

describe('DefaultFormatProvider', () => {
  const provider = new DefaultFormatProvider();

  describe('format/parse', () => {
    it('round trips', () => {
      const value = { keyVersion: 3, value: Buffer.from('hello') };

      const formatted = provider.format(value);
      expect(formatted).toBe(`enc::v3::${Buffer.from('hello').toString('base64')}`);

      const parsed = provider.parse(formatted);
      expect(parsed.keyVersion).toBe(3);
      expect(parsed.value).toEqual(Buffer.from('hello'));
    });

    it('round trips an empty value', () => {
      const value = { keyVersion: 1, value: Buffer.alloc(0) };

      const parsed = provider.parse(provider.format(value));
      expect(parsed.value).toEqual(Buffer.alloc(0));
    });
  });

  describe('parse', () => {
    it.each(['not-formatted', 'enc::v1', 'enc::1::aGVsbG8=', 'notenc::v1::aGVsbG8='])(
      'throws on malformed input %s',
      (input) => {
        expect(() => provider.parse(input)).toThrow(/Invalid encrypted format/);
      },
    );

    it('throws on invalid base64', () => {
      expect(() => provider.parse('enc::v1::not valid base64!')).toThrow('Encrypted value is not valid base64.');
    });
  });

  describe('getMaxDecryptedLength', () => {
    it('matches the actual decoded length', () => {
      const formatted = provider.format({ keyVersion: 1, value: Buffer.from('a longer value here') });

      expect(provider.getMaxDecryptedLength(formatted)).toBe(provider.parse(formatted).value.length);
    });

    it('throws on malformed input', () => {
      expect(() => provider.getMaxDecryptedLength('garbage')).toThrow(/Invalid encrypted format/);
    });
  });
});

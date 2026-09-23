import { AesGcmCryptoProviderFactory } from '@runsecure/hkdfguard-cryptosession-aesgcm256';
import { describe, expect, it } from 'vitest';
import { PipelineKeyFactory } from './pipelineKeyFactory.js';

const cryptoProviderFactory = new AesGcmCryptoProviderFactory();

describe('PipelineKeyFactory', () => {
  it('generates a 32-byte dek', () => {
    const factory = new PipelineKeyFactory();

    const key = factory.create(cryptoProviderFactory);
    expect(key.asBuffer().length).toBe(32);
    expect(key.asBuffer().some((b) => b !== 0)).toBe(true);
    key.close();
  });

  it('generates a different dek each time', () => {
    const factory = new PipelineKeyFactory();

    const key1 = factory.create(cryptoProviderFactory);
    const key2 = factory.create(cryptoProviderFactory);

    expect(key1.asBuffer()).not.toEqual(key2.asBuffer());
    key1.close();
    key2.close();
  });

  it('produces a working key', () => {
    const factory = new PipelineKeyFactory();
    const key = factory.create(cryptoProviderFactory);
    const plaintext = Buffer.from('top secret');
    const expected = Buffer.from(plaintext);

    const encrypted = key.encrypt(plaintext);
    const decrypted = Buffer.alloc(expected.length);
    const written = key.decrypt(encrypted, decrypted);

    expect(written).toBe(expected.length);
    expect(decrypted).toEqual(expected);
    key.close();
  });

  it('the key can be closed without throwing', () => {
    const factory = new PipelineKeyFactory();
    const key = factory.create(cryptoProviderFactory);

    expect(() => key.close()).not.toThrow();
  });
});

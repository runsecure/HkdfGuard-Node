import { randomBytes } from 'node:crypto';
import { AesGcmCryptoProviderFactory } from '@runsecure/hkdfguard-cryptosession-aesgcm256';
import { describe, expect, it } from 'vitest';
import { PipelineDataEncryptionKey } from './pipelineDataEncryptionKey.js';
import { FakeKeyWrapper } from './testHelpers/fakeKeyWrapper.js';

const cryptoProviderFactory = new AesGcmCryptoProviderFactory();

function createKey(dek?: Buffer): PipelineDataEncryptionKey {
  const theDek = dek ?? randomBytes(32);
  const provider = cryptoProviderFactory.createForPipeline(new FakeKeyWrapper(randomBytes(32)), theDek);
  return new PipelineDataEncryptionKey(provider, theDek);
}

describe('PipelineDataEncryptionKey', () => {
  it('asBuffer returns the supplied dek', () => {
    const dek = randomBytes(32);
    const expected = Buffer.from(dek);

    const key = createKey(dek);
    expect(key.asBuffer()).toEqual(expected);
    key.close();
  });

  it('round trips encrypt/decrypt', () => {
    const key = createKey();
    const plaintext = Buffer.from('top secret');
    const expected = Buffer.from(plaintext);

    const encrypted = key.encrypt(plaintext);
    const decrypted = Buffer.alloc(expected.length);
    const written = key.decrypt(encrypted, decrypted);

    expect(written).toBe(expected.length);
    expect(decrypted).toEqual(expected);
    key.close();
  });

  it('round trips with aad', () => {
    const key = createKey();
    const plaintext = Buffer.from('top secret');
    const expected = Buffer.from(plaintext);
    const aad = Buffer.from('context');

    const encrypted = key.encrypt(plaintext, aad);
    const decrypted = Buffer.alloc(expected.length);
    const written = key.decrypt(encrypted, decrypted, aad);

    expect(decrypted.subarray(0, written)).toEqual(expected);
    key.close();
  });

  it('throws on mismatched aad', () => {
    const key = createKey();
    const encrypted = key.encrypt(Buffer.from('top secret'), Buffer.from('context-a'));

    expect(() => key.decrypt(encrypted, Buffer.alloc(16), Buffer.from('context-b'))).toThrow();
    key.close();
  });

  it('two instances with different deks cannot decrypt each others ciphertext', () => {
    const key1 = createKey();
    const key2 = createKey();
    const encrypted = key1.encrypt(Buffer.from('top secret'));

    expect(() => key2.decrypt(encrypted, Buffer.alloc(16))).toThrow();
    key1.close();
    key2.close();
  });

  it('close zeroes the dek', () => {
    const dek = randomBytes(32);
    const key = createKey(dek);

    key.close();

    expect(dek).toEqual(Buffer.alloc(32));
  });

  it('close does not throw', () => {
    // Regression guard: the pipeline-only AesGcmCryptoProvider construction path must leave a
    // usable (undefined) refresh timer, not one that crashes close().
    const key = createKey();

    expect(() => key.close()).not.toThrow();
  });
});

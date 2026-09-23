import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { AesGcmCryptoProviderFactory } from './factory.js';
import { FakeKeyWrapper } from './testHelpers/fakeKeyWrapper.js';

describe('AesGcmCryptoProviderFactory', () => {
  const factory = new AesGcmCryptoProviderFactory();

  describe('create', () => {
    it('produces a working provider', () => {
      const wrapper = new FakeKeyWrapper();
      const provider = factory.create(wrapper, Buffer.from('wrapped'), 60);

      const plaintext = Buffer.from('top secret');
      const encrypted = Buffer.alloc(provider.getEncryptedAllocationLength(plaintext.length));
      const written = provider.encrypt(plaintext, encrypted);

      const decrypted = Buffer.alloc(10);
      expect(provider.decrypt(encrypted.subarray(0, written), decrypted)).toBe(10);
      provider.close();
    });
  });

  describe('createEphemeral', () => {
    it('calls generateAndWrap exactly once', () => {
      const wrapper = new FakeKeyWrapper();
      const provider = factory.createEphemeral(wrapper, 60);

      expect(wrapper.generateAndWrapCallCount).toBe(1);
      provider.close();
    });

    it('produces a working provider', () => {
      const wrapper = new FakeKeyWrapper();
      const provider = factory.createEphemeral(wrapper, 60);
      const plaintext = Buffer.from('top secret');
      const expected = Buffer.from(plaintext);

      const encrypted = Buffer.alloc(provider.getEncryptedAllocationLength(plaintext.length));
      const written = provider.encrypt(plaintext, encrypted);
      const decrypted = Buffer.alloc(expected.length);
      const decryptedLength = provider.decrypt(encrypted.subarray(0, written), decrypted);

      expect(decryptedLength).toBe(expected.length);
      expect(decrypted).toEqual(expected);
      provider.close();
    });
  });

  describe('createForPipeline', () => {
    it('never calls the key wrapper', () => {
      // createForPipeline uses the supplied bytes directly as the AES key - there is nothing to
      // wrap/unwrap, so the wrapper it's handed should never be invoked.
      const wrapper = new FakeKeyWrapper();
      wrapper.throwOnDecrypt = new Error('should not be called');
      const dek = randomBytes(32);

      const provider = factory.createForPipeline(wrapper, dek);

      expect(wrapper.decryptCallCount).toBe(0);
      expect(wrapper.generateAndWrapCallCount).toBe(0);
      provider.close();
    });

    it('produces a working provider', () => {
      const wrapper = new FakeKeyWrapper();
      const dek = randomBytes(32);
      const provider = factory.createForPipeline(wrapper, dek);
      const plaintext = Buffer.from('top secret');
      const expected = Buffer.from(plaintext);

      const encrypted = Buffer.alloc(provider.getEncryptedAllocationLength(plaintext.length));
      const written = provider.encrypt(plaintext, encrypted);
      const decrypted = Buffer.alloc(expected.length);
      const decryptedLength = provider.decrypt(encrypted.subarray(0, written), decrypted);

      expect(decryptedLength).toBe(expected.length);
      expect(decrypted).toEqual(expected);
      provider.close();
    });

    it('does not throw on close', () => {
      // Regression guard: the pipeline-only AesGcmCryptoProvider constructor must leave a usable
      // (undefined) refreshTimer, not one that crashes close().
      const wrapper = new FakeKeyWrapper();
      const provider = factory.createForPipeline(wrapper, randomBytes(32));

      expect(() => provider.close()).not.toThrow();
    });
  });
});

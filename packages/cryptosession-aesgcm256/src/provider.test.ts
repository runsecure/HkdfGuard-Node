import { describe, expect, it } from 'vitest';
import { AesGcmCryptoProvider } from './provider.js';
import { FakeKeyWrapper } from './testHelpers/fakeKeyWrapper.js';

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

describe('AesGcmCryptoProvider', () => {
  describe('constructor', () => {
    it('builds the initial session eagerly', () => {
      const wrapper = new FakeKeyWrapper();

      new AesGcmCryptoProvider(wrapper, Buffer.from('wrapped'), 60);

      expect(wrapper.decryptCallCount).toBe(1);
    });

    it('throws when the key wrapper fails', () => {
      const wrapper = new FakeKeyWrapper();
      wrapper.throwOnDecrypt = new Error('reveal failed');

      expect(() => new AesGcmCryptoProvider(wrapper, Buffer.from('wrapped'), 60)).toThrow('reveal failed');
    });

    it.each([0, -1, 301])('throws when expirySeconds (%d) is out of range', (expirySeconds) => {
      const wrapper = new FakeKeyWrapper();

      expect(() => new AesGcmCryptoProvider(wrapper, Buffer.from('wrapped'), expirySeconds)).toThrow(
        'expirySeconds must be between 1 and 300',
      );
    });
  });

  describe('background refresh', () => {
    it('proactively refreshes the session on each timer tick, without any encrypt/decrypt call', async () => {
      const wrapper = new FakeKeyWrapper();
      const provider = new AesGcmCryptoProvider(wrapper, Buffer.from('wrapped'), 1);

      // No encrypt/decrypt call at all - only the constructor's eager build
      // (decryptCallCount === 1) and the background timer, ticking every expirySeconds, should
      // have run by now.
      await sleep(1500);

      expect(wrapper.decryptCallCount).toBe(2);
      provider.close();
    });
  });

  describe('encrypt/decrypt', () => {
    it('round trips through the cached session', () => {
      const wrapper = new FakeKeyWrapper();
      const provider = new AesGcmCryptoProvider(wrapper, Buffer.from('wrapped'), 60);
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

    it('reuses the cached session across calls without re-revealing the key', () => {
      const wrapper = new FakeKeyWrapper();
      const provider = new AesGcmCryptoProvider(wrapper, Buffer.from('wrapped'), 60);

      const encrypted1 = Buffer.alloc(64);
      const written1 = provider.encrypt(Buffer.from('one'), encrypted1);
      const encrypted2 = Buffer.alloc(64);
      const written2 = provider.encrypt(Buffer.from('two'), encrypted2);

      provider.decrypt(encrypted1.subarray(0, written1), Buffer.alloc(3));
      provider.decrypt(encrypted2.subarray(0, written2), Buffer.alloc(3));

      expect(wrapper.decryptCallCount).toBe(1);
      provider.close();
    });
  });

  describe('allocation lengths', () => {
    it('adds nonce and tag overhead to getEncryptedAllocationLength', () => {
      const wrapper = new FakeKeyWrapper();
      const provider = new AesGcmCryptoProvider(wrapper, Buffer.from('wrapped'), 60);

      expect(provider.getEncryptedAllocationLength(10)).toBe(10 + 12 + 16);
      provider.close();
    });

    it('removes nonce and tag overhead from getDecryptedAllocationLength', () => {
      const wrapper = new FakeKeyWrapper();
      const provider = new AesGcmCryptoProvider(wrapper, Buffer.from('wrapped'), 60);

      expect(provider.getDecryptedAllocationLength(10 + 12 + 16)).toBe(10);
      provider.close();
    });
  });

  describe('close', () => {
    it('closes the current session and stops the background timer', async () => {
      const wrapper = new FakeKeyWrapper();
      const provider = new AesGcmCryptoProvider(wrapper, Buffer.from('wrapped'), 1);

      provider.close();
      await sleep(1500);

      // Only the constructor's eager build - the timer must not have ticked after close.
      expect(wrapper.decryptCallCount).toBe(1);
    });

    it('causes further encrypt/decrypt calls to throw', () => {
      const wrapper = new FakeKeyWrapper();
      const provider = new AesGcmCryptoProvider(wrapper, Buffer.from('wrapped'), 60);

      provider.close();

      expect(() => provider.encrypt(Buffer.from('x'), Buffer.alloc(64))).toThrow(
        'Operation on a closed AesGcmCryptoProvider.',
      );
    });
  });
});

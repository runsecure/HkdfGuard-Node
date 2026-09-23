import { randomBytes } from 'node:crypto';
import { AesGcmCryptoProvider } from '@runsecure/hkdfguard-cryptosession-aesgcm256';
import { describe, expect, it } from 'vitest';
import { KeyWrappedDataEncryptionKey } from './keyWrappedDataEncryptionKey.js';
import { FakeKeyWrapper } from './testHelpers/fakeKeyWrapper.js';

function createKey(): { key: KeyWrappedDataEncryptionKey; wrapper: FakeKeyWrapper } {
  const wrapper = new FakeKeyWrapper(randomBytes(32));
  return { key: new KeyWrappedDataEncryptionKey(new AesGcmCryptoProvider(wrapper, Buffer.from('wrapped'), 60)), wrapper };
}

describe('KeyWrappedDataEncryptionKey', () => {
  it('round trips encrypt/decrypt', () => {
    const { key } = createKey();
    const plaintext = Buffer.from('top secret');
    const expected = Buffer.from(plaintext);

    const encrypted = key.encrypt(plaintext);
    expect(encrypted.length).toBe(expected.length + 12 + 16);

    const decrypted = Buffer.alloc(expected.length);
    const decryptedLength = key.decrypt(encrypted, decrypted);

    expect(decryptedLength).toBe(expected.length);
    expect(decrypted).toEqual(expected);
  });

  it('round trips with aad', () => {
    const { key } = createKey();
    const plaintext = Buffer.from('top secret');
    const expected = Buffer.from(plaintext);
    const aad = Buffer.from('context');

    const encrypted = key.encrypt(plaintext, aad);
    const decrypted = Buffer.alloc(expected.length);
    const decryptedLength = key.decrypt(encrypted, decrypted, aad);

    expect(decrypted.subarray(0, decryptedLength)).toEqual(expected);
  });

  it('throws on mismatched aad', () => {
    const { key } = createKey();
    const encrypted = key.encrypt(Buffer.from('top secret'), Buffer.from('context-a'));

    expect(() => key.decrypt(encrypted, Buffer.alloc(10), Buffer.from('context-b'))).toThrow();
  });

  it('returns an exactly-sized result', () => {
    const { key } = createKey();
    const plaintext = Buffer.from('a longer plaintext value to encrypt');

    const encrypted = key.encrypt(plaintext);

    expect(encrypted.length).toBe(plaintext.length + 12 + 16);
  });

  it('reuses the cached session across calls', () => {
    // AesGcmCryptoProvider only calls back into the key wrapper when it has no cached session
    // yet or the cached one has expired - not on every operation - so a wrapper's key is
    // revealed once here, then reused for every subsequent encrypt/decrypt.
    const { key, wrapper } = createKey();
    const encrypted1 = key.encrypt(Buffer.from('one'));
    const encrypted2 = key.encrypt(Buffer.from('two'));

    key.decrypt(encrypted1, Buffer.alloc(3));
    key.decrypt(encrypted2, Buffer.alloc(3));

    expect(wrapper.decryptCallCount).toBe(1);
  });
});

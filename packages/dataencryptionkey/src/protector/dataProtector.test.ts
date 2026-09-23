import { randomBytes } from 'node:crypto';
import { AesGcmCryptoProvider } from '@runsecure/hkdfguard-cryptosession-aesgcm256';
import { describe, expect, it } from 'vitest';
import { DefaultFormatProvider } from '../formatProvider/defaultFormatProvider.js';
import { KeyRing } from '../keyRing.js';
import { KeyWrappedDataEncryptionKey } from '../keyWrappedDataEncryptionKey.js';
import { FakeKeyWrapper } from '../testHelpers/fakeKeyWrapper.js';

function newRingWithKey(version = 1): KeyRing {
  const ring = new KeyRing(new DefaultFormatProvider());
  const wrapper = new FakeKeyWrapper(randomBytes(32));
  ring.add(version, new KeyWrappedDataEncryptionKey(new AesGcmCryptoProvider(wrapper, Buffer.from('wrapped'), 60)));
  return ring;
}

describe('DataProtector', () => {
  it('round trips a plaintext string', () => {
    const protector = newRingWithKey().createProtector('purpose');

    const encrypted = protector.encrypt('top secret');
    expect(encrypted.startsWith('enc::v1::')).toBe(true);
    expect(protector.decrypt(encrypted)).toBe('top secret');
  });

  it('binds name as aad - a value protected under one purpose fails under another', () => {
    const ring = newRingWithKey();
    const a = ring.createProtector('purpose-a');
    const b = ring.createProtector('purpose-b');

    const encrypted = a.encrypt('top secret');

    expect(() => b.decrypt(encrypted)).toThrow();
  });

  it('encrypts new data with the ring current version', () => {
    const ring = newRingWithKey(1);
    const protector = ring.createProtector('purpose');
    const wrapper = new FakeKeyWrapper(randomBytes(32));
    ring.add(2, new KeyWrappedDataEncryptionKey(new AesGcmCryptoProvider(wrapper, Buffer.from('wrapped-v2'), 60)));

    const encrypted = protector.encrypt('top secret');

    expect(encrypted.startsWith('enc::v2::')).toBe(true);
  });

  it('decrypts using whichever version the ciphertext names, even after rotation', () => {
    const ring = newRingWithKey(1);
    const protector = ring.createProtector('purpose');
    const encryptedV1 = protector.encrypt('top secret');

    const wrapper = new FakeKeyWrapper(randomBytes(32));
    ring.add(2, new KeyWrappedDataEncryptionKey(new AesGcmCryptoProvider(wrapper, Buffer.from('wrapped-v2'), 60)));

    expect(protector.decrypt(encryptedV1)).toBe('top secret');
  });

  it('getMaxDecryptedLength delegates to the format provider', () => {
    const protector = newRingWithKey().createProtector('purpose');
    const encrypted = protector.encrypt('hello world');

    expect(protector.getMaxDecryptedLength(encrypted)).toBeGreaterThanOrEqual('hello world'.length);
  });
});

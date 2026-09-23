import { randomBytes } from 'node:crypto';
import type { DataEncryptionKey, EncryptedFormatProvider } from '@runsecure/hkdfguard-abstractions';
import { AesGcmCryptoProvider } from '@runsecure/hkdfguard-cryptosession-aesgcm256';
import { describe, expect, it } from 'vitest';
import { DefaultFormatProvider } from './formatProvider/defaultFormatProvider.js';
import { KeyRing } from './keyRing.js';
import { KeyWrappedDataEncryptionKey } from './keyWrappedDataEncryptionKey.js';
import { FakeKeyWrapper } from './testHelpers/fakeKeyWrapper.js';

function createFakeKey(): DataEncryptionKey {
  const wrapper = new FakeKeyWrapper(randomBytes(32));
  return new KeyWrappedDataEncryptionKey(new AesGcmCryptoProvider(wrapper, Buffer.from('wrapped'), 60));
}

function newRing(formatProvider: EncryptedFormatProvider = new DefaultFormatProvider()): KeyRing {
  return new KeyRing(formatProvider);
}

describe('KeyRing', () => {
  describe('currentVersion', () => {
    it('throws when no key has been added', () => {
      expect(() => newRing().currentVersion).toThrow('No current version has been set. Add a key first.');
    });

    it('becomes the highest added version', () => {
      const ring = newRing();
      ring.add(1, createFakeKey());
      ring.add(3, createFakeKey());
      ring.add(2, createFakeKey());

      expect(ring.currentVersion).toBe(3);
    });
  });

  describe('add', () => {
    it('throws when a version is already registered', () => {
      const ring = newRing();
      ring.add(1, createFakeKey());

      expect(() => ring.add(1, createFakeKey())).toThrow('A key for version 1 is already registered.');
    });
  });

  describe('get', () => {
    it('retrieves a registered key', () => {
      const ring = newRing();
      const key = createFakeKey();
      ring.add(1, key);

      expect(ring.get(1)).toBe(key);
    });

    it('throws for an unregistered version', () => {
      expect(() => newRing().get(5)).toThrow('No key is registered for version 5.');
    });
  });

  describe('tryGet', () => {
    it('returns undefined for an unregistered version', () => {
      expect(newRing().tryGet(5)).toBeUndefined();
    });

    it('returns the key for a registered version', () => {
      const ring = newRing();
      const key = createFakeKey();
      ring.add(1, key);

      expect(ring.tryGet(1)).toBe(key);
    });
  });

  describe('getCurrent', () => {
    it('throws when no key has been added', () => {
      expect(() => newRing().getCurrent()).toThrow('No current version has been set. Add a key first.');
    });

    it('returns the current version and its key', () => {
      const ring = newRing();
      const key = createFakeKey();
      ring.add(1, key);

      expect(ring.getCurrent()).toEqual({ version: 1, key });
    });
  });

  describe('createProtector', () => {
    it('creates a protector that round trips through the ring', () => {
      const ring = newRing();
      ring.add(1, createFakeKey());
      const protector = ring.createProtector('purpose');

      const encrypted = protector.encrypt('top secret');
      expect(protector.decrypt(encrypted)).toBe('top secret');
    });
  });
});

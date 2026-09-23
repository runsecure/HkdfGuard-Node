import { describe, expect, it } from 'vitest';
import type { DataEncryptionKey } from './dataEncryptionKey.js';
import { ProtectedCacheBase } from './protectedCacheBase.js';

/** A trivial, non-cryptographic DataEncryptionKey (identity transform) - abstractions has no real
 * cipher of its own to test against, so this is enough to exercise ProtectedCacheBase's own
 * plumbing (keying, tryPopulate fallback, encrypt/decrypt delegation) in isolation. */
class IdentityDataEncryptionKey implements DataEncryptionKey {
  encrypt(plaintext: Buffer): Buffer {
    return Buffer.from(plaintext);
  }

  decrypt(ciphertext: Buffer, result: Buffer): number {
    ciphertext.copy(result);
    return ciphertext.length;
  }
}

class TestCache extends ProtectedCacheBase {
  constructor(key: DataEncryptionKey = new IdentityDataEncryptionKey()) {
    super(key);
  }

  add(name: string, plaintext: Buffer): void {
    if (!this.tryAddEncrypted(name, this.encrypt(plaintext))) {
      throw new Error(`An item with the name '${name}' has already been added.`);
    }
  }

  addStr(name: string, plaintext: string): void {
    if (!this.tryAddEncrypted(name, this.encryptStr(plaintext))) {
      throw new Error(`An item with the name '${name}' has already been added.`);
    }
  }
}

class PopulatingTestCache extends TestCache {
  populateCallCount = 0;

  protected override tryPopulate(name: string): boolean {
    this.populateCallCount++;
    if (name === 'populatable') {
      this.add('populatable', Buffer.from('populated value'));
      return true;
    }
    return false;
  }
}

describe('ProtectedCacheBase', () => {
  describe('decrypt/decryptStr', () => {
    it('returns 0/undefined for a missing name', () => {
      const cache = new TestCache();
      expect(cache.decrypt('missing', Buffer.alloc(10))).toBe(0);
      expect(cache.decryptStr('missing')).toBeUndefined();
    });

    it('round trips a stored value', () => {
      const cache = new TestCache();
      cache.add('secret', Buffer.from('hello'));

      const result = Buffer.alloc(5);
      expect(cache.decrypt('secret', result)).toBe(5);
      expect(result).toEqual(Buffer.from('hello'));
    });

    it('is case-insensitive', () => {
      const cache = new TestCache();
      cache.add('Secret', Buffer.from('hello'));

      expect(cache.decryptStr('SECRET')).toBe('hello');
    });

    it('falls back to tryPopulate on a miss', () => {
      const cache = new PopulatingTestCache();

      expect(cache.decryptStr('populatable')).toBe('populated value');
      expect(cache.populateCallCount).toBe(1);
    });

    it('does not call tryPopulate again once populated', () => {
      const cache = new PopulatingTestCache();
      cache.decryptStr('populatable');
      cache.decryptStr('populatable');

      expect(cache.populateCallCount).toBe(1);
    });
  });

  describe('tryGetMaxDecryptedLength', () => {
    it('returns undefined for a missing name', () => {
      expect(new TestCache().tryGetMaxDecryptedLength('missing')).toBeUndefined();
    });

    it('returns the encrypted length for a stored value', () => {
      const cache = new TestCache();
      cache.add('secret', Buffer.from('hello'));

      expect(cache.tryGetMaxDecryptedLength('secret')).toBe(5);
    });
  });

  describe('add', () => {
    it('rejects a duplicate name', () => {
      const cache = new TestCache();
      cache.add('secret', Buffer.from('one'));

      expect(() => cache.add('secret', Buffer.from('two'))).toThrow();
    });
  });
});

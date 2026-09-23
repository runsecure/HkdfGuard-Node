import type { Logger } from '@runsecure/hkdfguard-diagnostics';
import { describe, expect, it, vi } from 'vitest';
import { ProtectedCache } from './protectedCache.js';
import { createDataEncryptionKey } from './testHelpers/createDataEncryptionKey.js';

describe('ProtectedCache', () => {
  describe('add/decrypt', () => {
    it('round trips a byte buffer', () => {
      const cache = new ProtectedCache(createDataEncryptionKey());
      cache.add('secret', Buffer.from('top secret'));

      const result = Buffer.alloc(10);
      expect(cache.decrypt('secret', result)).toBe(10);
      expect(result).toEqual(Buffer.from('top secret'));
    });

    it('rejects a duplicate name', () => {
      const cache = new ProtectedCache(createDataEncryptionKey());
      cache.add('secret', Buffer.from('one'));

      expect(() => cache.add('secret', Buffer.from('two'))).toThrow(
        "An item with the name 'secret' has already been added.",
      );
    });

    it('returns 0 for a missing name', () => {
      const cache = new ProtectedCache(createDataEncryptionKey());
      expect(cache.decrypt('missing', Buffer.alloc(10))).toBe(0);
    });

    it('is case-insensitive', () => {
      const cache = new ProtectedCache(createDataEncryptionKey());
      cache.add('Secret', Buffer.from('top secret'));

      const result = Buffer.alloc(10);
      expect(cache.decrypt('SECRET', result)).toBe(10);
    });
  });

  describe('addStr/decryptStr', () => {
    it('round trips a string', () => {
      const cache = new ProtectedCache(createDataEncryptionKey());
      cache.addStr('secret', 'top secret');

      expect(cache.decryptStr('secret')).toBe('top secret');
    });

    it('rejects a duplicate name', () => {
      const cache = new ProtectedCache(createDataEncryptionKey());
      cache.addStr('secret', 'one');

      expect(() => cache.addStr('secret', 'two')).toThrow(
        "An item with the name 'secret' has already been added.",
      );
    });

    it('returns undefined for a missing name', () => {
      const cache = new ProtectedCache(createDataEncryptionKey());
      expect(cache.decryptStr('missing')).toBeUndefined();
    });
  });

  describe('addOrUpdate/addOrUpdateStr', () => {
    it('replaces an existing value', () => {
      const cache = new ProtectedCache(createDataEncryptionKey());
      cache.add('secret', Buffer.from('one'));
      cache.addOrUpdate('secret', Buffer.from('two!'));

      const result = Buffer.alloc(4);
      expect(cache.decrypt('secret', result)).toBe(4);
      expect(result).toEqual(Buffer.from('two!'));
    });

    it('addOrUpdateStr replaces an existing value', () => {
      const cache = new ProtectedCache(createDataEncryptionKey());
      cache.addStr('secret', 'one');
      cache.addOrUpdateStr('secret', 'two');

      expect(cache.decryptStr('secret')).toBe('two');
    });
  });

  describe('tryGetMaxDecryptedLength', () => {
    it('returns the encrypted length for a stored value', () => {
      const cache = new ProtectedCache(createDataEncryptionKey());
      cache.add('secret', Buffer.from('top secret'));

      expect(cache.tryGetMaxDecryptedLength('secret')).toBeGreaterThanOrEqual(10);
    });

    it('returns undefined for a missing name', () => {
      const cache = new ProtectedCache(createDataEncryptionKey());
      expect(cache.tryGetMaxDecryptedLength('missing')).toBeUndefined();
    });
  });

  describe('logger', () => {
    it('logs a failure through operationFailed when add throws', () => {
      const cache = new ProtectedCache(createDataEncryptionKey());
      cache.add('secret', Buffer.from('one'));

      const logger: Logger = { debug: vi.fn(), error: vi.fn() };
      const loggedCache = new ProtectedCache(createDataEncryptionKey(), logger);
      loggedCache.add('secret', Buffer.from('one'));

      expect(() => loggedCache.add('secret', Buffer.from('two'))).toThrow();
      expect(logger.error).toHaveBeenCalled();
    });
  });
});

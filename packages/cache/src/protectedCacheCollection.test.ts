import { describe, expect, it } from 'vitest';
import { ProtectedCache } from './protectedCache.js';
import { ProtectedCacheCollection } from './protectedCacheCollection.js';
import { createDataEncryptionKey } from './testHelpers/createDataEncryptionKey.js';

describe('ProtectedCacheCollection', () => {
  it('add returns the same instance for fluent chaining', () => {
    const collection = new ProtectedCacheCollection();
    const a = new ProtectedCache(createDataEncryptionKey());

    expect(collection.add(a)).toBe(collection);
  });

  it('checks sources in registration order, returning the first match', () => {
    const a = new ProtectedCache(createDataEncryptionKey());
    const b = new ProtectedCache(createDataEncryptionKey());
    a.addStr('only-in-a', 'from-a');
    b.addStr('only-in-b', 'from-b');
    b.addStr('shared', 'from-b');
    a.addStr('shared', 'from-a');

    const collection = new ProtectedCacheCollection().add(a).add(b);

    expect(collection.decryptStr('only-in-a')).toBe('from-a');
    expect(collection.decryptStr('only-in-b')).toBe('from-b');
    expect(collection.decryptStr('shared')).toBe('from-a');
  });

  it('decrypt returns 0 when no source has the name', () => {
    const collection = new ProtectedCacheCollection().add(new ProtectedCache(createDataEncryptionKey()));

    expect(collection.decrypt('missing', Buffer.alloc(10))).toBe(0);
  });

  it('decryptStr returns undefined when no source has the name', () => {
    const collection = new ProtectedCacheCollection().add(new ProtectedCache(createDataEncryptionKey()));

    expect(collection.decryptStr('missing')).toBeUndefined();
  });

  it('tryGetMaxDecryptedLength checks sources in order', () => {
    const a = new ProtectedCache(createDataEncryptionKey());
    const b = new ProtectedCache(createDataEncryptionKey());
    b.addStr('only-in-b', 'from-b');

    const collection = new ProtectedCacheCollection().add(a).add(b);

    expect(collection.tryGetMaxDecryptedLength('only-in-b')).toBeGreaterThanOrEqual(6);
    expect(collection.tryGetMaxDecryptedLength('missing')).toBeUndefined();
  });
});

/**
 * Port of HkdfGuard.Abstractions/ProtectedCacheBase.cs.
 *
 * Case-insensitive keying: C#'s ConcurrentDictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
 * becomes a plain Map keyed by name.toLowerCase() - Node has no built-in concurrent map, but Node
 * is single-threaded, so a plain Map's reads/writes are already atomic with respect to other JS
 * code running concurrently (no interleaving mid-operation the way multiple OS threads could
 * interleave in C#/Java/Python) - no separate lock is needed anywhere in this class.
 */

import { ActivityNames, AttributeNames, ComponentTelemetry, HkdfGuardTelemetry } from '@runsecure/hkdfguard-diagnostics';
import { zeroMemory } from './arrayUtility.js';
import type { DataEncryptionKey } from './dataEncryptionKey.js';
import type { ProtectedReadOnlyCache } from './protectedReadOnlyCache.js';

const telemetry = HkdfGuardTelemetry.root;

/**
 * Shared ProtectedReadOnlyCache plumbing for every cache in this library: a single
 * DataEncryptionKey, a Map<string, Buffer> of encrypted bytes keyed case-insensitively, and the
 * encrypt/decrypt/telemetry logic every concrete cache needs. decrypt/decryptStr/
 * tryGetMaxDecryptedLength fall back to tryPopulate on a miss before giving up - the default
 * implementation here just returns false (nothing to pull from), but a subclass backed by an
 * external source (e.g. a remote secret store) overrides it to fetch the plaintext value and
 * encrypt it into this cache on demand, so nothing here ever holds plaintext beyond the duration
 * of a single call.
 */
export abstract class ProtectedCacheBase implements ProtectedReadOnlyCache {
  protected readonly data = new Map<string, Buffer>();

  protected constructor(private readonly dataEncryptionKey: DataEncryptionKey) {}

  /**
   * Called when name isn't already cached, before decrypt/decryptStr/tryGetMaxDecryptedLength
   * give up and return a miss. The default implementation does nothing - override to pull a
   * value in from an external source and populate this cache (via tryAddEncrypted/setEncrypted)
   * before returning true.
   */
  protected tryPopulate(_name: string): boolean {
    return false;
  }

  decrypt(name: string, result: Buffer): number {
    const span = telemetry.tracer.startSpan(ActivityNames.cache.decrypt);
    telemetry.logSensitiveOperation(span, ActivityNames.cache.decrypt, { [AttributeNames.name]: name });
    try {
      const encrypted = this.tryGetEncrypted(name);
      if (encrypted === undefined) {
        return 0;
      }
      return this.dataEncryptionKey.decrypt(encrypted, result);
    } catch (err) {
      ComponentTelemetry.recordException(span, err as Error);
      throw err;
    } finally {
      span.end();
    }
  }

  decryptStr(name: string): string | undefined {
    const span = telemetry.tracer.startSpan(ActivityNames.cache.decrypt);
    telemetry.logSensitiveOperation(span, ActivityNames.cache.decrypt, { [AttributeNames.name]: name });
    try {
      const encrypted = this.tryGetEncrypted(name);
      if (encrypted === undefined) {
        return undefined;
      }

      // AEAD ciphertext is always at least as long as the plaintext it encloses, so
      // encrypted.length is a safe upper bound for the decrypted UTF-8 byte count.
      const plaintextBytes = Buffer.alloc(encrypted.length);
      try {
        const decryptedLength = this.dataEncryptionKey.decrypt(encrypted, plaintextBytes);
        return plaintextBytes.toString('utf8', 0, decryptedLength);
      } finally {
        zeroMemory(plaintextBytes);
      }
    } catch (err) {
      ComponentTelemetry.recordException(span, err as Error);
      throw err;
    } finally {
      span.end();
    }
  }

  tryGetMaxDecryptedLength(name: string): number | undefined {
    const encrypted = this.tryGetEncrypted(name);
    return encrypted === undefined ? undefined : encrypted.length;
  }

  private tryGetEncrypted(name: string): Buffer | undefined {
    const key = name.toLowerCase();
    const encrypted = this.data.get(key);
    if (encrypted !== undefined) {
      return encrypted;
    }

    if (this.tryPopulate(name)) {
      return this.data.get(key);
    }

    return undefined;
  }

  /**
   * Inserts encrypted under name unless a value is already stored there.
   *
   * @returns True if it was inserted
   */
  protected tryAddEncrypted(name: string, encrypted: Buffer): boolean {
    const key = name.toLowerCase();
    if (this.data.has(key)) {
      return false;
    }
    this.data.set(key, encrypted);
    return true;
  }

  /** Inserts encrypted under name, replacing any value already stored there. */
  protected setEncrypted(name: string, encrypted: Buffer): void {
    this.data.set(name.toLowerCase(), encrypted);
  }

  /** Encrypts plaintext through this cache's DataEncryptionKey. */
  protected encrypt(plaintext: Buffer): Buffer {
    return this.dataEncryptionKey.encrypt(plaintext);
  }

  /** Encrypts plaintext (as UTF-8 bytes) through this cache's DataEncryptionKey. */
  protected encryptStr(plaintext: string): Buffer {
    const plaintextBytes = Buffer.from(plaintext, 'utf8');
    try {
      return this.dataEncryptionKey.encrypt(plaintextBytes);
    } finally {
      zeroMemory(plaintextBytes);
    }
  }
}

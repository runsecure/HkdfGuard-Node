/**
 * Port of HkdfGuard.Abstractions/IProtectedCache.cs.
 *
 * Read/write surface of a highly concurrent name -> encrypted-value cache backed by a single
 * DataEncryptionKey. add/addOrUpdate protect and store plaintext under a name; the read surface
 * (decrypt/decryptStr/tryGetMaxDecryptedLength) is inherited from ProtectedReadOnlyCache. Nothing
 * here ever holds plaintext beyond the duration of a single add/addOrUpdate call - only the
 * encrypted bytes are retained internally.
 */

import type { ProtectedReadOnlyCache } from './protectedReadOnlyCache.js';

export interface ProtectedCache extends ProtectedReadOnlyCache {
  /**
   * Encrypts plaintext and stores it under name. plaintext may be zeroed as a side effect of
   * encrypting it.
   *
   * @throws {Error} A value is already stored under this name
   */
  add(name: string, plaintext: Buffer): void;

  /**
   * Encrypts plaintext (as UTF-8 bytes) and stores it under name.
   *
   * @throws {Error} A value is already stored under this name
   */
  addStr(name: string, plaintext: string): void;

  /** Encrypts plaintext and stores it under name, replacing any value already stored under that name. */
  addOrUpdate(name: string, plaintext: Buffer): void;

  /** Encrypts plaintext (as UTF-8 bytes) and stores it under name, replacing any value already stored under that name. */
  addOrUpdateStr(name: string, plaintext: string): void;
}

/**
 * Port of HkdfGuard.Abstractions/IProtectedReadOnlyCache.cs.
 *
 * Read surface of a highly concurrent name -> encrypted-value cache backed by a single
 * DataEncryptionKey. Names are compared case-insensitively. decrypt/decryptStr reveal a stored
 * value back into a caller-owned buffer or as a string, returning 0/undefined for a missing name
 * rather than throwing. Nothing here ever holds plaintext beyond the duration of a single decrypt
 * call - only the encrypted bytes are retained internally.
 */
export interface ProtectedReadOnlyCache {
  /**
   * Decrypts the value stored under name into result.
   *
   * @returns Number of bytes written to result, or 0 if no value is stored under name
   */
  decrypt(name: string, result: Buffer): number;

  /**
   * Decrypts the value stored under name as a UTF-8-decoded string.
   *
   * @returns The decrypted plaintext, or undefined if no value is stored under name
   */
  decryptStr(name: string): string | undefined;

  /**
   * Attempts to compute an upper bound on how many bytes decrypt will write for the value stored
   * under name, so a result buffer can be sized without decrypting first.
   *
   * @returns An upper bound on the decrypted length, or undefined if no value is stored under name
   */
  tryGetMaxDecryptedLength(name: string): number | undefined;
}

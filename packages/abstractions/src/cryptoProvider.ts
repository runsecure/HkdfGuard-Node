/**
 * Port of HkdfGuard.Abstractions/ICryptoProvider.cs.
 *
 * C#'s two Encrypt/Decrypt overloads (with and without an aad parameter) collapse into a single
 * method with an optional trailing aad parameter - the direct TypeScript equivalent, and the same
 * substitution already used by KeyWrapper's callers throughout this port. IDisposable becomes a
 * plain close() method, matching this package's existing convention (KeyWrapper has none since
 * IKeyWrapper isn't IDisposable in C# either).
 */

/**
 * Tracks a single cached crypto session, refreshing it (from a fresh key reveal/unwrap) once it
 * expires, and closing the outgoing session as it does. Callers should call encrypt/decrypt on
 * every operation rather than caching results themselves, so they always see a non-expired
 * session.
 */
export interface CryptoProvider {
  /**
   * Encrypts plaintext, authenticating aad alongside it if given.
   *
   * @param plaintext Plain data to encrypt. May be zeroed in place once encryption completes, as
   *   HkdfGuard.CryptoSession.AesGcm256's implementation does - callers should not read
   *   plaintext again afterward.
   * @param result The buffer to receive the encrypted data
   * @param aad Additional Auth Data for the encrypt operation
   * @returns Number of bytes written to result
   */
  encrypt(plaintext: Buffer, result: Buffer, aad?: Buffer): number;

  /**
   * Decrypts ciphertext, verifying it (and aad, if given) was produced by a matching encrypt
   * call.
   *
   * @param ciphertext The encrypted data to decrypt
   * @param result The buffer to receive the decrypted data
   * @param aad Additional Auth Data for the decrypt operation
   * @returns Number of bytes written to result
   */
  decrypt(ciphertext: Buffer, result: Buffer, aad?: Buffer): number;

  /** Releases the underlying cryptographic session. */
  close(): void;

  /** The buffer size encrypt needs for a plaintext of the given length. */
  getEncryptedAllocationLength(length: number): number;

  /** The buffer size decrypt needs for a ciphertext of the given length. */
  getDecryptedAllocationLength(length: number): number;
}

/**
 * Protects (encrypt) and reveals (decrypt) an encryption key against a single, implicitly
 * identified KEK (e.g. a native KMS-backed key, identified by service name at construction).
 * decrypt takes the wrapped payload as an explicit argument on every call, so one instance can
 * reveal any number of different wrapped keys sharing the same KEK - it holds no wrapped payload
 * of its own.
 */
export interface KeyWrapper {
  /**
   * Protects an encryption key.
   *
   * @param plaintext The plain bytes to encrypt
   * @param result The buffer to receive the encrypted key
   * @returns Number of bytes written to result
   */
  encrypt(plaintext: Buffer, result: Buffer): number;

  /**
   * Reveals a previously-wrapped key.
   *
   * @param wrapped The wrapped key to reveal
   * @param result The buffer to receive the decrypted key
   * @returns Number of bytes written to result
   */
  decrypt(wrapped: Buffer, result: Buffer): number;

  /**
   * Generates a fresh key and immediately protects it against the same KEK this instance
   * wraps/reveals against - the plaintext key never crosses this call's return value.
   *
   * @param result The buffer to receive the wrapped key
   * @returns Number of bytes written to result
   */
  generateAndWrap(result: Buffer): number;
}

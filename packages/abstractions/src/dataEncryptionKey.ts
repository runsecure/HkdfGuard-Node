/** Port of HkdfGuard.Abstractions/IDataEncryptionKey.cs. */

export interface DataEncryptionKey {
  /**
   * Protects an encryption key.
   *
   * @param plaintext The plain bytes to encrypt. May be zeroed in place once encryption
   *   completes - callers should not read plaintext again afterward.
   * @param aad Additional Auth Data for the encrypt operation
   * @returns The encrypted key, ready to be stored
   */
  encrypt(plaintext: Buffer, aad?: Buffer): Buffer;

  /**
   * Reveals an encryption key.
   *
   * @param ciphertext The encrypted key
   * @param result The buffer to receive the decrypted key
   * @param aad Additional Auth Data for the decrypt operation
   * @returns Number of bytes written to result
   */
  decrypt(ciphertext: Buffer, result: Buffer, aad?: Buffer): number;
}

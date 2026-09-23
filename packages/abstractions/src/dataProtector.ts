/**
 * Port of HkdfGuard.Abstractions/IDataProtector.cs.
 *
 * C#'s Decrypt writes into a caller-supplied Span<char> result, sized ahead of time via
 * GetMaxDecryptedLength, purely to avoid an extra string allocation holding decrypted plaintext.
 * JS strings are always immutable - there is no in-place char buffer to decrypt into - so decrypt
 * here just returns a new string, the same way encrypt already does on both sides.
 * getMaxDecryptedLength stays, since EncryptedFormatProvider still needs it and it is otherwise
 * unused.
 */

/**
 * A named, string-level data protector: the name given at construction is used as the Additional
 * Auth Data for every encrypt/decrypt, binding a protected value to the purpose it was protected
 * for so it can't be reused under a different one. encrypt/decrypt resolve the actual
 * DataEncryptionKey to use from a KeyRing, rather than holding one key permanently.
 */
export interface DataProtector {
  /** Encrypts a plaintext string and formats the result via the configured EncryptedFormatProvider. */
  encrypt(plaintext: string): string;

  /** Parses a formatted encrypted string via the configured EncryptedFormatProvider and decrypts it. */
  decrypt(encrypted: string): string;

  /** Computes an upper bound on how long decrypt's result will be for the given formatted string, without decrypting it. */
  getMaxDecryptedLength(encrypted: string): number;
}

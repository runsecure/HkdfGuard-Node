/** Port of HkdfGuard.Abstractions/IEncryptedFormatProvider.cs. */

import type { KeyTrackingValue } from './keyTrackingValue.js';

export interface EncryptedFormatProvider {
  format(value: KeyTrackingValue): string;

  parse(encrypted: string): KeyTrackingValue;

  /**
   * Computes an upper bound on the decrypted plaintext's length (bytes or UTF-8-decoded chars -
   * safe for either, since a decoded char count never exceeds a byte count) from the Base64
   * payload's length alone, without decoding it. AEAD ciphertext is always at least as long as
   * the plaintext it encloses, so the actual decrypted length is this value or less - always safe
   * to size a result buffer to what this returns.
   */
  getMaxDecryptedLength(encrypted: string): number;
}

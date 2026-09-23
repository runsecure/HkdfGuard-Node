/** Port of HkdfGuard.DataEncryptionKey/KeyWrappedDataEncryptionKey.cs. */

import type { CryptoProvider } from '@runsecure/hkdfguard-abstractions';
import { EncryptionKeyBase } from './encryptionKeyBase.js';

/**
 * A DataEncryptionKey backed by one wrapped DEK payload. provider owns revealing that payload's
 * key (from a fresh unwrap, on its own internal refresh schedule) and performing the actual data
 * encrypt/decrypt with it - see CryptoProvider.
 */
export class KeyWrappedDataEncryptionKey extends EncryptionKeyBase {
  constructor(provider: CryptoProvider) {
    super(provider);
  }
}

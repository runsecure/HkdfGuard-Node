/** Port of HkdfGuard.DataEncryptionKey/PipelineDataEncryptionKey.cs. */

import type { CryptoProvider } from '@runsecure/hkdfguard-abstractions';
import { zeroMemory } from '@runsecure/hkdfguard-abstractions';
import { EncryptionKeyBase } from './encryptionKeyBase.js';

/**
 * A DataEncryptionKey backed by a plain 32-byte DEK, used directly - never wrapped, never
 * unwrapped. Meant for a pipeline that needs to encrypt secrets in-flight before a durable KEK
 * exists yet: build one via PipelineKeyFactory, encrypt whatever needs protecting during the
 * pipeline, then read the same plaintext DEK back via asBuffer() at the end of the chain to hand
 * off to the platform's native "initialize" CLI utility, which independently wraps/registers it
 * against a real KEK. close() zeroes the DEK.
 */
export class PipelineDataEncryptionKey extends EncryptionKeyBase {
  constructor(
    provider: CryptoProvider,
    private readonly dek: Buffer,
  ) {
    super(provider);
  }

  /**
   * The plain, plaintext DEK this instance protects with - e.g. to hand off to the platform's
   * native "initialize" CLI utility once the pipeline finishes. Returns the live buffer, not a
   * copy - it reflects close()'s zeroing.
   */
  asBuffer(): Buffer {
    return this.dek;
  }

  /** Closes the underlying provider, and zeroes the plaintext DEK. */
  close(): void {
    this.provider.close();
    zeroMemory(this.dek);
  }
}

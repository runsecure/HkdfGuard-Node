/**
 * Port of HkdfGuard.DataEncryptionKey/PipelineKeyFactory.cs.
 *
 * Builds fresh PipelineDataEncryptionKey instances, each around a newly generated random 32-byte
 * DEK.
 *
 * The .NET original's Create also accepts a format-provider argument and an optional key version,
 * neither of which its own implementation ever reads (a pipeline key isn't registered in a
 * KeyRing, so it has no format or version to speak of) - this port drops both rather than
 * carrying two parameters that do nothing.
 */

import type { CryptoProviderFactory } from '@runsecure/hkdfguard-abstractions';
import { randomBytes } from 'node:crypto';
import { DummyKeyWrapper } from './dummyKeyWrapper.js';
import { PipelineDataEncryptionKey } from './pipelineDataEncryptionKey.js';

const DEK_LENGTH = 32;

export class PipelineKeyFactory {
  /**
   * Generates a fresh, cryptographically random 32-byte DEK and builds a PipelineDataEncryptionKey
   * around it via factory.createForPipeline.
   */
  create(factory: CryptoProviderFactory): PipelineDataEncryptionKey {
    const dek = randomBytes(DEK_LENGTH);
    const provider = factory.createForPipeline(new DummyKeyWrapper(), dek);
    return new PipelineDataEncryptionKey(provider, dek);
  }
}

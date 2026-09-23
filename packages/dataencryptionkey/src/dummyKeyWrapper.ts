/**
 * Port of HkdfGuard.DataEncryptionKey/DummyKeyWrapper.cs.
 *
 * Stands in for the KeyWrapper the pipeline flow's CryptoProviderFactory.createForPipeline
 * requires but never actually calls (the DEK is used as-is, never wrapped) - every member is an
 * inert no-op.
 */

import type { KeyWrapper } from '@runsecure/hkdfguard-abstractions';

export class DummyKeyWrapper implements KeyWrapper {
  encrypt(_plaintext: Buffer, _result: Buffer): number {
    return 0;
  }

  decrypt(_wrapped: Buffer, _result: Buffer): number {
    return 0;
  }

  generateAndWrap(_result: Buffer): number {
    return 0;
  }
}

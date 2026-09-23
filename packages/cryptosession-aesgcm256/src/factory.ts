/** Port of HkdfGuard.CryptoSession.AesGcm256/AesGcmCryptoProviderFactory.cs. */

import type { CryptoProvider, CryptoProviderFactory, KeyWrapper } from '@runsecure/hkdfguard-abstractions';
import { AesGcmCryptoProvider } from './provider.js';

// KeyWrapper.generateAndWrap is implementation-agnostic about its own wrapped-payload
// format/size (a native KMS library's is a small fixed size, at most a few hundred bytes) -
// over-allocate generously and trim to what it actually wrote.
const GENERATE_AND_WRAP_BUFFER_LENGTH = 512;

/** Builds AesGcmCryptoProvider instances. */
export class AesGcmCryptoProviderFactory implements CryptoProviderFactory {
  create(wrapper: KeyWrapper, wrapped: Buffer, expirySeconds: number): CryptoProvider {
    return new AesGcmCryptoProvider(wrapper, wrapped, expirySeconds);
  }

  createEphemeral(wrapper: KeyWrapper, expirySeconds: number): CryptoProvider {
    const buffer = Buffer.alloc(GENERATE_AND_WRAP_BUFFER_LENGTH);
    const written = wrapper.generateAndWrap(buffer);
    return new AesGcmCryptoProvider(wrapper, buffer.subarray(0, written), expirySeconds);
  }

  createForPipeline(wrapper: KeyWrapper, notWrapped: Buffer): CryptoProvider {
    return new AesGcmCryptoProvider(wrapper, notWrapped, undefined);
  }
}

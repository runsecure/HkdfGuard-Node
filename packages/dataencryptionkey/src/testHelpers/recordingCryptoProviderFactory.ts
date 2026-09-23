import type { CryptoProvider, CryptoProviderFactory, KeyWrapper } from '@runsecure/hkdfguard-abstractions';
import { AesGcmCryptoProviderFactory } from '@runsecure/hkdfguard-cryptosession-aesgcm256';

/**
 * A CryptoProviderFactory that delegates to a real AesGcmCryptoProviderFactory (so callers get a
 * genuinely working CryptoProvider back) while recording the arguments each method was called
 * with - lets KeyRingBuilder tests assert exactly what it passes through without depending on
 * AesGcmCryptoProvider exposing its own configuration for inspection.
 */
export class RecordingCryptoProviderFactory implements CryptoProviderFactory {
  private readonly inner = new AesGcmCryptoProviderFactory();
  readonly createExpirySecondsCalls: number[] = [];
  readonly createEphemeralExpirySecondsCalls: number[] = [];

  create(wrapper: KeyWrapper, wrapped: Buffer, expirySeconds: number): CryptoProvider {
    this.createExpirySecondsCalls.push(expirySeconds);
    return this.inner.create(wrapper, wrapped, expirySeconds);
  }

  createEphemeral(wrapper: KeyWrapper, expirySeconds: number): CryptoProvider {
    this.createEphemeralExpirySecondsCalls.push(expirySeconds);
    return this.inner.createEphemeral(wrapper, expirySeconds);
  }

  createForPipeline(wrapper: KeyWrapper, notWrapped: Buffer): CryptoProvider {
    return this.inner.createForPipeline(wrapper, notWrapped);
  }
}

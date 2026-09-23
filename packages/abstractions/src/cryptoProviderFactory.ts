/** Port of HkdfGuard.Abstractions/ICryptoProviderFactory.cs. */

import type { CryptoProvider } from './cryptoProvider.js';
import type { KeyWrapper } from './keyWrapper.js';

/**
 * Builds CryptoProvider instances bound to a KeyWrapper, for each of the three ways this library
 * reveals a DEK.
 */
export interface CryptoProviderFactory {
  /** Builds a CryptoProvider that reveals wrapped through wrapper, refreshing every expirySeconds. */
  create(wrapper: KeyWrapper, wrapped: Buffer, expirySeconds: number): CryptoProvider;

  /**
   * Generates a fresh DEK via wrapper.generateAndWrap and builds a CryptoProvider around it,
   * refreshing every expirySeconds.
   */
  createEphemeral(wrapper: KeyWrapper, expirySeconds: number): CryptoProvider;

  /**
   * Builds a CryptoProvider around notWrapped directly - notWrapped is already a plaintext DEK,
   * never wrapped or unwrapped through wrapper.
   */
  createForPipeline(wrapper: KeyWrapper, notWrapped: Buffer): CryptoProvider;
}

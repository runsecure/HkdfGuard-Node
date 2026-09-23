/**
 * Port of HkdfGuard.CryptoSession.AesGcm256/AesGcmCryptoProvider.cs.
 *
 * Tracks one cached AesGcmCryptoSession, bound to a single wrapped DEK. A background timer,
 * ticking every expirySeconds, proactively reveals the DEK fresh (via
 * keyWrapper.decrypt(wrapped, ...)) and builds the next AesGcmCryptoSession before the current
 * one expires, then swaps it in and closes the outgoing one (zeroing its key) - so encrypt/
 * decrypt themselves never pay the unwrap cost. Unlike the C#/Java/Python ports, no lock is
 * needed anywhere here: Node's single-threaded, run-to-completion event loop means refresh() (and
 * every method on this class) always runs to completion without any other code interleaving mid-
 * call, so there is no possibility of two refreshes racing to unwrap/swap the session.
 *
 * The pipeline-only construction path (notWrapped already a plaintext DEK, never refreshed) is
 * expressed as a second, overloaded constructor signature taking `expirySeconds: undefined` -
 * only AesGcmCryptoProviderFactory.createForPipeline, in this same package, is meant to call it;
 * this is the TypeScript analogue of a package-private secondary constructor.
 */

import type { CryptoProvider, KeyWrapper } from '@runsecure/hkdfguard-abstractions';
import { zeroMemory } from '@runsecure/hkdfguard-abstractions';
import { ActivityNames, ComponentTelemetry, HkdfGuardTelemetry } from '@runsecure/hkdfguard-diagnostics';
import { AesGcmCryptoSession, NONCE_SIZE, TAG_SIZE } from './session.js';

const KEY_LENGTH = 32;
const EXTRA_ALLOCATION_LENGTH = NONCE_SIZE + TAG_SIZE;

const telemetry = HkdfGuardTelemetry.cryptoSessionAesGcm256;

export class AesGcmCryptoProvider implements CryptoProvider {
  private readonly keyWrapper: KeyWrapper;
  private readonly wrapped: Buffer;
  private readonly expirySeconds: number | undefined;
  private current: AesGcmCryptoSession | undefined;
  private refreshTimer: NodeJS.Timeout | undefined;

  /**
   * @param keyWrapper Reveals wrapped's DEK - see KeyWrapper.decrypt.
   * @param wrapped The wrapped DEK payload this provider's sessions decrypt.
   * @param expirySeconds How long each refreshed session stays valid for, in the range 1-300.
   *   Also the background refresh interval: a fresh session is unwrapped this often, ahead of
   *   the current one's expiry.
   * @throws {Error} expirySeconds is not between 1 and 300, or the initial key reveal/session
   *   build fails.
   */
  constructor(keyWrapper: KeyWrapper, wrapped: Buffer, expirySeconds: number);
  constructor(keyWrapper: KeyWrapper, notWrapped: Buffer, expirySeconds: undefined);
  constructor(keyWrapper: KeyWrapper, wrapped: Buffer, expirySeconds: number | undefined) {
    this.keyWrapper = keyWrapper;
    this.wrapped = Buffer.from(wrapped);

    if (expirySeconds === undefined) {
      // Pipeline-only path: wrapped is already a plaintext DEK, never wrapped or unwrapped
      // through keyWrapper (held only for symmetry - never called). There is no background
      // refresh: the key never changes, so there is nothing to refresh.
      this.expirySeconds = undefined;
      this.current = new AesGcmCryptoSession(this.wrapped);
      this.refreshTimer = undefined;
      return;
    }

    if (!(expirySeconds >= 1 && expirySeconds <= 300)) {
      throw new Error(`expirySeconds must be between 1 and 300, got ${expirySeconds}.`);
    }

    this.expirySeconds = expirySeconds;
    this.refresh();

    this.refreshTimer = setInterval(() => this.backgroundRefresh(), expirySeconds * 1000);
    this.refreshTimer.unref();
  }

  encrypt(plaintext: Buffer, result: Buffer, aad?: Buffer): number {
    const session = this.current;
    if (session === undefined) {
      throw new Error('Operation on a closed AesGcmCryptoProvider.');
    }
    return session.encrypt(plaintext, result, aad);
  }

  decrypt(ciphertext: Buffer, result: Buffer, aad?: Buffer): number {
    const session = this.current;
    if (session === undefined) {
      throw new Error('Operation on a closed AesGcmCryptoProvider.');
    }
    return session.decrypt(ciphertext, result, aad);
  }

  getEncryptedAllocationLength(length: number): number {
    return length + EXTRA_ALLOCATION_LENGTH;
  }

  getDecryptedAllocationLength(length: number): number {
    return length - EXTRA_ALLOCATION_LENGTH;
  }

  private refresh(): void {
    const key = Buffer.alloc(KEY_LENGTH);
    this.keyWrapper.decrypt(this.wrapped, key);
    const fresh = new AesGcmCryptoSession(key);

    const outgoing = this.current;
    this.current = fresh;
    outgoing?.close();
  }

  private backgroundRefresh(): void {
    const span = telemetry.tracer.startSpan(ActivityNames.cryptoSessionAesGcm256.backgroundRefresh);
    try {
      this.refresh();
    } catch (err) {
      ComponentTelemetry.recordException(span, err as Error);
    } finally {
      span.end();
    }
  }

  close(): void {
    if (this.refreshTimer !== undefined) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = undefined;
    }

    zeroMemory(this.wrapped);

    const outgoing = this.current;
    this.current = undefined;
    outgoing?.close();
  }
}

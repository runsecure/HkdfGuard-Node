/**
 * Port of HkdfGuard.CryptoSession.AesGcm256/AesGcmCryptoSession.cs.
 *
 * Uses Node's built-in node:crypto (createCipheriv/createDecipheriv with 'aes-256-gcm') rather
 * than a third-party library - Node has native AES-GCM support, unlike Python (which needed
 * pyca/cryptography) or Java (which needed BouncyCastle). decipher.final() throws a plain Error
 * on a tampered ciphertext or mismatched aad ("Unsupported state or unable to authenticate data")
 * - the Node analogue of .NET's AuthenticationTagMismatchException; no custom exception type is
 * needed to signal it.
 *
 * AesGcmCryptoSession is an internal implementation detail of AesGcmCryptoProvider - like the
 * .NET original (`internal class AesGcmCryptoSession`), it is not re-exported from this package's
 * index and isn't part of the public API, even though nothing stops importing it directly.
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { isNullOrEmpty, zeroMemory } from '@runsecure/hkdfguard-abstractions';
import { ActivityNames, AttributeNames, ComponentTelemetry, HkdfGuardTelemetry } from '@runsecure/hkdfguard-diagnostics';

export const TAG_SIZE = 16;
export const NONCE_SIZE = 12;
const KEY_LENGTH = 32;

const telemetry = HkdfGuardTelemetry.cryptoSessionAesGcm256;

/**
 * An encrypt/decrypt session backed by a single 32-byte AES-256 key, supplied once at
 * construction. This instance is meant to be held for a while - see AesGcmCryptoProvider - and
 * closed (zeroing the key) once no longer needed rather than rebuilt on every operation.
 */
export class AesGcmCryptoSession {
  private key: Buffer | undefined;

  /**
   * @param key The 32-byte AES-256 key this session encrypts/decrypts with - ownership transfers
   *   to this instance, which zeroes it on close().
   * @throws {Error} key is empty/all-zero, or not exactly 32 bytes
   */
  constructor(key: Buffer) {
    if (isNullOrEmpty(key)) {
      throw new Error('AES key must not be empty or all zero.');
    }
    if (key.length !== KEY_LENGTH) {
      throw new Error(`AES key must be exactly ${KEY_LENGTH} bytes.`);
    }

    this.key = key;
  }

  /**
   * plaintext is zeroed in place once encryption completes (success or failure) - callers rely on
   * this rather than zeroing their own plaintext buffer afterward.
   */
  encrypt(plaintext: Buffer, result: Buffer, aad?: Buffer): number {
    const span = telemetry.tracer.startSpan(ActivityNames.cryptoSessionAesGcm256.encrypt);
    telemetry.logSensitiveOperation(span, ActivityNames.cryptoSessionAesGcm256.encrypt, {
      [AttributeNames.plaintextLength]: plaintext.length,
      [AttributeNames.aadLength]: aad?.length ?? 0,
    });
    try {
      return this.coreEncrypt(plaintext, result, aad);
    } catch (err) {
      ComponentTelemetry.recordException(span, err as Error);
      throw err;
    } finally {
      zeroMemory(plaintext);
      span.end();
    }
  }

  private coreEncrypt(plaintext: Buffer, result: Buffer, aad?: Buffer): number {
    if (this.key === undefined) {
      throw new Error('Operation on a closed AesGcmCryptoSession.');
    }
    if (isNullOrEmpty(plaintext)) {
      throw new Error('Plaintext must not be empty or all zero.');
    }

    const totalLength = NONCE_SIZE + plaintext.length + TAG_SIZE;
    if (result.length < totalLength) {
      throw new Error('Result buffer too small.');
    }

    // Layout: [nonce | ciphertext | tag]
    const nonce = randomBytes(NONCE_SIZE);
    const cipher = createCipheriv('aes-256-gcm', this.key, nonce, { authTagLength: TAG_SIZE });
    if (aad !== undefined) {
      cipher.setAAD(aad);
    }
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    nonce.copy(result, 0);
    ciphertext.copy(result, NONCE_SIZE);
    tag.copy(result, NONCE_SIZE + ciphertext.length);

    return totalLength;
  }

  decrypt(ciphertext: Buffer, result: Buffer, aad?: Buffer): number {
    const span = telemetry.tracer.startSpan(ActivityNames.cryptoSessionAesGcm256.decrypt);
    telemetry.logSensitiveOperation(span, ActivityNames.cryptoSessionAesGcm256.decrypt, {
      [AttributeNames.ciphertextLength]: ciphertext.length,
      [AttributeNames.aadLength]: aad?.length ?? 0,
    });
    try {
      return this.coreDecrypt(ciphertext, result, aad);
    } catch (err) {
      ComponentTelemetry.recordException(span, err as Error);
      throw err;
    } finally {
      span.end();
    }
  }

  private coreDecrypt(ciphertext: Buffer, result: Buffer, aad?: Buffer): number {
    if (this.key === undefined) {
      throw new Error('Operation on a closed AesGcmCryptoSession.');
    }
    if (isNullOrEmpty(ciphertext)) {
      throw new Error('Ciphertext must not be empty or all zero.');
    }
    if (ciphertext.length < NONCE_SIZE + TAG_SIZE) {
      throw new Error('Ciphertext too short.');
    }

    const resultLength = ciphertext.length - NONCE_SIZE - TAG_SIZE;
    if (result.length < resultLength) {
      throw new Error('Result buffer too small.');
    }

    const nonce = ciphertext.subarray(0, NONCE_SIZE);
    const ct = ciphertext.subarray(NONCE_SIZE, NONCE_SIZE + resultLength);
    const tag = ciphertext.subarray(NONCE_SIZE + resultLength, NONCE_SIZE + resultLength + TAG_SIZE);

    const decipher = createDecipheriv('aes-256-gcm', this.key, nonce, { authTagLength: TAG_SIZE });
    if (aad !== undefined) {
      decipher.setAAD(aad);
    }
    decipher.setAuthTag(tag);

    const plaintext = Buffer.concat([decipher.update(ct), decipher.final()]);
    plaintext.copy(result, 0);

    return resultLength;
  }

  /** Zeroes the session's own key copy. */
  close(): void {
    if (this.key !== undefined) {
      zeroMemory(this.key);
      this.key = undefined;
    }
  }
}

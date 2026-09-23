import type { KeyWrapper } from '@runsecure/hkdfguard-abstractions';
import { randomBytes } from 'node:crypto';

/**
 * A KeyWrapper that always reveals a fresh random key, tracking how many times decrypt/
 * generateAndWrap were called - isolates AesGcmCryptoProvider tests from any real native KMS
 * machinery.
 */
export class FakeKeyWrapper implements KeyWrapper {
  decryptCallCount = 0;
  generateAndWrapCallCount = 0;

  /** When set, decrypt throws this instead of revealing a key. */
  throwOnDecrypt: Error | undefined;

  encrypt(_plaintext: Buffer, _result: Buffer): number {
    throw new Error('FakeKeyWrapper only supports decrypt/generateAndWrap.');
  }

  decrypt(_wrapped: Buffer, result: Buffer): number {
    this.decryptCallCount++;
    if (this.throwOnDecrypt !== undefined) {
      throw this.throwOnDecrypt;
    }

    randomBytes(result.length).copy(result);
    return result.length;
  }

  generateAndWrap(result: Buffer): number {
    this.generateAndWrapCallCount++;
    const key = randomBytes(32);
    key.copy(result);
    return key.length;
  }
}

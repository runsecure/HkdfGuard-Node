import type { KeyWrapper } from '@runsecure/hkdfguard-abstractions';

/**
 * A KeyWrapper that always reveals/generates the same fixed key, tracking how many times
 * decrypt/generateAndWrap were called - isolates KeyWrappedDataEncryptionKey/KeyRing tests from
 * the real native KMS machinery while still exercising real AES-GCM via a real CryptoProvider.
 */
export class FakeKeyWrapper implements KeyWrapper {
  decryptCallCount = 0;
  generateAndWrapCallCount = 0;

  /**
   * When set, decrypt throws this instead of revealing the key - lets tests exercise a
   * KeyWrappedDataEncryptionKey encrypt/decrypt catch block without depending on the real cipher
   * failing.
   */
  throwOnDecrypt: Error | undefined;

  constructor(private readonly key: Buffer) {}

  encrypt(_plaintext: Buffer, _result: Buffer): number {
    throw new Error('FakeKeyWrapper only supports decrypt.');
  }

  decrypt(_wrapped: Buffer, result: Buffer): number {
    this.decryptCallCount++;
    if (this.throwOnDecrypt !== undefined) {
      throw this.throwOnDecrypt;
    }

    this.key.copy(result);
    return this.key.length;
  }

  generateAndWrap(result: Buffer): number {
    this.generateAndWrapCallCount++;
    this.key.copy(result);
    return this.key.length;
  }
}

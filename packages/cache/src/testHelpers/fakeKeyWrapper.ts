import type { KeyWrapper } from '@runsecure/hkdfguard-abstractions';

/** A KeyWrapper that always reveals the same fixed key - isolates cache tests from any real native KMS machinery. */
export class FakeKeyWrapper implements KeyWrapper {
  constructor(private readonly key: Buffer) {}

  encrypt(_plaintext: Buffer, _result: Buffer): number {
    throw new Error('FakeKeyWrapper only supports decrypt.');
  }

  decrypt(_wrapped: Buffer, result: Buffer): number {
    this.key.copy(result);
    return this.key.length;
  }

  generateAndWrap(_result: Buffer): number {
    throw new Error('FakeKeyWrapper only supports decrypt.');
  }
}

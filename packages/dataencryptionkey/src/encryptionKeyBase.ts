/**
 * Port of HkdfGuard.DataEncryptionKey/EncryptionKeyBase.cs.
 *
 * A DataEncryptionKey backed by one CryptoProvider. Every operation calls straight through to
 * provider, which owns revealing/refreshing its own key material - EncryptionKeyBase adds only
 * the allocation sizing (via provider.getEncryptedAllocationLength) and telemetry every concrete
 * key in this package needs.
 */

import type { CryptoProvider, DataEncryptionKey } from '@runsecure/hkdfguard-abstractions';
import { ActivityNames, AttributeNames, ComponentTelemetry, HkdfGuardTelemetry } from '@runsecure/hkdfguard-diagnostics';

const telemetry = HkdfGuardTelemetry.dataProtection;

export abstract class EncryptionKeyBase implements DataEncryptionKey {
  protected constructor(protected readonly provider: CryptoProvider) {}

  encrypt(plaintext: Buffer, aad?: Buffer): Buffer {
    const span = telemetry.tracer.startSpan(ActivityNames.dataProtection.keyWrappedKeyEncrypt);
    telemetry.logSensitiveOperation(span, ActivityNames.dataProtection.keyWrappedKeyEncrypt, {
      [AttributeNames.plaintextLength]: plaintext.length,
      [AttributeNames.aadLength]: aad?.length ?? 0,
    });
    try {
      const buffer = Buffer.alloc(this.provider.getEncryptedAllocationLength(plaintext.length));
      const written = this.provider.encrypt(plaintext, buffer, aad);
      return buffer.subarray(0, written);
    } catch (err) {
      ComponentTelemetry.recordException(span, err as Error);
      throw err;
    } finally {
      span.end();
    }
  }

  decrypt(ciphertext: Buffer, result: Buffer, aad?: Buffer): number {
    const span = telemetry.tracer.startSpan(ActivityNames.dataProtection.keyWrappedKeyDecrypt);
    telemetry.logSensitiveOperation(span, ActivityNames.dataProtection.keyWrappedKeyDecrypt, {
      [AttributeNames.ciphertextLength]: ciphertext.length,
      [AttributeNames.aadLength]: aad?.length ?? 0,
    });
    try {
      return this.provider.decrypt(ciphertext, result, aad);
    } catch (err) {
      ComponentTelemetry.recordException(span, err as Error);
      throw err;
    } finally {
      span.end();
    }
  }
}

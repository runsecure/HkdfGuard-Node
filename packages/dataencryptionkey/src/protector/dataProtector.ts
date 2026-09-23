/**
 * Port of HkdfGuard.DataEncryptionKey/Protector/DataProtector.cs.
 *
 * Default DataProtector. Not exported from this package's index: only KeyRing
 * (KeyRing.createProtector) can construct one, so callers only ever see it as a DataProtector -
 * guaranteeing every instance is actually bound to a real KeyRing rather than constructed loose.
 * name is UTF-8-encoded once into aad and used for every encrypt/decrypt, so a value protected
 * under one name/purpose fails to decrypt under another. encrypt resolves keyRing.getCurrent()
 * fresh on every call rather than capturing a version once at construction, so it always protects
 * new data with whatever the ring's latest rotation is; decrypt instead resolves whichever
 * version the formatted ciphertext itself names, so old versions stay readable regardless.
 */

import type { DataProtector as DataProtectorContract, EncryptedFormatProvider } from '@runsecure/hkdfguard-abstractions';
import { zeroMemory } from '@runsecure/hkdfguard-abstractions';
import { ActivityNames, AttributeNames, ComponentTelemetry, HkdfGuardTelemetry } from '@runsecure/hkdfguard-diagnostics';
import type { KeyRing } from '../keyRing.js';

const telemetry = HkdfGuardTelemetry.dataProtection;

export class DataProtector implements DataProtectorContract {
  private readonly aad: Buffer;

  constructor(
    private readonly name: string,
    private readonly keyRing: KeyRing,
    private readonly formatProvider: EncryptedFormatProvider,
  ) {
    this.aad = Buffer.from(name, 'utf8');
  }

  encrypt(plaintext: string): string {
    const span = telemetry.tracer.startSpan(ActivityNames.dataProtection.protectorEncrypt);
    telemetry.logSensitiveOperation(span, ActivityNames.dataProtection.protectorEncrypt, {
      [AttributeNames.name]: this.name,
      [AttributeNames.plaintextLength]: plaintext.length,
    });
    try {
      const { version, key } = this.keyRing.getCurrent();

      // plaintextBytes is zeroed as a side effect of the encrypt call it's passed to.
      const plaintextBytes = Buffer.from(plaintext, 'utf8');
      const encryptedBytes = key.encrypt(plaintextBytes, this.aad);

      return this.formatProvider.format({ keyVersion: version, value: encryptedBytes });
    } catch (err) {
      ComponentTelemetry.recordException(span, err as Error);
      throw err;
    } finally {
      span.end();
    }
  }

  decrypt(encrypted: string): string {
    const span = telemetry.tracer.startSpan(ActivityNames.dataProtection.protectorDecrypt);
    telemetry.logSensitiveOperation(span, ActivityNames.dataProtection.protectorDecrypt, {
      [AttributeNames.name]: this.name,
      [AttributeNames.encryptedLength]: encrypted.length,
    });
    try {
      const value = this.formatProvider.parse(encrypted);
      const key = this.keyRing.get(value.keyVersion);

      // AEAD ciphertext is always at least as long as the plaintext it encloses, so
      // value.value.length is a safe upper bound for the decrypted UTF-8 byte count.
      const plaintextBytes = Buffer.alloc(value.value.length);
      try {
        const bytesWritten = key.decrypt(value.value, plaintextBytes, this.aad);
        return plaintextBytes.toString('utf8', 0, bytesWritten);
      } finally {
        zeroMemory(plaintextBytes);
      }
    } catch (err) {
      ComponentTelemetry.recordException(span, err as Error);
      throw err;
    } finally {
      span.end();
    }
  }

  getMaxDecryptedLength(encrypted: string): number {
    return this.formatProvider.getMaxDecryptedLength(encrypted);
  }
}

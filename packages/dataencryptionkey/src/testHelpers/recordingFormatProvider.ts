import type { EncryptedFormatProvider, KeyTrackingValue } from '@runsecure/hkdfguard-abstractions';
import { DefaultFormatProvider } from '../formatProvider/defaultFormatProvider.js';

/**
 * An EncryptedFormatProvider that delegates to a real DefaultFormatProvider while recording
 * whether format was called - lets KeyRingBuilder tests assert the configured format provider is
 * actually the one used, without depending on the built KeyRing exposing its own format provider
 * for inspection.
 */
export class RecordingFormatProvider implements EncryptedFormatProvider {
  private readonly inner = new DefaultFormatProvider();
  formatCalled = false;

  format(value: KeyTrackingValue): string {
    this.formatCalled = true;
    return this.inner.format(value);
  }

  parse(encrypted: string): KeyTrackingValue {
    return this.inner.parse(encrypted);
  }

  getMaxDecryptedLength(encrypted: string): number {
    return this.inner.getMaxDecryptedLength(encrypted);
  }
}

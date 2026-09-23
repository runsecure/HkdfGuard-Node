/** Port of HkdfGuard.DataEncryptionKey/FormatProvider/DefaultFormatProvider.cs. */

import type { EncryptedFormatProvider, KeyTrackingValue } from '@runsecure/hkdfguard-abstractions';
import { ActivityNames, AttributeNames, ComponentTelemetry, HkdfGuardTelemetry } from '@runsecure/hkdfguard-diagnostics';
import { getBinaryLength, isBase64 } from '../utilities/base64ConversionUtility.js';

const ENC_PREFIX = 'enc';
const DELIMITER = '::';
const VERSION_PREFIX = 'v';

const telemetry = HkdfGuardTelemetry.dataProtection;

export class DefaultFormatProvider implements EncryptedFormatProvider {
  format(value: KeyTrackingValue): string {
    const span = telemetry.tracer.startSpan(ActivityNames.dataProtection.formatProviderFormat);
    telemetry.logSensitiveOperation(span, ActivityNames.dataProtection.formatProviderFormat, {
      [AttributeNames.keyVersion]: value.keyVersion,
      [AttributeNames.valueLength]: value.value.length,
    });
    try {
      const base64 = value.value.toString('base64');
      return `${ENC_PREFIX}${DELIMITER}${VERSION_PREFIX}${value.keyVersion}${DELIMITER}${base64}`;
    } catch (err) {
      ComponentTelemetry.recordException(span, err as Error);
      throw err;
    } finally {
      span.end();
    }
  }

  parse(encrypted: string): KeyTrackingValue {
    const span = telemetry.tracer.startSpan(ActivityNames.dataProtection.formatProviderParse);
    telemetry.logSensitiveOperation(span, ActivityNames.dataProtection.formatProviderParse, {
      [AttributeNames.encryptedLength]: encrypted.length,
    });
    try {
      const segments = tryParseSegments(encrypted);
      if (segments === undefined) {
        throw new Error(malformedMessage());
      }
      const { version, base64 } = segments;

      if (!isBase64(base64)) {
        throw new Error('Encrypted value is not valid base64.');
      }

      return { keyVersion: version, value: Buffer.from(base64, 'base64') };
    } catch (err) {
      ComponentTelemetry.recordException(span, err as Error);
      throw err;
    } finally {
      span.end();
    }
  }

  getMaxDecryptedLength(encrypted: string): number {
    const span = telemetry.tracer.startSpan(ActivityNames.dataProtection.formatProviderGetMaxDecryptedLength);
    telemetry.logSensitiveOperation(span, ActivityNames.dataProtection.formatProviderGetMaxDecryptedLength, {
      [AttributeNames.encryptedLength]: encrypted.length,
    });
    try {
      const segments = tryParseSegments(encrypted);
      if (segments === undefined) {
        throw new Error(malformedMessage());
      }

      if (!isBase64(segments.base64)) {
        throw new Error('Encrypted value is not valid base64.');
      }
      return getBinaryLength(segments.base64);
    } catch (err) {
      ComponentTelemetry.recordException(span, err as Error);
      throw err;
    } finally {
      span.end();
    }
  }
}

function malformedMessage(): string {
  return `Invalid encrypted format. Expected '${ENC_PREFIX}${DELIMITER}${VERSION_PREFIX}<version>${DELIMITER}<base64>'.`;
}

// Shared by parse and getMaxDecryptedLength so both agree on exactly what counts as well-formed -
// only getMaxDecryptedLength skips the actual base64 decode/allocation.
function tryParseSegments(encrypted: string): { version: number; base64: string } | undefined {
  const first = encrypted.indexOf(DELIMITER);
  if (first < 0) {
    return undefined;
  }

  const afterPrefix = encrypted.slice(first + DELIMITER.length);
  const second = afterPrefix.indexOf(DELIMITER);
  if (second < 0) {
    return undefined;
  }

  const prefix = encrypted.slice(0, first);
  const versionSegment = afterPrefix.slice(0, second);
  const base64Segment = afterPrefix.slice(second + DELIMITER.length);

  if (prefix !== ENC_PREFIX || !versionSegment.startsWith(VERSION_PREFIX)) {
    return undefined;
  }

  const versionText = versionSegment.slice(VERSION_PREFIX.length);
  if (!/^-?\d+$/.test(versionText)) {
    return undefined;
  }

  return { version: Number.parseInt(versionText, 10), base64: base64Segment };
}

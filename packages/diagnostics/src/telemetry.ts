import { ComponentTelemetry } from './componentTelemetry.js';

/**
 * One ComponentTelemetry instance per component in the library - the single place every
 * package's Tracer/Meter/enableSensitiveLogging telemetry lives. Preserves the same flag-sharing
 * split as the C# original: root, cache, dataProtection, and encryptedConfiguration all share one
 * enableSensitiveLogging flag (set any of them, all four read the new value);
 * cryptoSessionAesGcm256 and keyWrapping each keep their own, independent flag.
 */
const root = new ComponentTelemetry('HkdfGuard');
const cache = new ComponentTelemetry('HkdfGuard.Cache', root);
const dataProtection = new ComponentTelemetry('HkdfGuard.DataEncryptionKey', root);
const encryptedConfiguration = new ComponentTelemetry('HkdfGuard.EncryptedConfiguration', root);
const cryptoSessionAesGcm256 = new ComponentTelemetry('HkdfGuard.CryptoSession.AesGcm256');
const keyWrapping = new ComponentTelemetry('HkdfGuard.KeyWrapping.V1');

export const HkdfGuardTelemetry = {
  root,
  cache,
  dataProtection,
  encryptedConfiguration,
  cryptoSessionAesGcm256,
  keyWrapping,
} as const;

/**
 * Port of HkdfGuard.Cache/ProtectedCache.cs.
 *
 * Default ProtectedCache. Backed by a single, already-built DataEncryptionKey - every add/
 * addOrUpdate encrypts through it (see ProtectedCacheBase), every decrypt reveals through it. add
 * uses tryAddEncrypted as its atomicity gate so a duplicate name is rejected even under
 * concurrent callers; addOrUpdate's upsert and decrypt's reads are otherwise lock-free (Node's
 * single-threaded event loop needs no explicit locking here at all), so this holds up under
 * highly concurrent access in every direction. Nothing here ever holds plaintext beyond the
 * duration of a single add/addOrUpdate/decrypt call.
 *
 * The pattern class for HkdfGuard.Diagnostics's metrics/logging extension points: logger is
 * optional and, when supplied, receives a debug log per sensitive operation and an error log per
 * failure alongside the existing span/cache-operations-counter telemetry.
 */

import type { DataEncryptionKey, ProtectedCache as ProtectedCacheContract } from '@runsecure/hkdfguard-abstractions';
import { ProtectedCacheBase } from '@runsecure/hkdfguard-abstractions';
import {
  ActivityNames,
  AttributeNames,
  ComponentTelemetry,
  HkdfGuardTelemetry,
  operationFailed,
  recordCacheOperation,
  sensitiveOperationLogged,
  type Logger,
} from '@runsecure/hkdfguard-diagnostics';

const telemetry = HkdfGuardTelemetry.cache;

export class ProtectedCache extends ProtectedCacheBase implements ProtectedCacheContract {
  constructor(
    dataEncryptionKey: DataEncryptionKey,
    private readonly logger?: Logger,
  ) {
    super(dataEncryptionKey);
  }

  add(name: string, plaintext: Buffer): void {
    const span = telemetry.tracer.startSpan(ActivityNames.cache.add);
    if (telemetry.enableSensitiveLogging) {
      telemetry.logSensitiveOperation(span, ActivityNames.cache.add, {
        [AttributeNames.name]: name,
        [AttributeNames.plaintextLength]: plaintext.length,
      });
      sensitiveOperationLogged(this.logger, ActivityNames.cache.add, name);
    }

    try {
      if (!this.tryAddEncrypted(name, this.encrypt(plaintext))) {
        throw new Error(`An item with the name '${name}' has already been added.`);
      }
      recordCacheOperation(ActivityNames.cache.add, true);
    } catch (err) {
      ComponentTelemetry.recordException(span, err as Error);
      operationFailed(this.logger, ActivityNames.cache.add, err as Error);
      recordCacheOperation(ActivityNames.cache.add, false);
      throw err;
    } finally {
      span.end();
    }
  }

  addStr(name: string, plaintext: string): void {
    const span = telemetry.tracer.startSpan(ActivityNames.cache.add);
    if (telemetry.enableSensitiveLogging) {
      telemetry.logSensitiveOperation(span, ActivityNames.cache.add, {
        [AttributeNames.name]: name,
        [AttributeNames.plaintextLength]: plaintext.length,
      });
      sensitiveOperationLogged(this.logger, ActivityNames.cache.add, name);
    }

    try {
      if (!this.tryAddEncrypted(name, this.encryptStr(plaintext))) {
        throw new Error(`An item with the name '${name}' has already been added.`);
      }
      recordCacheOperation(ActivityNames.cache.add, true);
    } catch (err) {
      ComponentTelemetry.recordException(span, err as Error);
      operationFailed(this.logger, ActivityNames.cache.add, err as Error);
      recordCacheOperation(ActivityNames.cache.add, false);
      throw err;
    } finally {
      span.end();
    }
  }

  addOrUpdate(name: string, plaintext: Buffer): void {
    const span = telemetry.tracer.startSpan(ActivityNames.cache.addOrUpdate);
    if (telemetry.enableSensitiveLogging) {
      telemetry.logSensitiveOperation(span, ActivityNames.cache.addOrUpdate, {
        [AttributeNames.name]: name,
        [AttributeNames.plaintextLength]: plaintext.length,
      });
      sensitiveOperationLogged(this.logger, ActivityNames.cache.addOrUpdate, name);
    }

    try {
      this.setEncrypted(name, this.encrypt(plaintext));
      recordCacheOperation(ActivityNames.cache.addOrUpdate, true);
    } catch (err) {
      ComponentTelemetry.recordException(span, err as Error);
      operationFailed(this.logger, ActivityNames.cache.addOrUpdate, err as Error);
      recordCacheOperation(ActivityNames.cache.addOrUpdate, false);
      throw err;
    } finally {
      span.end();
    }
  }

  addOrUpdateStr(name: string, plaintext: string): void {
    const span = telemetry.tracer.startSpan(ActivityNames.cache.addOrUpdate);
    if (telemetry.enableSensitiveLogging) {
      telemetry.logSensitiveOperation(span, ActivityNames.cache.addOrUpdate, {
        [AttributeNames.name]: name,
        [AttributeNames.plaintextLength]: plaintext.length,
      });
      sensitiveOperationLogged(this.logger, ActivityNames.cache.addOrUpdate, name);
    }

    try {
      this.setEncrypted(name, this.encryptStr(plaintext));
      recordCacheOperation(ActivityNames.cache.addOrUpdate, true);
    } catch (err) {
      ComponentTelemetry.recordException(span, err as Error);
      operationFailed(this.logger, ActivityNames.cache.addOrUpdate, err as Error);
      recordCacheOperation(ActivityNames.cache.addOrUpdate, false);
      throw err;
    } finally {
      span.end();
    }
  }
}

/**
 * Port of HkdfGuard.Cache/ProtectedCacheCollection.cs.
 *
 * Aggregates multiple ProtectedReadOnlyCache sources into a single read-only surface. add
 * registers a source and returns this same instance for fluent chaining (e.g.
 * new ProtectedCacheCollection().add(a).add(b)). decrypt/decryptStr/tryGetMaxDecryptedLength
 * check each registered source in the order it was added, returning the first match. This never
 * owns or writes any encrypted values of its own - add here only registers a source, it never
 * protects or stores a value - so mutation of actual cached values stays entirely a concern of
 * whichever underlying source(s) actually support it (e.g. a writable ProtectedCache mixed in as
 * one of the sources).
 */

import type { ProtectedReadOnlyCache } from '@runsecure/hkdfguard-abstractions';
import { ActivityNames, AttributeNames, ComponentTelemetry, HkdfGuardTelemetry } from '@runsecure/hkdfguard-diagnostics';

const telemetry = HkdfGuardTelemetry.cache;

export class ProtectedCacheCollection implements ProtectedReadOnlyCache {
  private readonly sources: ProtectedReadOnlyCache[] = [];

  /** Registers source as an additional lookup source, checked after every source already added. */
  add(source: ProtectedReadOnlyCache): this {
    this.sources.push(source);
    return this;
  }

  decrypt(name: string, result: Buffer): number {
    const span = telemetry.tracer.startSpan(ActivityNames.cache.decrypt);
    telemetry.logSensitiveOperation(span, ActivityNames.cache.decrypt, { [AttributeNames.name]: name });
    try {
      for (const source of this.sources) {
        const written = source.decrypt(name, result);
        if (written > 0) {
          return written;
        }
      }
      return 0;
    } catch (err) {
      ComponentTelemetry.recordException(span, err as Error);
      throw err;
    } finally {
      span.end();
    }
  }

  decryptStr(name: string): string | undefined {
    const span = telemetry.tracer.startSpan(ActivityNames.cache.decrypt);
    telemetry.logSensitiveOperation(span, ActivityNames.cache.decrypt, { [AttributeNames.name]: name });
    try {
      for (const source of this.sources) {
        const value = source.decryptStr(name);
        if (value !== undefined) {
          return value;
        }
      }
      return undefined;
    } catch (err) {
      ComponentTelemetry.recordException(span, err as Error);
      throw err;
    } finally {
      span.end();
    }
  }

  tryGetMaxDecryptedLength(name: string): number | undefined {
    for (const source of this.sources) {
      const maxLength = source.tryGetMaxDecryptedLength(name);
      if (maxLength !== undefined) {
        return maxLength;
      }
    }
    return undefined;
  }
}

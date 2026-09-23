import { HkdfGuardTelemetry } from './telemetry.js';
import { MetricNames } from './metricNames.js';
import { AttributeNames } from './attributeNames.js';

/**
 * Records a ProtectedCache add/addOrUpdate call, tagged with `AttributeNames.operationName`
 * (which ActivityNames.cache constant ran) and `AttributeNames.result` ("success" or "error").
 *
 * The counter is resolved fresh from `HkdfGuardTelemetry.cache.meter` on every call rather than
 * cached in a module-level variable - see ComponentTelemetry's own tracer/meter getters for why
 * an instrument resolved once, early, can't be trusted to observe a MeterProvider registered
 * later (e.g. by a test).
 */
export function recordCacheOperation(operationName: string, success: boolean): void {
  const counter = HkdfGuardTelemetry.cache.meter.createCounter(MetricNames.cache.operations, {
    unit: '{operation}',
    description: 'Number of ProtectedCache operations, tagged by operation and result.',
  });

  counter.add(1, {
    [AttributeNames.operationName]: operationName,
    [AttributeNames.result]: success ? 'success' : 'error',
  });
}

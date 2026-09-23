import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { metrics } from '@opentelemetry/api';
import { AggregationTemporality, InMemoryMetricExporter, MeterProvider, PeriodicExportingMetricReader } from '@opentelemetry/sdk-metrics';
import { recordCacheOperation } from './cacheMetrics.js';
import { MetricNames } from './metricNames.js';
import { AttributeNames } from './attributeNames.js';

describe('recordCacheOperation', () => {
  let exporter: InMemoryMetricExporter;
  let reader: PeriodicExportingMetricReader;

  beforeAll(() => {
    exporter = new InMemoryMetricExporter(AggregationTemporality.CUMULATIVE);
    reader = new PeriodicExportingMetricReader({ exporter, exportIntervalMillis: 100_000 });
    const provider = new MeterProvider({ readers: [reader] });
    metrics.setGlobalMeterProvider(provider);
  });

  beforeEach(() => {
    exporter.reset();
  });

  afterAll(() => {
    metrics.disable();
  });

  it('records a success operation tagged with the operation name and result', async () => {
    recordCacheOperation('hkdfguard.cache.add', true);
    await reader.forceFlush();

    const [resourceMetrics] = exporter.getMetrics();
    const scopeMetric = resourceMetrics!.scopeMetrics.find((s) => s.scope.name === 'HkdfGuard.Cache');
    const metric = scopeMetric!.metrics.find((m) => m.descriptor.name === MetricNames.cache.operations);

    expect(metric).toBeDefined();
    expect(metric!.descriptor.unit).toBe('{operation}');

    const point = metric!.dataPoints[0]!;
    expect(point.value).toBe(1);
    expect(point.attributes[AttributeNames.operationName]).toBe('hkdfguard.cache.add');
    expect(point.attributes[AttributeNames.result]).toBe('success');
  });

  it('records a failed operation with result "error"', async () => {
    recordCacheOperation('hkdfguard.cache.add_or_update', false);
    await reader.forceFlush();

    const [resourceMetrics] = exporter.getMetrics();
    const scopeMetric = resourceMetrics!.scopeMetrics.find((s) => s.scope.name === 'HkdfGuard.Cache');
    const metric = scopeMetric!.metrics.find((m) => m.descriptor.name === MetricNames.cache.operations);

    const point = metric!.dataPoints.find(
      (p) => p.attributes[AttributeNames.operationName] === 'hkdfguard.cache.add_or_update',
    )!;
    expect(point.attributes[AttributeNames.result]).toBe('error');
  });
});

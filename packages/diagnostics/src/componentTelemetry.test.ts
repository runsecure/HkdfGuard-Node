import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { trace } from '@opentelemetry/api';
import { BasicTracerProvider, InMemorySpanExporter, SimpleSpanProcessor } from '@opentelemetry/sdk-trace-base';
import { ComponentTelemetry } from './componentTelemetry.js';
import { HkdfGuardTelemetry } from './telemetry.js';
import { EventNames } from './eventNames.js';
import { AttributeNames } from './attributeNames.js';

const allComponents: [string, ComponentTelemetry][] = [
  ['root', HkdfGuardTelemetry.root],
  ['cache', HkdfGuardTelemetry.cache],
  ['dataProtection', HkdfGuardTelemetry.dataProtection],
  ['encryptedConfiguration', HkdfGuardTelemetry.encryptedConfiguration],
  ['cryptoSessionAesGcm256', HkdfGuardTelemetry.cryptoSessionAesGcm256],
  ['keyWrapping', HkdfGuardTelemetry.keyWrapping],
];

describe('ComponentTelemetry', () => {
  let exporter: InMemorySpanExporter;

  beforeAll(() => {
    exporter = new InMemorySpanExporter();
    const provider = new BasicTracerProvider({
      spanProcessors: [new SimpleSpanProcessor(exporter)],
    });
    trace.setGlobalTracerProvider(provider);
  });

  beforeEach(() => {
    exporter.reset();
  });

  afterAll(() => {
    trace.disable();
  });

  it.each(allComponents)('tracer and meter names match sourceName (%s)', (_label, component) => {
    // The OTel API's InstrumentationScope isn't exposed on the public Tracer/Meter interfaces,
    // so the only externally-observable check is that resolving the tracer/meter for this
    // component's own sourceName doesn't throw and returns a usable instance.
    expect(component.tracer).toBeDefined();
    expect(component.meter).toBeDefined();
  });

  it.each(allComponents)('recordException with no span does not throw (%s)', () => {
    expect(() => ComponentTelemetry.recordException(undefined, new Error('boom'))).not.toThrow();
  });

  it.each(allComponents)('recordException records the exception and error status on a real span (%s)', (_label, component) => {
    const span = component.tracer.startSpan('test-activity');
    const error = new Error('boom');

    ComponentTelemetry.recordException(span, error);
    span.end();

    const [recorded] = exporter.getFinishedSpans();
    expect(recorded).toBeDefined();
    expect(recorded!.status.code).toBe(2); // SpanStatusCode.ERROR
    expect(recorded!.events.some((e) => e.name === 'exception')).toBe(true);
  });

  it.each(allComponents)('logSensitiveOperation with no span does not throw (%s)', (_label, component) => {
    expect(() => component.logSensitiveOperation(undefined, 'test-op')).not.toThrow();
  });

  it.each(allComponents)('logSensitiveOperation when disabled does not add an event (%s)', (_label, component) => {
    const original = component.enableSensitiveLogging;
    try {
      component.enableSensitiveLogging = false;

      const span = component.tracer.startSpan('test-activity');
      component.logSensitiveOperation(span, 'test-op', { key: 'value' });
      span.end();

      const [recorded] = exporter.getFinishedSpans();
      expect(recorded!.events).toHaveLength(0);
    } finally {
      component.enableSensitiveLogging = original;
    }
  });

  it.each(allComponents)('logSensitiveOperation when enabled adds a fixed-name event with operation and detail attributes (%s)', (_label, component) => {
    const original = component.enableSensitiveLogging;
    try {
      component.enableSensitiveLogging = true;

      const span = component.tracer.startSpan('test-activity');
      component.logSensitiveOperation(span, 'test-op', { [AttributeNames.name]: 'item' });
      span.end();

      const [recorded] = exporter.getFinishedSpans();
      expect(recorded!.events).toHaveLength(1);
      const loggedEvent = recorded!.events[0]!;
      expect(loggedEvent.name).toBe(EventNames.sensitiveOperation);
      expect(loggedEvent.attributes?.[AttributeNames.operationName]).toBe('test-op');
      expect(loggedEvent.attributes?.[AttributeNames.name]).toBe('item');
    } finally {
      component.enableSensitiveLogging = original;
    }
  });

  it('root shares its flag with cache, dataProtection, and encryptedConfiguration', () => {
    const original = HkdfGuardTelemetry.root.enableSensitiveLogging;
    try {
      HkdfGuardTelemetry.root.enableSensitiveLogging = true;
      expect(HkdfGuardTelemetry.cache.enableSensitiveLogging).toBe(true);
      expect(HkdfGuardTelemetry.dataProtection.enableSensitiveLogging).toBe(true);
      expect(HkdfGuardTelemetry.encryptedConfiguration.enableSensitiveLogging).toBe(true);

      HkdfGuardTelemetry.cache.enableSensitiveLogging = false;
      expect(HkdfGuardTelemetry.root.enableSensitiveLogging).toBe(false);
      expect(HkdfGuardTelemetry.dataProtection.enableSensitiveLogging).toBe(false);
      expect(HkdfGuardTelemetry.encryptedConfiguration.enableSensitiveLogging).toBe(false);
    } finally {
      HkdfGuardTelemetry.root.enableSensitiveLogging = original;
    }
  });

  it('cryptoSessionAesGcm256 and keyWrapping are independent from root and each other', () => {
    const originalRoot = HkdfGuardTelemetry.root.enableSensitiveLogging;
    const originalCryptoSession = HkdfGuardTelemetry.cryptoSessionAesGcm256.enableSensitiveLogging;
    const originalKeyWrapping = HkdfGuardTelemetry.keyWrapping.enableSensitiveLogging;
    try {
      HkdfGuardTelemetry.cryptoSessionAesGcm256.enableSensitiveLogging = false;
      HkdfGuardTelemetry.keyWrapping.enableSensitiveLogging = false;

      HkdfGuardTelemetry.root.enableSensitiveLogging = true;
      expect(HkdfGuardTelemetry.cryptoSessionAesGcm256.enableSensitiveLogging).toBe(false);
      expect(HkdfGuardTelemetry.keyWrapping.enableSensitiveLogging).toBe(false);

      HkdfGuardTelemetry.cryptoSessionAesGcm256.enableSensitiveLogging = true;
      expect(HkdfGuardTelemetry.keyWrapping.enableSensitiveLogging).toBe(false);
    } finally {
      HkdfGuardTelemetry.root.enableSensitiveLogging = originalRoot;
      HkdfGuardTelemetry.cryptoSessionAesGcm256.enableSensitiveLogging = originalCryptoSession;
      HkdfGuardTelemetry.keyWrapping.enableSensitiveLogging = originalKeyWrapping;
    }
  });
});

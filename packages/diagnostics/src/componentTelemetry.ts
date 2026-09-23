import { trace, metrics, SpanStatusCode, type Span, type Attributes, type Tracer, type Meter } from '@opentelemetry/api';
import { AttributeNames } from './attributeNames.js';
import { EventNames } from './eventNames.js';

/**
 * One component's telemetry surface: a Tracer and Meter sharing that component's scope name, an
 * enableSensitiveLogging toggle, and the recordException/logSensitiveOperation helpers every
 * operation across the library calls through. The Tracer/Meter are resolved from the global OTel
 * API on every access rather than cached at construction, so tests (and applications) that
 * register their own TracerProvider/MeterProvider after this module's instances have already
 * been created still observe it.
 */
export class ComponentTelemetry {
  /** This component's Tracer/Meter scope name - e.g. "HkdfGuard.Cache". */
  readonly sourceName: string;

  private readonly sharedFlagOwner: ComponentTelemetry | undefined;
  private ownEnableSensitiveLogging = false;

  /**
   * @param sourceName This component's Tracer/Meter scope name.
   * @param sharedFlagOwner enableSensitiveLogging delegates to this component's own flag instead
   *   of keeping an independent one - e.g. cache/dataProtection/encryptedConfiguration all share
   *   root's flag.
   */
  constructor(sourceName: string, sharedFlagOwner?: ComponentTelemetry) {
    this.sourceName = sourceName;
    this.sharedFlagOwner = sharedFlagOwner;
  }

  get tracer(): Tracer {
    return trace.getTracer(this.sourceName);
  }

  get meter(): Meter {
    return metrics.getMeter(this.sourceName);
  }

  /**
   * When enabled, sensitive operations emit additional debug telemetry (operation metadata such
   * as buffer lengths and identifiers). Raw key, plaintext, and ciphertext bytes are never
   * logged, regardless of this setting. A component constructed with a sharedFlagOwner reads and
   * writes that owner's flag instead of keeping its own.
   */
  get enableSensitiveLogging(): boolean {
    return this.sharedFlagOwner ? this.sharedFlagOwner.enableSensitiveLogging : this.ownEnableSensitiveLogging;
  }

  set enableSensitiveLogging(value: boolean) {
    if (this.sharedFlagOwner) {
      this.sharedFlagOwner.enableSensitiveLogging = value;
    } else {
      this.ownEnableSensitiveLogging = value;
    }
  }

  /**
   * Records an exception on span and marks it as errored. A missing span is a no-op.
   */
  static recordException(span: Span | undefined, error: Error): void {
    if (!span) {
      return;
    }
    span.recordException(error);
    span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
  }

  /**
   * Emits a fixed-name ({@link EventNames.sensitiveOperation}) debug event on span when
   * {@link enableSensitiveLogging} is set, carrying operationName and every detail as attributes.
   * Only pass non-sensitive metadata (lengths, identifiers, timings) as details - never raw key,
   * plaintext, or ciphertext bytes.
   */
  logSensitiveOperation(span: Span | undefined, operationName: string, details?: Attributes): void {
    if (!this.enableSensitiveLogging || !span) {
      return;
    }

    span.addEvent(EventNames.sensitiveOperation, {
      [AttributeNames.operationName]: operationName,
      ...details,
    });
  }
}

/**
 * Fixed span event names. Unlike the operation-specific {@link ActivityNames}, an event's own
 * name stays constant regardless of which operation raised it - the operation itself is carried
 * as the `AttributeNames.operationName` attribute instead - so event names stay low-cardinality
 * and stable for dashboards/queries.
 */
export const EventNames = {
  sensitiveOperation: 'hkdfguard.sensitive_operation',
} as const;

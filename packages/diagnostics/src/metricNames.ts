/**
 * Metric instrument names, following the same `hkdfguard.<component>.<noun>` convention as
 * {@link ActivityNames}.
 */
export const MetricNames = {
  cache: {
    operations: 'hkdfguard.cache.operations',
  },
} as const;

import { describe, it, expect } from 'vitest';
import { resolvePlatform } from './nativeHost.js';

describe('resolvePlatform', () => {
  it.each([
    ['win32', 'windows'],
    ['linux', 'linux'],
    ['darwin', 'macos'],
  ] as const)('maps %s to %s', (platform, expected) => {
    expect(resolvePlatform(platform)).toBe(expected);
  });

  it.each(['aix', 'freebsd', 'openbsd', 'sunos', 'android', 'haiku', 'cygwin', 'netbsd'] as const)(
    'throws for the unsupported platform %s',
    (platform) => {
      expect(() => resolvePlatform(platform)).toThrow(
        `HkdfGuard.KeyWrapping.V1 has no native KMS library for '${platform}'.`,
      );
    },
  );
});

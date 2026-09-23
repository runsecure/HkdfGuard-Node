import { describe, it, expect } from 'vitest';
import { AbstractHkdfGuardKmsLibrary } from './interop/abstractHkdfGuardKmsLibrary.js';
import { LinuxHkdfGuardKmsLibrary } from './interop/linuxHkdfGuardKmsLibrary.js';
import { MacOsHkdfGuardKmsLibrary } from './interop/macOsHkdfGuardKmsLibrary.js';
import { WindowsHkdfGuardKmsLibrary } from './interop/windowsHkdfGuardKmsLibrary.js';

// These only touch the platform classes' static error-code constants, never constructing an
// instance - construction calls koffi.load() against the real native library, which isn't
// present in this environment (or most CI environments). See nativeHkdfKeyWrapperV1.test.ts for
// behavioral coverage, exercised against a fake AbstractHkdfGuardKmsLibrary instead.

describe('AbstractHkdfGuardKmsLibrary constants', () => {
  it('match the expected values', () => {
    expect(AbstractHkdfGuardKmsLibrary.DEK_LENGTH).toBe(32);
    expect(AbstractHkdfGuardKmsLibrary.OK).toBe(0);
  });
});

describe('WindowsHkdfGuardKmsLibrary error constants', () => {
  it('match the expected values', () => {
    expect(WindowsHkdfGuardKmsLibrary.ERR_INVALID_ARG).toBe(-1);
    expect(WindowsHkdfGuardKmsLibrary.ERR_BUFFER_TOO_SMALL).toBe(-2);
    expect(WindowsHkdfGuardKmsLibrary.ERR_PROVIDER).toBe(-3);
    expect(WindowsHkdfGuardKmsLibrary.ERR_CRYPTO).toBe(-4);
    expect(WindowsHkdfGuardKmsLibrary.ERR_AUTH_FAILED).toBe(-5);
    expect(WindowsHkdfGuardKmsLibrary.ERR_MALFORMED).toBe(-6);
    expect(WindowsHkdfGuardKmsLibrary.ERR_INTERNAL).toBe(-7);
  });
});

describe('LinuxHkdfGuardKmsLibrary error constants', () => {
  it('match the expected values', () => {
    expect(LinuxHkdfGuardKmsLibrary.ERR_INVALID_ARGUMENT).toBe(-1);
    expect(LinuxHkdfGuardKmsLibrary.ERR_BUFFER_TOO_SMALL).toBe(-2);
    expect(LinuxHkdfGuardKmsLibrary.ERR_PROVIDER_UNAVAILABLE).toBe(-3);
    expect(LinuxHkdfGuardKmsLibrary.ERR_PROVIDER_ERROR).toBe(-4);
    expect(LinuxHkdfGuardKmsLibrary.ERR_CRYPTO_ERROR).toBe(-5);
    expect(LinuxHkdfGuardKmsLibrary.ERR_INTERNAL_ERROR).toBe(-6);
    expect(LinuxHkdfGuardKmsLibrary.ERR_INVALID_UTF8).toBe(-7);
    expect(LinuxHkdfGuardKmsLibrary.ERR_MISSING_SERVICE_NAME).toBe(-8);
  });
});

describe('MacOsHkdfGuardKmsLibrary error constants', () => {
  it('match the expected values', () => {
    expect(MacOsHkdfGuardKmsLibrary.ERR_INVALID_INPUT_LENGTH).toBe(-1);
    expect(MacOsHkdfGuardKmsLibrary.ERR_OUTPUT_BUFFER_TOO_SMALL).toBe(-2);
    expect(MacOsHkdfGuardKmsLibrary.ERR_KEY_UNAVAILABLE).toBe(-3);
    expect(MacOsHkdfGuardKmsLibrary.ERR_PUBLIC_KEY_UNAVAILABLE).toBe(-4);
    expect(MacOsHkdfGuardKmsLibrary.ERR_ENCRYPTION_FAILED).toBe(-5);
    expect(MacOsHkdfGuardKmsLibrary.ERR_DECRYPTION_FAILED).toBe(-6);
    expect(MacOsHkdfGuardKmsLibrary.ERR_UNEXPECTED_OUTPUT_LENGTH).toBe(-7);
    expect(MacOsHkdfGuardKmsLibrary.ERR_MISSING_SERVICE_IDENTIFIER).toBe(-8);
  });
});

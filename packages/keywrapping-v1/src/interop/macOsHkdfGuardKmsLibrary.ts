import koffi, { type LibraryHandle } from 'koffi';
import { AbstractHkdfGuardKmsLibrary, type NativeCallResult } from './abstractHkdfGuardKmsLibrary.js';

const LIBRARY_NAME = 'HkdfGuard.Kms.MacOS.v1.dylib';

type NativeFn = ReturnType<LibraryHandle['func']>;

/**
 * Binds HkdfGuard.Kms.MacOS.v1.dylib (see HkdfGuardKeyProtectionEnclave.h), which holds the
 * per-service KEK as a Secure Enclave key. Each distinct service string gets its own,
 * independent Secure Enclave key - wrapping under one service's identifier and unwrapping under
 * a different one fails by design (ERR_DECRYPTION_FAILED).
 */
export class MacOsHkdfGuardKmsLibrary extends AbstractHkdfGuardKmsLibrary {
  static readonly ERR_INVALID_INPUT_LENGTH = -1;
  static readonly ERR_OUTPUT_BUFFER_TOO_SMALL = -2;
  static readonly ERR_KEY_UNAVAILABLE = -3;
  static readonly ERR_PUBLIC_KEY_UNAVAILABLE = -4;
  static readonly ERR_ENCRYPTION_FAILED = -5;
  static readonly ERR_DECRYPTION_FAILED = -6;
  static readonly ERR_UNEXPECTED_OUTPUT_LENGTH = -7;
  static readonly ERR_MISSING_SERVICE_IDENTIFIER = -8;

  private readonly wrapDekFn: NativeFn;
  private readonly unwrapDekFn: NativeFn;
  private readonly generateAndWrapDekFn: NativeFn;

  constructor() {
    super();
    const lib = koffi.load(LIBRARY_NAME);
    this.wrapDekFn = lib.func(
      'int hkdfguard_wrap_dek(const char *service, const uint8_t *dek, int dek_len, uint8_t *output, _Inout_ int *out_len)',
    );
    this.unwrapDekFn = lib.func(
      'int hkdfguard_unwrap_dek(const char *service, const uint8_t *wrapped, int wrapped_len, uint8_t *output, _Inout_ int *out_len)',
    );
    this.generateAndWrapDekFn = lib.func(
      'int hkdfguard_generate_and_wrap_dek(const char *service, uint8_t *output, _Inout_ int *out_len)',
    );
  }

  override wrapDek(service: string, dek: Buffer, destination: Buffer): NativeCallResult {
    const outLen = [destination.length];
    const status = this.wrapDekFn(service, dek, dek.length, destination, outLen) as number;
    return { status, bytesWritten: outLen[0]! };
  }

  override unwrapDek(service: string, wrapped: Buffer, destination: Buffer): NativeCallResult {
    const outLen = [destination.length];
    const status = this.unwrapDekFn(service, wrapped, wrapped.length, destination, outLen) as number;
    return { status, bytesWritten: outLen[0]! };
  }

  override generateAndWrapDek(service: string, destination: Buffer): NativeCallResult {
    const outLen = [destination.length];
    const status = this.generateAndWrapDekFn(service, destination, outLen) as number;
    return { status, bytesWritten: outLen[0]! };
  }
}

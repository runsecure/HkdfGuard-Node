import koffi, { type LibraryHandle } from 'koffi';
import { AbstractHkdfGuardKmsLibrary, type NativeCallResult } from './abstractHkdfGuardKmsLibrary.js';

const LIBRARY_NAME = 'HkdfGuard.Kms.Windows.v1.dll';

type NativeFn = ReturnType<LibraryHandle['func']>;

/**
 * Binds HkdfGuard.Kms.Windows.v1.dll (see hkdfguard.h), which holds the per-service KEK as a
 * persistent, machine-wide-scoped, non-exportable P-256 key in the Microsoft Platform Crypto
 * Provider (TPM/vTPM) when available, or the Microsoft Software Key Storage Provider otherwise.
 */
export class WindowsHkdfGuardKmsLibrary extends AbstractHkdfGuardKmsLibrary {
  static readonly ERR_INVALID_ARG = -1;
  static readonly ERR_BUFFER_TOO_SMALL = -2;
  static readonly ERR_PROVIDER = -3;
  static readonly ERR_CRYPTO = -4;
  static readonly ERR_AUTH_FAILED = -5;
  static readonly ERR_MALFORMED = -6;
  static readonly ERR_INTERNAL = -7;

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

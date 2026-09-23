import koffi, { type LibraryHandle } from 'koffi';
import { AbstractHkdfGuardKmsLibrary, type NativeCallResult } from './abstractHkdfGuardKmsLibrary.js';

const LIBRARY_NAME = 'libHkdfGuardKeyProtectionLinux.so';

type NativeFn = ReturnType<LibraryHandle['func']>;

/**
 * Binds libHkdfGuardKeyProtectionLinux.so (see hkdfguard.h), which picks the strongest available
 * provider on the host - TPM2 > PKCS#11 > external secret > software > ephemeral - to hold the
 * per-service KEK. No Rust type, TPM handle, or OpenSSL structure ever crosses this boundary, and
 * no panic ever crosses it either: every native call below returns a plain status code.
 */
export class LinuxHkdfGuardKmsLibrary extends AbstractHkdfGuardKmsLibrary {
  static readonly ERR_INVALID_ARGUMENT = -1;
  static readonly ERR_BUFFER_TOO_SMALL = -2;
  static readonly ERR_PROVIDER_UNAVAILABLE = -3;
  static readonly ERR_PROVIDER_ERROR = -4;
  static readonly ERR_CRYPTO_ERROR = -5;
  static readonly ERR_INTERNAL_ERROR = -6;
  static readonly ERR_INVALID_UTF8 = -7;
  static readonly ERR_MISSING_SERVICE_NAME = -8;

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

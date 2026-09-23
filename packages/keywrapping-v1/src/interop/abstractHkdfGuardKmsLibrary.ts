/**
 * The result of a call into the native HkdfGuard KMS library: its status code (OK on success, or
 * a negative, implementation-specific error code), and the number of bytes written to the
 * destination buffer - or, on a buffer-too-small failure, the required capacity instead.
 */
export interface NativeCallResult {
  readonly status: number;
  readonly bytesWritten: number;
}

/**
 * Shared surface over a platform's native HkdfGuard KMS library. Every implementation wraps and
 * unwraps a fixed-length DEK under a persistent, per-service KEK held outside the Node process (a
 * TPM2 key, a Secure Enclave key, etc.) via that platform's hkdfguard_wrap_dek /
 * hkdfguard_unwrap_dek / hkdfguard_generate_and_wrap_dek native functions - identical in shape
 * across platforms, but each library's negative status codes mean different things, so callers
 * must consult the concrete implementation they're using to interpret a non-OK result.
 */
export abstract class AbstractHkdfGuardKmsLibrary {
  static readonly DEK_LENGTH = 32;

  /** Status code common to every platform's native library: the call succeeded. */
  static readonly OK = 0;

  /**
   * Wraps dek under the persistent KEK identified by service.
   *
   * @param service Non-empty, cross-platform identity of the KEK.
   * @param dek The plaintext DEK to wrap (must be exactly DEK_LENGTH bytes).
   * @param destination Buffer to receive the wrapped payload.
   */
  abstract wrapDek(service: string, dek: Buffer, destination: Buffer): NativeCallResult;

  /**
   * Unwraps a payload previously produced by wrapDek for the same service, recovering the
   * original DEK.
   *
   * @param service Must match the value used when the payload was wrapped.
   * @param wrapped The wrapped payload bytes.
   * @param destination Buffer to receive the recovered DEK.
   */
  abstract unwrapDek(service: string, wrapped: Buffer, destination: Buffer): NativeCallResult;

  /**
   * Generates a fresh, cryptographically random DEK and immediately wraps it under the persistent
   * KEK identified by service. The plaintext DEK never crosses this boundary - recover it later
   * via unwrapDek with the same service.
   *
   * @param service Service name to use with KMS operations.
   * @param destination Buffer to receive the wrapped payload.
   */
  abstract generateAndWrapDek(service: string, destination: Buffer): NativeCallResult;
}

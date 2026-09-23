/**
 * Thrown when a call into the native HkdfGuard KMS library returns a non-OK status.
 */
export class NativeKmsException extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NativeKmsException';
  }
}

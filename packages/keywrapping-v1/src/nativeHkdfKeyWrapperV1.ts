import type { KeyWrapper } from '@runsecure/hkdfguard-abstractions';
import { AbstractHkdfGuardKmsLibrary } from './interop/abstractHkdfGuardKmsLibrary.js';
import { NativeHost } from './nativeHost.js';
import { NativeKmsException } from './nativeKmsException.js';

/**
 * Protects (encrypt) a fresh DEK, or reveals (decrypt) a previously-wrapped one, via the current
 * OS's native HkdfGuard KMS library (see NativeHost) - a TPM2, Secure Enclave, or Platform Crypto
 * Provider key held entirely outside this process, identified only by a service name. No
 * salt/blob machinery is involved: the native library owns the KEK, the wrapped payload's format,
 * and its own key derivation. Since decrypt takes its wrapped payload as an explicit argument
 * rather than one bound at construction, a single instance freely handles both directions, and
 * any number of different wrapped payloads sharing the same service name. The native ABI has no
 * concept of AAD, so KeyWrapper itself does not expose an AAD-taking overload.
 */
export class NativeHkdfKeyWrapperV1 implements KeyWrapper {
  private readonly serviceName: string;
  private readonly library: AbstractHkdfGuardKmsLibrary;

  constructor(serviceName: string, library: AbstractHkdfGuardKmsLibrary = NativeHost.getLibrary()) {
    this.serviceName = serviceName;
    this.library = library;
  }

  encrypt(plaintext: Buffer, result: Buffer): number {
    const { status, bytesWritten } = this.library.wrapDek(this.serviceName, plaintext, result);
    if (status !== AbstractHkdfGuardKmsLibrary.OK) {
      throw new NativeKmsException(`Native KMS wrap failed with status ${status}.`);
    }
    return bytesWritten;
  }

  decrypt(wrapped: Buffer, result: Buffer): number {
    const { status, bytesWritten } = this.library.unwrapDek(this.serviceName, wrapped, result);
    if (status !== AbstractHkdfGuardKmsLibrary.OK) {
      throw new NativeKmsException(`Native KMS unwrap failed with status ${status}.`);
    }
    return bytesWritten;
  }

  generateAndWrap(result: Buffer): number {
    const { status, bytesWritten } = this.library.generateAndWrapDek(this.serviceName, result);
    if (status !== AbstractHkdfGuardKmsLibrary.OK) {
      throw new NativeKmsException(`Native KMS generate-and-wrap failed with status ${status}.`);
    }
    return bytesWritten;
  }
}

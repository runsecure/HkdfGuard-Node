import { describe, it, expect } from 'vitest';
import { AbstractHkdfGuardKmsLibrary, type NativeCallResult } from './interop/abstractHkdfGuardKmsLibrary.js';
import { NativeHkdfKeyWrapperV1 } from './nativeHkdfKeyWrapperV1.js';
import { NativeKmsException } from './nativeKmsException.js';

// Exercises NativeHkdfKeyWrapperV1 against a fake AbstractHkdfGuardKmsLibrary rather than a real
// platform binding - the real bindings call koffi.load() against a native library that isn't
// present in this (or most CI) environments. See kmsLibraryContract.test.ts for the one thing
// that's safe to assert about the real platform classes without loading them: their constants.
class FakeHkdfGuardKmsLibrary extends AbstractHkdfGuardKmsLibrary {
  wrapDekStatus = AbstractHkdfGuardKmsLibrary.OK;
  unwrapDekStatus = AbstractHkdfGuardKmsLibrary.OK;
  generateAndWrapDekStatus = AbstractHkdfGuardKmsLibrary.OK;

  wrapPayloadToEmit: Buffer | undefined;
  unwrapPayloadToEmit: Buffer | undefined;
  generateAndWrapPayloadToEmit: Buffer | undefined;

  lastService: string | undefined;
  lastWrapPlaintext: Buffer | undefined;
  lastUnwrapWrapped: Buffer | undefined;

  wrapCallCount = 0;
  unwrapCallCount = 0;
  generateAndWrapCallCount = 0;

  override wrapDek(service: string, dek: Buffer, destination: Buffer): NativeCallResult {
    this.wrapCallCount++;
    this.lastService = service;
    this.lastWrapPlaintext = Buffer.from(dek);

    if (this.wrapDekStatus !== AbstractHkdfGuardKmsLibrary.OK) {
      return { status: this.wrapDekStatus, bytesWritten: 0 };
    }

    const payload = this.wrapPayloadToEmit ?? dek;
    payload.copy(destination);
    return { status: AbstractHkdfGuardKmsLibrary.OK, bytesWritten: payload.length };
  }

  override unwrapDek(service: string, wrapped: Buffer, destination: Buffer): NativeCallResult {
    this.unwrapCallCount++;
    this.lastService = service;
    this.lastUnwrapWrapped = Buffer.from(wrapped);

    if (this.unwrapDekStatus !== AbstractHkdfGuardKmsLibrary.OK) {
      return { status: this.unwrapDekStatus, bytesWritten: 0 };
    }

    const payload = this.unwrapPayloadToEmit ?? wrapped;
    payload.copy(destination);
    return { status: AbstractHkdfGuardKmsLibrary.OK, bytesWritten: payload.length };
  }

  override generateAndWrapDek(service: string, destination: Buffer): NativeCallResult {
    this.generateAndWrapCallCount++;
    this.lastService = service;

    if (this.generateAndWrapDekStatus !== AbstractHkdfGuardKmsLibrary.OK) {
      return { status: this.generateAndWrapDekStatus, bytesWritten: 0 };
    }

    const payload = this.generateAndWrapPayloadToEmit ?? Buffer.alloc(64);
    payload.copy(destination);
    return { status: AbstractHkdfGuardKmsLibrary.OK, bytesWritten: payload.length };
  }
}

describe('NativeHkdfKeyWrapperV1', () => {
  describe('encrypt', () => {
    it('delegates to the library and returns the bytes written', () => {
      const library = new FakeHkdfGuardKmsLibrary();
      library.wrapPayloadToEmit = Buffer.from([10, 20, 30, 40]);
      const wrapper = new NativeHkdfKeyWrapperV1('service-a', library);

      const plaintext = Buffer.from([1, 2, 3, 4, 5]);
      const result = Buffer.alloc(16);
      const written = wrapper.encrypt(plaintext, result);

      expect(written).toBe(4);
      expect(library.wrapCallCount).toBe(1);
      expect(library.lastService).toBe('service-a');
      expect(library.lastWrapPlaintext).toEqual(plaintext);
      expect(result.subarray(0, 4)).toEqual(Buffer.from([10, 20, 30, 40]));
    });

    it.each([-1, -2, -7])('throws NativeKmsException when the library reports status %d', (status) => {
      const library = new FakeHkdfGuardKmsLibrary();
      library.wrapDekStatus = status;
      const wrapper = new NativeHkdfKeyWrapperV1('service-d', library);

      expect(() => wrapper.encrypt(Buffer.from([1, 2, 3]), Buffer.alloc(8))).toThrow(
        new NativeKmsException(`Native KMS wrap failed with status ${status}.`),
      );
      expect(library.wrapCallCount).toBe(1);
    });
  });

  describe('decrypt', () => {
    it('delegates to the library and returns the bytes written', () => {
      const library = new FakeHkdfGuardKmsLibrary();
      library.unwrapPayloadToEmit = Buffer.from([1, 2, 3, 4, 5]);
      const wrapper = new NativeHkdfKeyWrapperV1('service-a', library);

      const wrapped = Buffer.from([10, 20, 30, 40]);
      const result = Buffer.alloc(16);
      const written = wrapper.decrypt(wrapped, result);

      expect(written).toBe(5);
      expect(library.unwrapCallCount).toBe(1);
      expect(library.lastService).toBe('service-a');
      expect(library.lastUnwrapWrapped).toEqual(wrapped);
      expect(result.subarray(0, 5)).toEqual(Buffer.from([1, 2, 3, 4, 5]));
    });

    it.each([-1, -2, -6])('throws NativeKmsException when the library reports status %d', (status) => {
      const library = new FakeHkdfGuardKmsLibrary();
      library.unwrapDekStatus = status;
      const wrapper = new NativeHkdfKeyWrapperV1('service-d', library);

      expect(() => wrapper.decrypt(Buffer.from([10, 20, 30]), Buffer.alloc(8))).toThrow(
        new NativeKmsException(`Native KMS unwrap failed with status ${status}.`),
      );
      expect(library.unwrapCallCount).toBe(1);
    });
  });

  describe('generateAndWrap', () => {
    it('delegates to the library and returns the bytes written', () => {
      const library = new FakeHkdfGuardKmsLibrary();
      library.generateAndWrapPayloadToEmit = Buffer.from([11, 22, 33, 44, 55]);
      const wrapper = new NativeHkdfKeyWrapperV1('service-e', library);

      const result = Buffer.alloc(16);
      const written = wrapper.generateAndWrap(result);

      expect(written).toBe(5);
      expect(library.generateAndWrapCallCount).toBe(1);
      expect(library.lastService).toBe('service-e');
      expect(result.subarray(0, 5)).toEqual(Buffer.from([11, 22, 33, 44, 55]));
    });

    it.each([-1, -3, -7])('throws NativeKmsException when the library reports status %d', (status) => {
      const library = new FakeHkdfGuardKmsLibrary();
      library.generateAndWrapDekStatus = status;
      const wrapper = new NativeHkdfKeyWrapperV1('service-f', library);

      expect(() => wrapper.generateAndWrap(Buffer.alloc(16))).toThrow(
        new NativeKmsException(`Native KMS generate-and-wrap failed with status ${status}.`),
      );
      expect(library.generateAndWrapCallCount).toBe(1);
    });
  });
});

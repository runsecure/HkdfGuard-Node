/**
 * Port of HkdfGuard.DataEncryptionKey/KeyRing.cs.
 *
 * Tracks DataEncryptionKey instances by version. Node's single-threaded, run-to-completion event
 * loop means a plain Map's reads/writes are already atomic with respect to other JS code - unlike
 * the C#/Java/Python originals, add needs no separate lock/semaphore around its
 * check-and-insert, since nothing can interleave mid-call.
 *
 * The ring tracks its own current version intrinsically: whichever registered version number is
 * highest becomes currentVersion, automatically, the moment it's added - there is no separate
 * call to designate one, so it can never fall out of sync with what's actually registered.
 */

import type { DataEncryptionKey, DataProtector as DataProtectorContract, EncryptedFormatProvider } from '@runsecure/hkdfguard-abstractions';
import { ActivityNames, AttributeNames, ComponentTelemetry, HkdfGuardTelemetry } from '@runsecure/hkdfguard-diagnostics';
import { DataProtector } from './protector/dataProtector.js';

const telemetry = HkdfGuardTelemetry.dataProtection;

export class KeyRing {
  private readonly keysByVersion = new Map<number, DataEncryptionKey>();
  private currentVersionValue: number | undefined;

  constructor(private readonly formatProvider: EncryptedFormatProvider) {}

  /**
   * The highest version registered so far - what encrypt-side operations (e.g.
   * DataProtector.encrypt) protect new data with.
   *
   * @throws {Error} No key has been added yet
   */
  get currentVersion(): number {
    if (this.currentVersionValue === undefined) {
      throw new Error('No current version has been set. Add a key first.');
    }
    return this.currentVersionValue;
  }

  /**
   * Registers a key for the given version. If version is higher than every version registered so
   * far, it intrinsically becomes the new currentVersion.
   *
   * @throws {Error} A key for this version is already registered
   */
  add(version: number, key: DataEncryptionKey): void {
    const span = telemetry.tracer.startSpan(ActivityNames.dataProtection.keyRingAdd);
    try {
      if (this.keysByVersion.has(version)) {
        throw new Error(`A key for version ${version} is already registered.`);
      }
      this.keysByVersion.set(version, key);

      const becameCurrent = this.currentVersionValue === undefined || version > this.currentVersionValue;
      if (becameCurrent) {
        this.currentVersionValue = version;
      }

      telemetry.logSensitiveOperation(span, ActivityNames.dataProtection.keyRingAdd, {
        [AttributeNames.keyVersion]: version,
        [AttributeNames.keyRingBecameCurrent]: becameCurrent,
      });
    } catch (err) {
      ComponentTelemetry.recordException(span, err as Error);
      throw err;
    } finally {
      span.end();
    }
  }

  /**
   * Retrieves the key registered for the given version.
   *
   * @throws {Error} No key is registered for this version
   */
  get(version: number): DataEncryptionKey {
    const key = this.keysByVersion.get(version);
    if (key !== undefined) {
      return key;
    }

    const notFound = new Error(`No key is registered for version ${version}.`);
    const span = telemetry.tracer.startSpan(ActivityNames.dataProtection.keyRingGet);
    ComponentTelemetry.recordException(span, notFound);
    span.end();
    throw notFound;
  }

  /**
   * Attempts to retrieve the key registered for the given version without throwing - for the
   * high-frequency hot path, where exception overhead (and telemetry) on a routine miss is
   * unacceptable.
   */
  tryGet(version: number): DataEncryptionKey | undefined {
    return this.keysByVersion.get(version);
  }

  /**
   * Retrieves currentVersion together with its DataEncryptionKey atomically - what encrypt-side
   * operations (e.g. DataProtector.encrypt) resolve fresh on every call, so they always reflect
   * the latest rotation rather than a version captured once at construction.
   *
   * @throws {Error} No key has been added yet
   */
  getCurrent(): { version: number; key: DataEncryptionKey } {
    try {
      const version = this.currentVersion;
      return { version, key: this.get(version) };
    } catch (err) {
      const span = telemetry.tracer.startSpan(ActivityNames.dataProtection.keyRingGetCurrent);
      ComponentTelemetry.recordException(span, err as Error);
      span.end();
      throw err;
    }
  }

  /**
   * Creates a DataProtector bound to this KeyRing - the only way to obtain one, since
   * DataProtector is not part of this package's public API. encrypt resolves currentVersion
   * fresh via getCurrent on every call (not a version captured once here), and formats/parses via
   * the EncryptedFormatProvider this ring was constructed with.
   *
   * @param name Used as this protector's Additional Auth Data on every encrypt/decrypt
   */
  createProtector(name: string): DataProtectorContract {
    return new DataProtector(name, this, this.formatProvider);
  }
}

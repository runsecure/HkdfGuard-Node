/** Port of HkdfGuard.DataEncryptionKey/KeyRingBuilder.cs. */

import type { CryptoProviderFactory, EncryptedFormatProvider, KeyWrapper } from '@runsecure/hkdfguard-abstractions';
import { readFileSync } from 'node:fs';
import { DefaultFormatProvider } from './formatProvider/defaultFormatProvider.js';
import { KeyRing } from './keyRing.js';
import { KeyWrappedDataEncryptionKey } from './keyWrappedDataEncryptionKey.js';

/**
 * Builds a KeyRing from wrapped-DEK files on disk, suitable for registering as a singleton at
 * startup. There is one KeyWrapper shared by every registered file - it's bound only to a KEK
 * (e.g. NativeHkdfKeyWrapperV1's service name), not to any one wrapped payload, so it can reveal
 * any number of different files' DEKs (see KeyWrapper). Each registered file gets its own
 * CryptoProvider (minted by the configured CryptoProviderFactory, bound to that file's own
 * wrapped bytes) and becomes its own KeyWrappedDataEncryptionKey. withEphemeralKey registers a
 * version whose own key material is instead generated fresh in memory on first use (via
 * CryptoProviderFactory.createEphemeral) - it shares the same KeyWrapper/CryptoProviderFactory,
 * so no extra configuration is needed for it.
 * serviceName/keyRotationDays describe this ring's key identity/policy - they're carried on the
 * builder for callers to read back, but only cachedKeyExpiry is consumed by build itself (as
 * every provider's refresh interval), since KeyWrapper already knows what KEK it's bound to.
 */
export class KeyRingBuilder {
  private readonly keyFiles = new Map<number, string>();
  private readonly ephemeralVersions: number[] = [];
  private keyWrapper: KeyWrapper | undefined;
  private cryptoProviderFactory: CryptoProviderFactory | undefined;
  private formatProvider: EncryptedFormatProvider = new DefaultFormatProvider();
  private serviceNameValue: string | undefined;
  private cachedKeyExpiryValue: number | undefined;
  private keyRotationDaysValue: number | undefined;

  get serviceName(): string | undefined {
    return this.serviceNameValue;
  }

  get cachedKeyExpiry(): number | undefined {
    return this.cachedKeyExpiryValue;
  }

  get keyRotationDays(): number | undefined {
    return this.keyRotationDaysValue;
  }

  /** The service name identifying this ring's KEK to the native KMS library. */
  withServiceName(serviceName: string): this {
    this.serviceNameValue = serviceName;
    return this;
  }

  /**
   * How many seconds a revealed key may be cached in memory before it must be re-derived.
   *
   * @throws {Error} cachedKeyExpiry is not between 0 and 300
   */
  withCachedKeyExpiry(cachedKeyExpiry: number): this {
    if (!(cachedKeyExpiry >= 0 && cachedKeyExpiry <= 300)) {
      throw new Error(`cachedKeyExpiry must be between 0 and 300 seconds, got ${cachedKeyExpiry}.`);
    }
    this.cachedKeyExpiryValue = cachedKeyExpiry;
    return this;
  }

  /**
   * How many days may pass before this ring's key must be rotated.
   *
   * @throws {Error} keyRotationDays is not between 1 and 180
   */
  withKeyRotationDays(keyRotationDays: number): this {
    if (!(keyRotationDays >= 1 && keyRotationDays <= 180)) {
      throw new Error(`keyRotationDays must be between 1 and 180 days, got ${keyRotationDays}.`);
    }
    this.keyRotationDaysValue = keyRotationDays;
    return this;
  }

  /** Supplies the KeyWrapper shared by every registered key file when build runs. */
  withKeyWrapper(keyWrapper: KeyWrapper): this {
    this.keyWrapper = keyWrapper;
    return this;
  }

  /**
   * Supplies the factory used to build each key file's own CryptoProvider, called once per
   * registered file with the shared KeyWrapper and that file's own wrapped bytes.
   */
  withCryptoProviderFactory(cryptoProviderFactory: CryptoProviderFactory): this {
    this.cryptoProviderFactory = cryptoProviderFactory;
    return this;
  }

  /** Overrides the EncryptedFormatProvider the built KeyRing uses for createProtector. Defaults to DefaultFormatProvider. */
  withFormatProvider(formatProvider: EncryptedFormatProvider): this {
    this.formatProvider = formatProvider;
    return this;
  }

  /**
   * Registers a version whose wrapped DEK will be read from pathToFile when build runs. The
   * highest version registered across every withKeyFile call intrinsically becomes the built
   * KeyRing's currentVersion.
   *
   * @throws {Error} version is already registered
   */
  withKeyFile(version: number, pathToFile: string): this {
    if (this.keyFiles.has(version)) {
      throw new Error(`A key file for version ${version} is already registered.`);
    }
    this.keyFiles.set(version, pathToFile);
    return this;
  }

  /**
   * Registers a version whose own key material is generated fresh in memory the first time it's
   * used, and never written to or read from disk. The highest version registered across every
   * withKeyFile/withEphemeralKey call intrinsically becomes the built KeyRing's currentVersion.
   */
  withEphemeralKey(version: number): this {
    this.ephemeralVersions.push(version);
    return this;
  }

  /**
   * Reads each registered key file's wrapped bytes, mints each registered ephemeral key, and
   * returns a populated KeyRing.
   *
   * @throws {Error} No key wrapper, no crypto provider factory, no key files/ephemeral keys, or
   *   no cached key expiry were configured
   */
  build(): KeyRing {
    if (this.keyWrapper === undefined) {
      throw new Error('A key wrapper is required - call withKeyWrapper first.');
    }
    if (this.cryptoProviderFactory === undefined) {
      throw new Error('A crypto provider factory is required - call withCryptoProviderFactory first.');
    }
    if (this.keyFiles.size === 0 && this.ephemeralVersions.length === 0) {
      throw new Error('At least one key file or ephemeral key is required - call withKeyFile or withEphemeralKey first.');
    }
    if (this.cachedKeyExpiryValue === undefined) {
      throw new Error('A cached key expiry is required - call withCachedKeyExpiry first.');
    }

    const ring = new KeyRing(this.formatProvider);

    for (const version of [...this.keyFiles.keys()].sort((a, b) => a - b)) {
      const path = this.keyFiles.get(version)!;
      const wrapped = readFileSync(path);
      const provider = this.cryptoProviderFactory.create(this.keyWrapper, wrapped, this.cachedKeyExpiryValue);
      ring.add(version, new KeyWrappedDataEncryptionKey(provider));
    }

    for (const version of this.ephemeralVersions) {
      const provider = this.cryptoProviderFactory.createEphemeral(this.keyWrapper, this.cachedKeyExpiryValue);
      ring.add(version, new KeyWrappedDataEncryptionKey(provider));
    }

    return ring;
  }
}

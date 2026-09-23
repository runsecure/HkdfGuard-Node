import { randomBytes } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AesGcmCryptoProviderFactory } from '@runsecure/hkdfguard-cryptosession-aesgcm256';
import { describe, expect, it } from 'vitest';
import { KeyRingBuilder } from './keyRingBuilder.js';
import { FakeKeyWrapper } from './testHelpers/fakeKeyWrapper.js';
import { RecordingCryptoProviderFactory } from './testHelpers/recordingCryptoProviderFactory.js';
import { RecordingFormatProvider } from './testHelpers/recordingFormatProvider.js';

const cryptoProviderFactory = new AesGcmCryptoProviderFactory();

function fakeWrapper(): FakeKeyWrapper {
  return new FakeKeyWrapper(randomBytes(32));
}

function tempKeyFile(contents = 'wrapped'): string {
  const dir = mkdtempSync(join(tmpdir(), 'hkdfguard-keyringbuilder-'));
  const path = join(dir, 'key.bin');
  writeFileSync(path, contents);
  return path;
}

describe('KeyRingBuilder', () => {
  it('withServiceName sets serviceName', () => {
    expect(new KeyRingBuilder().withServiceName('my-service').serviceName).toBe('my-service');
  });

  it.each([0, 300])('withCachedKeyExpiry accepts %d', (value) => {
    expect(new KeyRingBuilder().withCachedKeyExpiry(value).cachedKeyExpiry).toBe(value);
  });

  it.each([-1, 301])('withCachedKeyExpiry rejects %d', (value) => {
    expect(() => new KeyRingBuilder().withCachedKeyExpiry(value)).toThrow();
  });

  it.each([1, 180])('withKeyRotationDays accepts %d', (value) => {
    expect(new KeyRingBuilder().withKeyRotationDays(value).keyRotationDays).toBe(value);
  });

  it.each([0, 181])('withKeyRotationDays rejects %d', (value) => {
    expect(() => new KeyRingBuilder().withKeyRotationDays(value)).toThrow();
  });

  it('build without a key wrapper throws', () => {
    const builder = new KeyRingBuilder().withCryptoProviderFactory(cryptoProviderFactory).withCachedKeyExpiry(60).withEphemeralKey(1);
    expect(() => builder.build()).toThrow();
  });

  it('build without a crypto provider factory throws', () => {
    const builder = new KeyRingBuilder().withKeyWrapper(fakeWrapper()).withCachedKeyExpiry(60).withEphemeralKey(1);
    expect(() => builder.build()).toThrow();
  });

  it('build without key files or ephemeral keys throws', () => {
    const builder = new KeyRingBuilder().withKeyWrapper(fakeWrapper()).withCryptoProviderFactory(cryptoProviderFactory).withCachedKeyExpiry(60);
    expect(() => builder.build()).toThrow();
  });

  it('build without a cached key expiry throws', () => {
    const builder = new KeyRingBuilder().withKeyWrapper(fakeWrapper()).withCryptoProviderFactory(cryptoProviderFactory).withEphemeralKey(1);
    expect(() => builder.build()).toThrow();
  });

  it('build with a key file registers the version from the file', () => {
    const ring = new KeyRingBuilder()
      .withKeyWrapper(fakeWrapper())
      .withCryptoProviderFactory(cryptoProviderFactory)
      .withCachedKeyExpiry(60)
      .withKeyFile(1, tempKeyFile())
      .build();

    expect(ring.currentVersion).toBe(1);
  });

  it('build with multiple key files, the highest version becomes current', () => {
    const ring = new KeyRingBuilder()
      .withKeyWrapper(fakeWrapper())
      .withCryptoProviderFactory(cryptoProviderFactory)
      .withCachedKeyExpiry(60)
      .withKeyFile(1, tempKeyFile('wrapped-v1'))
      .withKeyFile(2, tempKeyFile('wrapped-v2'))
      .build();

    expect(ring.currentVersion).toBe(2);
  });

  it('build with an ephemeral key registers the version', () => {
    const ring = new KeyRingBuilder()
      .withKeyWrapper(fakeWrapper())
      .withCryptoProviderFactory(cryptoProviderFactory)
      .withCachedKeyExpiry(60)
      .withEphemeralKey(1)
      .build();

    expect(ring.currentVersion).toBe(1);
  });

  it('build with an ephemeral key produces a working key', () => {
    const ring = new KeyRingBuilder()
      .withKeyWrapper(fakeWrapper())
      .withCryptoProviderFactory(cryptoProviderFactory)
      .withCachedKeyExpiry(60)
      .withEphemeralKey(1)
      .build();

    const key = ring.get(1);
    const plaintext = Buffer.from('top secret');
    const expected = Buffer.from(plaintext);

    const encrypted = key.encrypt(plaintext);
    const decrypted = Buffer.alloc(expected.length);
    const written = key.decrypt(encrypted, decrypted);

    expect(written).toBe(expected.length);
    expect(decrypted).toEqual(expected);
  });

  it('build with a key file and a higher-version ephemeral key, the ephemeral key becomes current', () => {
    const ring = new KeyRingBuilder()
      .withKeyWrapper(fakeWrapper())
      .withCryptoProviderFactory(cryptoProviderFactory)
      .withCachedKeyExpiry(60)
      .withKeyFile(1, tempKeyFile())
      .withEphemeralKey(2)
      .build();

    expect(ring.currentVersion).toBe(2);
  });

  it('build uses the configured format provider', () => {
    const recordingFormatProvider = new RecordingFormatProvider();

    const ring = new KeyRingBuilder()
      .withKeyWrapper(fakeWrapper())
      .withCryptoProviderFactory(cryptoProviderFactory)
      .withCachedKeyExpiry(60)
      .withEphemeralKey(1)
      .withFormatProvider(recordingFormatProvider)
      .build();

    ring.createProtector('purpose').encrypt('hello');

    expect(recordingFormatProvider.formatCalled).toBe(true);
  });

  it('build with a key file passes cachedKeyExpiry to the crypto provider factory', () => {
    const recordingFactory = new RecordingCryptoProviderFactory();

    new KeyRingBuilder()
      .withKeyWrapper(fakeWrapper())
      .withCryptoProviderFactory(recordingFactory)
      .withCachedKeyExpiry(123)
      .withKeyFile(1, tempKeyFile())
      .build();

    expect(recordingFactory.createExpirySecondsCalls).toEqual([123]);
  });

  it('build with an ephemeral key passes cachedKeyExpiry rather than the version to the crypto provider factory', () => {
    // Regression test: createEphemeral used to be called with the KeyRing version instead of
    // cachedKeyExpiry - a version of 1 would silently become a 1-second session lifetime.
    const recordingFactory = new RecordingCryptoProviderFactory();

    new KeyRingBuilder()
      .withKeyWrapper(fakeWrapper())
      .withCryptoProviderFactory(recordingFactory)
      .withCachedKeyExpiry(123)
      .withEphemeralKey(42)
      .build();

    expect(recordingFactory.createEphemeralExpirySecondsCalls).toEqual([123]);
  });
});

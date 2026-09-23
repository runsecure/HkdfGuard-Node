import { randomBytes } from 'node:crypto';
import type { DataEncryptionKey } from '@runsecure/hkdfguard-abstractions';
import { AesGcmCryptoProvider } from '@runsecure/hkdfguard-cryptosession-aesgcm256';
import { KeyWrappedDataEncryptionKey } from '@runsecure/hkdfguard-dataencryptionkey';
import { FakeKeyWrapper } from './fakeKeyWrapper.js';

/** A real, working DataEncryptionKey backed by a fake (fixed-key) wrapper - for exercising the cache against real AES-GCM. */
export function createDataEncryptionKey(): DataEncryptionKey {
  const wrapper = new FakeKeyWrapper(randomBytes(32));
  return new KeyWrappedDataEncryptionKey(new AesGcmCryptoProvider(wrapper, Buffer.from('wrapped'), 60));
}

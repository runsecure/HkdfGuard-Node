/**
 * Span/operation names, grouped by component - lowercase, dot-separated (OpenTelemetry
 * semantic-convention style: `hkdfguard.<component>.<operation>`), so the same names translate
 * identically into every HkdfGuard port's own OTel SDK usage.
 */
export const ActivityNames = {
  cache: {
    add: 'hkdfguard.cache.add',
    addOrUpdate: 'hkdfguard.cache.add_or_update',
    decrypt: 'hkdfguard.cache.decrypt',
  },
  dataProtection: {
    protectorEncrypt: 'hkdfguard.data_protection.protector.encrypt',
    protectorDecrypt: 'hkdfguard.data_protection.protector.decrypt',
    keyWrappedKeyEncrypt: 'hkdfguard.data_protection.key_wrapped_key.encrypt',
    keyWrappedKeyDecrypt: 'hkdfguard.data_protection.key_wrapped_key.decrypt',
    ephemeralKeyInitialize: 'hkdfguard.data_protection.ephemeral_key.initialize',
    pipelineKeyInitialize: 'hkdfguard.data_protection.pipeline_key.initialize',
    keyRingAdd: 'hkdfguard.data_protection.key_ring.add',
    keyRingGet: 'hkdfguard.data_protection.key_ring.get',
    keyRingGetCurrent: 'hkdfguard.data_protection.key_ring.get_current',
    formatProviderFormat: 'hkdfguard.data_protection.format.format',
    formatProviderParse: 'hkdfguard.data_protection.format.parse',
    formatProviderGetMaxDecryptedLength: 'hkdfguard.data_protection.format.get_max_decrypted_length',
  },
  cryptoSessionAesGcm256: {
    encrypt: 'hkdfguard.crypto_session_aes_gcm256.encrypt',
    decrypt: 'hkdfguard.crypto_session_aes_gcm256.decrypt',
    backgroundRefresh: 'hkdfguard.crypto_session_aes_gcm256.background_refresh',
  },
  encryptedConfiguration: {
    decrypt: 'hkdfguard.encrypted_configuration.decrypt',
  },
} as const;

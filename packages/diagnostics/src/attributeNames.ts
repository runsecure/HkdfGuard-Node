/**
 * Attribute/tag keys shared across every component's spans, events, and metrics - lowercase,
 * dot-separated (OpenTelemetry semantic-convention style), so the same keys translate identically
 * into every HkdfGuard port's own OTel SDK usage.
 */
export const AttributeNames = {
  name: 'hkdfguard.name',
  plaintextLength: 'hkdfguard.plaintext_length',
  ciphertextLength: 'hkdfguard.ciphertext_length',
  encryptedLength: 'hkdfguard.encrypted_length',
  aadLength: 'hkdfguard.aad_length',
  valueLength: 'hkdfguard.value_length',
  keyVersion: 'hkdfguard.key_version',
  keyRingBecameCurrent: 'hkdfguard.key_ring.became_current',
  operationName: 'hkdfguard.operation.name',
  result: 'hkdfguard.result',
} as const;

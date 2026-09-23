import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { AesGcmCryptoSession, NONCE_SIZE, TAG_SIZE } from './session.js';

function randomKey(): Buffer {
  return randomBytes(32);
}

describe('AesGcmCryptoSession', () => {
  describe('constructor', () => {
    it('throws on an empty key', () => {
      expect(() => new AesGcmCryptoSession(Buffer.alloc(32))).toThrow('AES key must not be empty or all zero.');
    });

    it('throws on a wrong-size key', () => {
      expect(() => new AesGcmCryptoSession(randomBytes(16))).toThrow('AES key must be exactly 32 bytes.');
    });
  });

  describe('encrypt/decrypt', () => {
    it('round trips', () => {
      const session = new AesGcmCryptoSession(randomKey());
      const plaintext = Buffer.from('top secret');
      const expected = Buffer.from(plaintext);

      const encrypted = Buffer.alloc(plaintext.length + NONCE_SIZE + TAG_SIZE);
      const written = session.encrypt(plaintext, encrypted);
      expect(written).toBe(encrypted.length);

      const decrypted = Buffer.alloc(expected.length);
      const decryptedLength = session.decrypt(encrypted.subarray(0, written), decrypted);

      expect(decryptedLength).toBe(expected.length);
      expect(decrypted).toEqual(expected);
    });

    it('zeroes the plaintext buffer as a side effect', () => {
      const session = new AesGcmCryptoSession(randomKey());
      const plaintext = Buffer.from('top secret');
      const result = Buffer.alloc(plaintext.length + NONCE_SIZE + TAG_SIZE);

      session.encrypt(plaintext, result);

      expect(plaintext).toEqual(Buffer.alloc(plaintext.length));
    });

    it('round trips with aad', () => {
      const session = new AesGcmCryptoSession(randomKey());
      const plaintext = Buffer.from('top secret');
      const expected = Buffer.from(plaintext);
      const aad = Buffer.from('context');

      const encrypted = Buffer.alloc(plaintext.length + NONCE_SIZE + TAG_SIZE);
      const written = session.encrypt(plaintext, encrypted, aad);

      const decrypted = Buffer.alloc(expected.length);
      const decryptedLength = session.decrypt(encrypted.subarray(0, written), decrypted, aad);

      expect(decrypted.subarray(0, decryptedLength)).toEqual(expected);
    });

    it('throws on mismatched aad', () => {
      const session = new AesGcmCryptoSession(randomKey());
      const plaintext = Buffer.from('top secret');
      const encrypted = Buffer.alloc(plaintext.length + NONCE_SIZE + TAG_SIZE);
      const written = session.encrypt(plaintext, encrypted, Buffer.from('context-a'));

      expect(() => session.decrypt(encrypted.subarray(0, written), Buffer.alloc(16), Buffer.from('context-b'))).toThrow();
    });

    it('throws on tampered ciphertext', () => {
      const session = new AesGcmCryptoSession(randomKey());
      const plaintext = Buffer.from('top secret');
      const encrypted = Buffer.alloc(plaintext.length + NONCE_SIZE + TAG_SIZE);
      const written = session.encrypt(plaintext, encrypted);
      encrypted[NONCE_SIZE] ^= 0xff;

      expect(() => session.decrypt(encrypted.subarray(0, written), Buffer.alloc(plaintext.length))).toThrow();
    });

    it('throws on an empty plaintext', () => {
      const session = new AesGcmCryptoSession(randomKey());
      expect(() => session.encrypt(Buffer.alloc(10), Buffer.alloc(64))).toThrow(
        'Plaintext must not be empty or all zero.',
      );
    });

    it('throws when the result buffer is too small', () => {
      const session = new AesGcmCryptoSession(randomKey());
      expect(() => session.encrypt(Buffer.from('top secret'), Buffer.alloc(4))).toThrow('Result buffer too small.');
    });
  });

  describe('close', () => {
    it('zeroes the key', () => {
      const key = randomKey();
      const original = Buffer.from(key);
      const session = new AesGcmCryptoSession(key);

      session.close();

      expect(key).not.toEqual(original);
      expect(key).toEqual(Buffer.alloc(32));
    });

    it('causes further operations to throw', () => {
      const session = new AesGcmCryptoSession(randomKey());
      session.close();

      expect(() => session.encrypt(Buffer.from('x'), Buffer.alloc(64))).toThrow(
        'Operation on a closed AesGcmCryptoSession.',
      );
      expect(() => session.decrypt(Buffer.alloc(64), Buffer.alloc(64))).toThrow(
        'Operation on a closed AesGcmCryptoSession.',
      );
    });
  });
});

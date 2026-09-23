/**
 * Port of HkdfGuard.DataEncryptionKey/Utilities/Base64ConversionUtility.cs.
 *
 * Node's Buffer.from(str, 'base64') is lenient - it silently ignores invalid characters rather
 * than throwing, unlike .NET's Convert.FromBase64String - so isBase64 must be checked explicitly
 * before trusting a caller-supplied string is well-formed. Encoding/decoding themselves need no
 * dedicated wrapper: Buffer.from(data).toString('base64') and Buffer.from(base64, 'base64') are
 * already the idiomatic, correctly-behaved Node equivalents once validity is confirmed.
 */

const BASE64_PATTERN = /^[A-Za-z0-9+/]*={0,2}$/;

/** True if every char in base64 is valid, correctly-padded base64 text. */
export function isBase64(base64: string): boolean {
  if (base64.length === 0) {
    return true;
  }
  if (base64.length % 4 !== 0) {
    return false;
  }
  return BASE64_PATTERN.test(base64);
}

/**
 * Computes the decoded binary length for a base64-encoded string, without decoding it.
 *
 * @throws {Error} base64's length is not a multiple of 4
 */
export function getBinaryLength(base64: string): number {
  if (base64.length === 0) {
    return 0;
  }
  if (base64.length % 4 !== 0) {
    throw new Error('Base64 input length must be a multiple of 4.');
  }

  let padding = 0;
  if (base64.endsWith('==')) {
    padding = 2;
  } else if (base64.endsWith('=')) {
    padding = 1;
  }

  return (base64.length / 4) * 3 - padding;
}

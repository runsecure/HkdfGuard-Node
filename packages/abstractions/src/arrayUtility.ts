/**
 * Port of HkdfGuard.Abstractions/ArrayUtility.cs (the byte-buffer members only - Buffer covers
 * both the byte and char cases the C# original splits into overloads, since Node has no separate
 * mutable "char buffer" type).
 */

/** True if data is empty, or every byte in it is zero. */
export function isNullOrEmpty(data: Buffer): boolean {
  return data.every((byte) => byte === 0);
}

/** Overwrites every byte of data with zero, in place. */
export function zeroMemory(data: Buffer): void {
  data.fill(0);
}

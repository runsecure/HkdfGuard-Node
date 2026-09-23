/** Port of HkdfGuard.Abstractions/KeyTrackingValue.cs. */
export interface KeyTrackingValue {
  readonly keyVersion: number;
  readonly value: Buffer;
}

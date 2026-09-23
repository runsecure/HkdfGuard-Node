import { describe, expect, it } from 'vitest';
import { DummyKeyWrapper } from './dummyKeyWrapper.js';

describe('DummyKeyWrapper', () => {
  it('encrypt returns zero', () => {
    expect(new DummyKeyWrapper().encrypt(Buffer.alloc(32), Buffer.alloc(64))).toBe(0);
  });

  it('decrypt returns zero', () => {
    expect(new DummyKeyWrapper().decrypt(Buffer.alloc(32), Buffer.alloc(32))).toBe(0);
  });

  it('generateAndWrap returns zero', () => {
    expect(new DummyKeyWrapper().generateAndWrap(Buffer.alloc(32))).toBe(0);
  });
});

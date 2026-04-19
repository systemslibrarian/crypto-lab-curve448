import { describe, expect, it } from 'vitest';
import {
  bigIntToBytes,
  bytesToBigInt,
  bytesToHex,
  clampX448Scalar,
  CURVE448,
  hexToBytes,
} from '../src/params';

describe('params utils', () => {
  it('round-trips bigint <-> fixed length bytes', () => {
    const value = 123456789n;
    const encoded = bigIntToBytes(value, 56);
    const decoded = bytesToBigInt(encoded);
    expect(decoded).toBe(value);
  });

  it('clamps x448 scalar correctly', () => {
    const allFf = new Uint8Array(CURVE448.privateKeyBytes).fill(0xff);
    const clamped = clampX448Scalar(allFf);

    expect(clamped[0] & 0b11).toBe(0);
    expect((clamped[clamped.length - 1] & 0b10000000) >>> 7).toBe(1);
  });

  it('round-trips hex', () => {
    const bytes = new Uint8Array([0, 1, 2, 253, 254, 255, 16, 32, 48]);
    const hex = bytesToHex(bytes);
    const decoded = hexToBytes(hex);
    expect(decoded).toEqual(bytes);
  });
});

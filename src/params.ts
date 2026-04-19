/**
 * Curve448 parameters per RFC 7748 Section 4.2.
 */
export const CURVE448 = {
  /** p = 2^448 - 2^224 - 1 (Goldilocks prime) */
  p: 2n ** 448n - 2n ** 224n - 1n,

  /** A coefficient in Montgomery form y^2 = x^3 + Ax^2 + x */
  A: 156326n,

  /** Base point u-coordinate for X448 */
  u: 5n,

  /** Cofactor */
  cofactor: 4n,

  /** Subgroup order (prime, per RFC 7748) */
  order: 2n ** 446n - 0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0dn,

  /** Private key size (bytes) */
  privateKeyBytes: 56,

  /** Public key size (bytes) */
  publicKeyBytes: 56,

  /** Signature size for Ed448 (bytes) */
  signatureBytes: 114,
} as const;

/**
 * Convert a little-endian byte array to BigInt.
 */
export function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

/**
 * Convert a BigInt to little-endian bytes of fixed length.
 */
export function bigIntToBytes(n: bigint, length: number): Uint8Array {
  if (length <= 0) throw new Error('Length must be positive');
  if (n < 0n) throw new Error('Cannot encode negative bigint');

  const out = new Uint8Array(length);
  let value = n;
  for (let i = 0; i < length; i += 1) {
    out[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  if (value !== 0n) {
    throw new Error('BigInt does not fit in the requested length');
  }
  return out;
}

/**
 * X448 scalar clamping per RFC 7748 Section 5.
 */
export function clampX448Scalar(scalar: Uint8Array): Uint8Array {
  if (scalar.length !== CURVE448.privateKeyBytes) {
    throw new Error(`X448 scalar must be ${CURVE448.privateKeyBytes} bytes`);
  }

  const out = new Uint8Array(scalar);
  out[0] &= 0b11111100;
  out[out.length - 1] |= 0b10000000;
  return out;
}

/**
 * Decode a hexadecimal string to bytes.
 */
export function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.trim().toLowerCase().replace(/^0x/, '').replace(/\s+/g, '');
  if (normalized.length === 0) return new Uint8Array();
  if (normalized.length % 2 !== 0) {
    throw new Error('Hex string must have an even number of characters');
  }
  if (!/^[0-9a-f]+$/.test(normalized)) {
    throw new Error('Hex string contains invalid characters');
  }

  const out = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < normalized.length; i += 2) {
    out[i / 2] = Number.parseInt(normalized.slice(i, i + 2), 16);
  }
  return out;
}

/**
 * Encode bytes as a lowercase hexadecimal string.
 */
export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) {
    out += b.toString(16).padStart(2, '0');
  }
  return out;
}

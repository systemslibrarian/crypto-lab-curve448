import { describe, expect, it } from 'vitest';
import { sha512Split, shake256Split } from '../src/hashdemo';

describe('hashdemo (seed -> hash -> scalar/nonce split)', () => {
  it('SHA-512 produces a fixed 64-byte digest split 32/32', () => {
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const split = sha512Split(seed);

    expect(split.algo).toBe('SHA-512');
    expect(split.fixedOutput).toBe(true);
    expect(split.digestLen).toBe(64);
    expect(split.scalarHalf).toHaveLength(32);
    expect(split.prefixHalf).toHaveLength(32);
  });

  it('SHAKE256 (XOF) squeezes to Ed448 length 114, split 57/57', () => {
    const seed = crypto.getRandomValues(new Uint8Array(57));
    const split = shake256Split(seed, 114);

    expect(split.algo).toBe('SHAKE256');
    expect(split.fixedOutput).toBe(false);
    expect(split.digestLen).toBe(114);
    expect(split.scalarHalf).toHaveLength(57);
    expect(split.prefixHalf).toHaveLength(57);
  });

  it('SHAKE256 is extendable: a longer squeeze is a prefix-superset of a shorter one', () => {
    const seed = crypto.getRandomValues(new Uint8Array(57));
    const short = shake256Split(seed, 64);
    const long = shake256Split(seed, 114);
    // The XOF property: the first N bytes are identical regardless of how far
    // you squeeze. This is exactly why SHAKE256 can serve Ed448's larger need.
    for (let i = 0; i < 64; i += 1) {
      expect(long.digest[i]).toBe(short.digest[i]);
    }
  });
});

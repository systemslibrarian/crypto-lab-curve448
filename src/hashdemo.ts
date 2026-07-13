import { sha512 } from '@noble/hashes/sha2.js';
import { shake256 } from '@noble/hashes/sha3.js';

/**
 * Observable comparison of the two EdDSA hash regimes.
 *
 * EdDSA derives both the secret scalar and the per-signature nonce prefix by
 * hashing the private seed once and splitting the digest in half:
 *
 *   - Ed25519 (RFC 8032 §5.1.5) hashes the 32-byte seed with SHA-512 (a
 *     FIXED 64-byte output). Bytes 0..31 -> clamped scalar, bytes 32..63 -> prefix.
 *   - Ed448  (RFC 8032 §5.2.5) hashes the 57-byte seed with SHAKE256, an
 *     eXtendable-Output Function. It is squeezed to 114 bytes (2 * 57).
 *     Bytes 0..56 -> pruned scalar, bytes 57..113 -> prefix.
 *
 * SHA-512 cannot produce 114 bytes: its output length is fixed. SHAKE256 can be
 * squeezed to *any* length, which is exactly why Ed448's larger field needs it.
 * These are the real hashes — nothing here is faked. We deliberately do NOT run
 * the field reduction that turns these bytes into the final curve scalar; the
 * point is to show the raw hash split that the higher-level `sign` uses.
 */

export interface HashSplit {
  algo: string;
  seedLen: number;
  digestLen: number;
  fixedOutput: boolean;
  digest: Uint8Array;
  scalarHalf: Uint8Array;
  prefixHalf: Uint8Array;
}

/** Ed25519 regime: SHA-512 over a 32-byte seed, split 32 / 32. */
export function sha512Split(seed: Uint8Array): HashSplit {
  const digest = sha512(seed); // always 64 bytes — length is not a parameter
  return {
    algo: 'SHA-512',
    seedLen: seed.length,
    digestLen: digest.length,
    fixedOutput: true,
    digest,
    scalarHalf: digest.slice(0, 32),
    prefixHalf: digest.slice(32),
  };
}

/**
 * Ed448 regime: SHAKE256 over a 57-byte seed, squeezed to `outLen` bytes
 * (114 for Ed448) and split in half. `outLen` is a real parameter of the XOF —
 * ask for more, get more, from the same sponge state.
 */
export function shake256Split(seed: Uint8Array, outLen = 114): HashSplit {
  const digest = shake256(seed, { dkLen: outLen });
  const half = outLen / 2;
  return {
    algo: 'SHAKE256',
    seedLen: seed.length,
    digestLen: digest.length,
    fixedOutput: false,
    digest,
    scalarHalf: digest.slice(0, half),
    prefixHalf: digest.slice(half),
  };
}

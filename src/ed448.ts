import { ed448 as nobleEd448 } from '@noble/curves/ed448.js';

export interface Ed448KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

const PRIVATE_KEY_BYTES = 57;
const PUBLIC_KEY_BYTES = 57;
const SIGNATURE_BYTES = 114;

function assertLength(name: string, bytes: Uint8Array, expected: number): void {
  if (bytes.length !== expected) {
    throw new Error(`${name} must be ${expected} bytes`);
  }
}

export function generateKeyPair(): Ed448KeyPair {
  const privateKey = crypto.getRandomValues(new Uint8Array(PRIVATE_KEY_BYTES));
  const publicKey = nobleEd448.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

export function sign(
  message: Uint8Array,
  privateKey: Uint8Array,
  context?: Uint8Array,
): Uint8Array {
  assertLength('Ed448 private key (seed)', privateKey, PRIVATE_KEY_BYTES);
  return context
    ? nobleEd448.sign(message, privateKey, { context })
    : nobleEd448.sign(message, privateKey);
}

export function verify(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
  context?: Uint8Array,
): boolean {
  assertLength('Ed448 signature', signature, SIGNATURE_BYTES);
  assertLength('Ed448 public key', publicKey, PUBLIC_KEY_BYTES);
  return context
    ? nobleEd448.verify(signature, message, publicKey, { context })
    : nobleEd448.verify(signature, message, publicKey);
}

export function tamperSignature(sig: Uint8Array): Uint8Array {
  if (sig.length === 0) {
    throw new Error('Signature cannot be empty');
  }
  const out = new Uint8Array(sig);
  out[0] ^= 0x01;
  return out;
}

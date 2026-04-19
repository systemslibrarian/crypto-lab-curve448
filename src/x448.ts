import { x448 as nobleX448 } from '@noble/curves/ed448.js';
import { clampX448Scalar, CURVE448 } from './params';

export interface X448KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

function decodeScalar(input: Uint8Array): Uint8Array {
  if (input.length !== CURVE448.privateKeyBytes) {
    throw new Error(`X448 scalar must be ${CURVE448.privateKeyBytes} bytes`);
  }
  return clampX448Scalar(input);
}

function decodeUCoordinate(input: Uint8Array): Uint8Array {
  if (input.length !== CURVE448.publicKeyBytes) {
    throw new Error(`X448 u-coordinate must be ${CURVE448.publicKeyBytes} bytes`);
  }
  return new Uint8Array(input);
}

export function generateKeyPair(): X448KeyPair {
  const raw = crypto.getRandomValues(new Uint8Array(CURVE448.privateKeyBytes));
  const privateKey = decodeScalar(raw);
  const publicKey = nobleX448.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

export function computeSharedSecret(
  myPrivateKey: Uint8Array,
  theirPublicKey: Uint8Array,
): Uint8Array {
  const scalar = decodeScalar(myPrivateKey);
  const uCoordinate = decodeUCoordinate(theirPublicKey);
  return nobleX448.getSharedSecret(scalar, uCoordinate);
}

export interface DHHandshake {
  alice: X448KeyPair;
  bob: X448KeyPair;
  aliceComputedShared: Uint8Array;
  bobComputedShared: Uint8Array;
  secretsMatch: boolean;
}

export function simulateHandshake(): DHHandshake {
  const alice = generateKeyPair();
  const bob = generateKeyPair();

  const aliceComputedShared = computeSharedSecret(alice.privateKey, bob.publicKey);
  const bobComputedShared = computeSharedSecret(bob.privateKey, alice.publicKey);
  const secretsMatch =
    aliceComputedShared.length === bobComputedShared.length &&
    aliceComputedShared.every((v, i) => v === bobComputedShared[i]);

  return {
    alice,
    bob,
    aliceComputedShared,
    bobComputedShared,
    secretsMatch,
  };
}

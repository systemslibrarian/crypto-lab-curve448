import { describe, expect, it } from 'vitest';
import { bytesToHex, clampX448Scalar, CURVE448, hexToBytes } from '../src/params';
import { computeSharedSecret, generateKeyPair, simulateHandshake } from '../src/x448';

describe('x448', () => {
  it('generates 56-byte private/public keypair with clamping', () => {
    const kp = generateKeyPair();
    expect(kp.privateKey).toHaveLength(56);
    expect(kp.publicKey).toHaveLength(56);

    const clamped = clampX448Scalar(kp.privateKey);
    expect(kp.privateKey).toEqual(clamped);
  });

  it('alice and bob derive the same shared secret', () => {
    const h = simulateHandshake();
    expect(h.aliceComputedShared).toEqual(h.bobComputedShared);
    expect(h.secretsMatch).toBe(true);
  });

  it('passes RFC 7748 section 5.2 test vector', () => {
    const scalar = hexToBytes(
      '3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121'
        + '700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3',
    );
    const u = hexToBytes(
      '06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9'
        + '814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086',
    );
    const expected =
      'ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaad'
      + 'eb445fc66a01b0779d98223961111e21766282f73dd96b6f';

    const out = computeSharedSecret(scalar, u);

    expect(bytesToHex(out)).toBe(expected);
  });

  it('shared secret remains 56 bytes', () => {
    const alice = generateKeyPair();
    const bob = generateKeyPair();
    const shared = computeSharedSecret(alice.privateKey, bob.publicKey);
    expect(shared).toHaveLength(CURVE448.publicKeyBytes);
  });
});

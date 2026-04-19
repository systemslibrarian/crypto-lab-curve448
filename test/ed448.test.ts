import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes } from '../src/params';
import { generateKeyPair, sign, tamperSignature, verify } from '../src/ed448';

describe('ed448', () => {
  it('generates keypair, signs, and verifies', () => {
    const msg = new TextEncoder().encode('Hello, Ed448');
    const kp = generateKeyPair();
    const sig = sign(msg, kp.privateKey);

    expect(kp.privateKey).toHaveLength(57);
    expect(kp.publicKey).toHaveLength(57);
    expect(sig).toHaveLength(114);
    expect(verify(sig, msg, kp.publicKey)).toBe(true);
  });

  it('fails verification for tampered signature', () => {
    const msg = new TextEncoder().encode('Hello, Ed448');
    const kp = generateKeyPair();
    const sig = sign(msg, kp.privateKey);
    const tampered = tamperSignature(sig);

    expect(verify(tampered, msg, kp.publicKey)).toBe(false);
  });

  it('fails verification for tampered message', () => {
    const msg = new TextEncoder().encode('Hello, Ed448');
    const kp = generateKeyPair();
    const sig = sign(msg, kp.privateKey);

    const tamperedMsg = new Uint8Array(msg);
    tamperedMsg[0] ^= 0x01;

    expect(verify(sig, tamperedMsg, kp.publicKey)).toBe(false);
  });

  it('round-trips random messages', () => {
    const kp = generateKeyPair();
    for (let i = 1; i <= 5; i += 1) {
      const msg = crypto.getRandomValues(new Uint8Array(i * 17));
      const sig = sign(msg, kp.privateKey);
      expect(verify(sig, msg, kp.publicKey)).toBe(true);
    }
  });

  it('passes RFC 8032 section 7.4 1-octet test vector', () => {
    const privateKey = hexToBytes(
      'c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a'
      + 'fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e',
    );
    const publicKey = hexToBytes(
      '43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086'
      + '6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480',
    );
    const message = hexToBytes('03');
    const expectedSignature =
      '26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f435'
      + '2541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cb'
      + 'cee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0f'
      + 'f3348ab21aa4adafd1d234441cf807c03a00';

    const signature = sign(message, privateKey);

    expect(bytesToHex(signature)).toBe(expectedSignature);
    expect(verify(signature, message, publicKey)).toBe(true);
  });
});

# crypto-lab-curve448

## What It Is

Browser-based demo of Curve448 (X448 key exchange) and Ed448 (digital signatures) per RFC 7748 and RFC 8032. Curve448 provides 224-bit classical security, the paranoid tier for long-lived data, national security profiles, and decades-long archive protection. The app uses `@noble/curves` for audited arithmetic and implements protocol flows on top: X448 Diffie-Hellman handshake with matching shared secrets, Ed448 signatures with SHAKE256-based derivation, and side-by-side comparison against Curve25519/Ed25519. Validation includes RFC 7748 Section 5.2 and RFC 8032 Section 7.4 vectors.

## When to Use It

- Understanding why the 224-bit security tier exists and where it is justified
- Teaching the hash distinction: Ed25519 uses SHA-512 while Ed448 uses SHAKE256
- Showing trade-offs: stronger security margins come with slower operations and larger signatures
- Evaluating long-term key material (identity keys, code-signing keys, root authority keys)
- Not for ephemeral sessions or short-lived tokens where Curve25519 already fits
- Do NOT use this as production code — it is a teaching demo built on `@noble/curves`, not a hardened protocol implementation.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-curve448](https://systemslibrarian.github.io/crypto-lab-curve448/)**

Six interactive exhibits: the security-margin rationale, a live X448 Diffie-Hellman handshake (with a toggle that reveals RFC 7748 scalar clamping), Ed448 sign / verify / tamper with optional context separation, a live Curve25519-vs-Curve448 comparison with averaged in-browser benchmarks, and a "Verified Against the RFCs" panel that recomputes the RFC 7748 §5.2 and RFC 8032 §7.4 test vectors in your browser on every load. Light and dark themes are both fully supported.

## What Can Go Wrong

- Curve448 is still vulnerable to Shor's algorithm on a sufficiently large quantum computer, just like Curve25519. This is classical security, not post-quantum security.
- X448 scalar clamping is mandatory per RFC 7748. Skipping clamping can reintroduce subgroup and validation hazards.
- Ed448 uses SHAKE256, not SHA-512. Porting Ed25519 code naively to Ed448 often fails RFC vectors for this reason.
- Ed448 signatures are 114 bytes; protocols hard-coded for 64-byte signatures will break.
- Ed448 context is domain separation: same message with different contexts yields different valid signatures.

## Real-World Usage

- Curve448 was designed by Mike Hamburg at Rambus in 2014 and named Ed448-Goldilocks for the prime's balanced structure, then standardized in RFC 7748 (X448) and RFC 8032 (Ed448).
- TLS 1.3 includes X448 as an optional NamedGroup for high-security key exchange.
- OpenSSH 9+ supports high-assurance Ed448 keys, and GnuPG supports Ed448 for long-lived identity keys.
- CNSA-style high-assurance classical cryptography profiles favor Curve448 when long-horizon confidentiality or stronger classical margins are required, though most broad interoperability still centers on Curve25519.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-curve448
cd crypto-lab-curve448
npm install
npm run dev
```

## Related Demos
- [crypto-lab-curve-lens](https://systemslibrarian.github.io/crypto-lab-curve-lens/) — Curve25519 and P-256 ECDH, the curves Curve448 is benchmarked against.
- [crypto-lab-ed25519-forge](https://systemslibrarian.github.io/crypto-lab-ed25519-forge/) — Ed25519/EdDSA, the SHA-512 sibling of the Ed448 signatures here.
- [crypto-lab-key-exchange](https://systemslibrarian.github.io/crypto-lab-key-exchange/) — Diffie-Hellman, ECDH, and X25519 key agreement fundamentals.
- [crypto-lab-ssh-handshake](https://systemslibrarian.github.io/crypto-lab-ssh-handshake/) — X25519 + Ed25519 in the SSH transport, an applied use of these curves.

## Development

```bash
npm install      # install dependencies
npm run dev      # start the Vite dev server
npm test         # run the Vitest suite (crypto vectors + DOM smoke tests)
npm run build    # type-check and produce the production bundle in dist/
```

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*

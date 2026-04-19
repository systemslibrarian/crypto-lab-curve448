# crypto-lab-curve448

Browser-based Curve448 demo featuring RFC 7748 X448 key exchange and RFC 8032 Ed448 signatures.

## What It Is

Browser-based demo of Curve448 (X448 key exchange) and Ed448 (digital signatures) per RFC 7748 and RFC 8032. Curve448 provides 224-bit classical security, the paranoid tier for long-lived data, national security profiles, and decades-long archive protection. The app uses `@noble/curves` for audited arithmetic and implements protocol flows on top: X448 Diffie-Hellman handshake with matching shared secrets, Ed448 signatures with SHAKE256-based derivation, and side-by-side comparison against Curve25519/Ed25519. Validation includes RFC 7748 Section 5.2 and RFC 8032 Section 7.4 vectors.

## When to Use It

- Understanding why the 224-bit security tier exists and where it is justified
- Teaching the hash distinction: Ed25519 uses SHA-512 while Ed448 uses SHAKE256
- Showing trade-offs: stronger security margins come with slower operations and larger signatures
- Evaluating long-term key material (identity keys, code-signing keys, root authority keys)
- Not for ephemeral sessions or short-lived tokens where Curve25519 already fits

## Live Demo

https://systemslibrarian.github.io/crypto-lab-curve448/

## What Can Go Wrong

- Curve448 is still vulnerable to Shor's algorithm on a sufficiently large quantum computer, just like Curve25519. This is classical security, not post-quantum security.
- X448 scalar clamping is mandatory per RFC 7748. Skipping clamping can reintroduce subgroup and validation hazards.
- Ed448 uses SHAKE256, not SHA-512. Porting Ed25519 code naively to Ed448 often fails RFC vectors for this reason.
- Ed448 signatures are 114 bytes; protocols hard-coded for 64-byte signatures will break.
- Ed448 context is domain separation: same message with different contexts yields different valid signatures.

## Real-World Usage

Curve448 was designed by Mike Hamburg at Rambus in 2014 and named Ed448-Goldilocks for the prime's balanced structure. It was standardized in RFC 7748 (X448) and RFC 8032 (Ed448). Deployments include TLS 1.3 as optional NamedGroup X448, OpenSSH 9+ high-security Ed448 keys, GnuPG long-lived identity keys, and CNSA-style high-assurance classical cryptography profiles. Most broad interoperability still centers on Curve25519, but Curve448 is valuable when long-horizon confidentiality or stronger classical margins are required.
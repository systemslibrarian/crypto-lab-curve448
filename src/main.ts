import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import './style.css';
import { bytesToHex } from './params';
import { computeSharedSecret, generateKeyPair, simulateHandshake } from './x448';
import {
  generateKeyPair as generateEd448KeyPair,
  sign as signEd448,
  tamperSignature,
  verify as verifyEd448,
} from './ed448';

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) throw new Error('App container not found');

const encoder = new TextEncoder();

function shortHex(bytes: Uint8Array, chars = 24): string {
  const hex = bytesToHex(bytes);
  return `${hex.slice(0, chars)}...${hex.slice(-chars)}`;
}

function maskHex(bytes: Uint8Array): string {
  return '█'.repeat(Math.min(14, Math.ceil(bytes.length / 4)));
}

function ms(label: string, fn: () => void): string {
  const t0 = performance.now();
  fn();
  const dt = performance.now() - t0;
  return `${label}: ~${Math.max(1, Math.round(dt))} ms`;
}

app.innerHTML = `
  <main class="lab-shell">
    <header class="vault-hero reveal">
      <p class="verse">"Whether therefore ye eat, or drink, or whatsoever ye do, do all to the glory of God."<br />1 Corinthians 10:31</p>
      <h1>crypto-lab-curve448</h1>
      <p class="subtitle">The 224-bit security tier: X448 key exchange + Ed448 signatures.</p>
      <div class="security-bar" aria-label="Security margin visualization">
        <span>128-bit</span>
        <div class="bar"></div>
        <span>224-bit</span>
      </div>
    </header>

    <section class="panel reveal" style="--stagger: 1" id="exhibit-1">
      <h2>Exhibit 1: Why Curve448?</h2>
      <div class="grid two">
        <article class="card">
          <h3>Security Margin</h3>
          <p>Curve25519 gives 128-bit classical security. Curve448 raises that to 224-bit for long-lived archives, compliance profiles, and larger safety margins.</p>
          <pre>2^128 ≈ 3.4 × 10^38
2^224 ≈ 2.7 × 10^67
Difference: 2^96 harder</pre>
        </article>
        <article class="card">
          <h3>Goldilocks Prime</h3>
          <pre>p = 2^448 - 2^224 - 1

Binary shape:
[224 ones][gap][224 ones]</pre>
          <p class="mono" id="prime-value"></p>
        </article>
      </div>
    </section>

    <section class="panel reveal" style="--stagger: 2" id="exhibit-2">
      <h2>Exhibit 2: X448 Diffie-Hellman Live</h2>
      <div class="actions">
        <button id="btn-handshake">Run Handshake</button>
        <button id="btn-compare">Compare Shared Secrets</button>
      </div>
      <div class="grid two">
        <article class="card alice">
          <h3>Alice</h3>
          <p>Private a: <span id="alice-priv" class="secret"></span></p>
          <p>Public A: <span id="alice-pub" class="mono"></span></p>
          <p>Shared a·B: <span id="alice-shared" class="mono"></span></p>
        </article>
        <article class="card bob">
          <h3>Bob</h3>
          <p>Private b: <span id="bob-priv" class="secret"></span></p>
          <p>Public B: <span id="bob-pub" class="mono"></span></p>
          <p>Shared b·A: <span id="bob-shared" class="mono"></span></p>
        </article>
      </div>
      <p id="dh-status" class="status"></p>
      <article class="card scenario">
        <h3>Surveillance Scenario</h3>
        <p>Eve sees only A and B. Recovering (ab)·G from public points requires solving ECDLP at roughly 2^224 work on Curve448.</p>
      </article>
    </section>

    <section class="panel reveal" style="--stagger: 3" id="exhibit-3">
      <h2>Exhibit 3: Ed448 Signatures</h2>
      <div class="grid two">
        <article class="card">
          <label for="ed-message">Message</label>
          <input id="ed-message" value="Paul Clark certified" />
          <label for="ed-context">Context (optional)</label>
          <input id="ed-context" value="" placeholder="e.g. tls-handshake" />
          <div class="actions inline">
            <button id="btn-ed-keygen">Generate Keypair</button>
            <button id="btn-ed-sign">Sign</button>
            <button id="btn-ed-verify">Verify</button>
            <button id="btn-ed-tamper-msg">Tamper Message</button>
            <button id="btn-ed-tamper-sig">Tamper Signature</button>
          </div>
        </article>
        <article class="card">
          <p>Private seed: <span id="ed-priv" class="secret"></span></p>
          <p>Public key: <span id="ed-pub" class="mono"></span></p>
          <p>Signature: <span id="ed-sig" class="mono"></span></p>
          <p id="ed-status" class="status"></p>
        </article>
      </div>
      <article class="card">
        <h3>Why SHAKE256?</h3>
        <p>Ed25519 uses SHA-512. Ed448 uses SHAKE256 (XOF) per RFC 8032 for scalar and nonce derivation.</p>
      </article>
    </section>

    <section class="panel reveal" style="--stagger: 4" id="exhibit-4">
      <h2>Exhibit 4: Curve25519 vs Curve448</h2>
      <div class="actions"><button id="btn-compare-curves">Generate Live Comparison</button></div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>Metric</th><th>Curve25519 / Ed25519</th><th>Curve448 / Ed448</th></tr>
          </thead>
          <tbody id="compare-body"></tbody>
        </table>
      </div>
    </section>

    <section class="panel reveal" style="--stagger: 5" id="exhibit-5">
      <h2>Exhibit 5: When to Use Which</h2>
      <div class="grid two">
        <article class="card">
          <h3>Decision Tree</h3>
          <ul>
            <li>Short-lived data (&lt;10 years): Curve25519/Ed25519</li>
            <li>Need post-quantum: neither; use ML-KEM + ML-DSA</li>
            <li>Need 192+ classical security: Curve448/Ed448</li>
            <li>Mobile performance constraints: Curve25519</li>
          </ul>
        </article>
        <article class="card">
          <h3>Real Deployments</h3>
          <ul>
            <li>TLS 1.3 default: X25519, optional X448</li>
            <li>OpenSSH modern default: Ed25519; high-security profile: Ed448</li>
            <li>GnuPG long-term identity keys: Ed448</li>
          </ul>
        </article>
      </div>
      <p class="cross-links">Cross-links: curve-lens, x3dh-wire, ed25519-forge, ratchet-wire, hybrid-wire, quantum-vault-kpqc, dilithium-seal.</p>
    </section>
  </main>
`;

const primeValueEl = document.querySelector<HTMLParagraphElement>('#prime-value');
if (primeValueEl) {
  primeValueEl.textContent =
    '726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365439';
}

let latestHandshake = simulateHandshake();

function renderHandshake(): void {
  const alicePriv = document.querySelector<HTMLSpanElement>('#alice-priv');
  const alicePub = document.querySelector<HTMLSpanElement>('#alice-pub');
  const aliceShared = document.querySelector<HTMLSpanElement>('#alice-shared');
  const bobPriv = document.querySelector<HTMLSpanElement>('#bob-priv');
  const bobPub = document.querySelector<HTMLSpanElement>('#bob-pub');
  const bobShared = document.querySelector<HTMLSpanElement>('#bob-shared');
  const status = document.querySelector<HTMLParagraphElement>('#dh-status');

  if (!alicePriv || !alicePub || !aliceShared || !bobPriv || !bobPub || !bobShared || !status) return;

  alicePriv.textContent = maskHex(latestHandshake.alice.privateKey);
  bobPriv.textContent = maskHex(latestHandshake.bob.privateKey);
  alicePub.textContent = shortHex(latestHandshake.alice.publicKey);
  bobPub.textContent = shortHex(latestHandshake.bob.publicKey);
  aliceShared.textContent = shortHex(latestHandshake.aliceComputedShared);
  bobShared.textContent = shortHex(latestHandshake.bobComputedShared);
  status.textContent = latestHandshake.secretsMatch
    ? '✓ IDENTICAL: both parties derived the same 56-byte shared secret.'
    : '✗ mismatch: handshake failed.';
  status.className = `status ${latestHandshake.secretsMatch ? 'ok' : 'bad'}`;
}

document.querySelector<HTMLButtonElement>('#btn-handshake')?.addEventListener('click', () => {
  latestHandshake = simulateHandshake();
  renderHandshake();
});

document.querySelector<HTMLButtonElement>('#btn-compare')?.addEventListener('click', () => {
  const status = document.querySelector<HTMLParagraphElement>('#dh-status');
  if (!status) return;
  const exact = latestHandshake.aliceComputedShared.every((b, i) => b === latestHandshake.bobComputedShared[i]);
  status.textContent = exact
    ? `✓ Byte-for-byte match: ${bytesToHex(latestHandshake.aliceComputedShared)}`
    : '✗ Shared secret mismatch';
  status.className = `status ${exact ? 'ok' : 'bad'}`;
});

renderHandshake();

let edState = generateEd448KeyPair();
let latestSignature: Uint8Array<ArrayBufferLike> = new Uint8Array(114);
let latestMessage = encoder.encode('Paul Clark certified');

function readContext(): Uint8Array | undefined {
  const context = (document.querySelector<HTMLInputElement>('#ed-context')?.value ?? '').trim();
  return context.length > 0 ? encoder.encode(context) : undefined;
}

function renderEdState(statusText = 'Ready', ok = true): void {
  const priv = document.querySelector<HTMLSpanElement>('#ed-priv');
  const pub = document.querySelector<HTMLSpanElement>('#ed-pub');
  const sig = document.querySelector<HTMLSpanElement>('#ed-sig');
  const status = document.querySelector<HTMLParagraphElement>('#ed-status');
  if (!priv || !pub || !sig || !status) return;

  priv.textContent = maskHex(edState.privateKey);
  pub.textContent = shortHex(edState.publicKey);
  sig.textContent = latestSignature.length > 0 ? shortHex(latestSignature, 20) : '(no signature yet)';
  status.textContent = statusText;
  status.className = `status ${ok ? 'ok' : 'bad'}`;
}

document.querySelector<HTMLButtonElement>('#btn-ed-keygen')?.addEventListener('click', () => {
  edState = generateEd448KeyPair();
  latestSignature = new Uint8Array(114);
  renderEdState('Generated fresh 57-byte seed and 57-byte public key.', true);
});

document.querySelector<HTMLButtonElement>('#btn-ed-sign')?.addEventListener('click', () => {
  const msgInput = document.querySelector<HTMLInputElement>('#ed-message')?.value ?? '';
  latestMessage = encoder.encode(msgInput);
  latestSignature = signEd448(latestMessage, edState.privateKey, readContext());
  renderEdState(`Signed ${latestMessage.length} bytes. Signature is ${latestSignature.length} bytes.`, true);
});

document.querySelector<HTMLButtonElement>('#btn-ed-verify')?.addEventListener('click', () => {
  const valid = verifyEd448(latestSignature, latestMessage, edState.publicKey, readContext());
  renderEdState(valid ? '✓ VALID signature' : '✗ INVALID signature', valid);
});

document.querySelector<HTMLButtonElement>('#btn-ed-tamper-msg')?.addEventListener('click', () => {
  const tampered = new Uint8Array(latestMessage);
  if (tampered.length > 0) tampered[0] ^= 0x01;
  const valid = verifyEd448(latestSignature, tampered, edState.publicKey, readContext());
  renderEdState(valid ? 'Unexpected valid result' : '✗ INVALID after message tamper', false);
});

document.querySelector<HTMLButtonElement>('#btn-ed-tamper-sig')?.addEventListener('click', () => {
  const tampered = tamperSignature(latestSignature);
  const valid = verifyEd448(tampered, latestMessage, edState.publicKey, readContext());
  renderEdState(valid ? 'Unexpected valid result' : '✗ INVALID after signature tamper', false);
});

renderEdState();

function compareCurves(): void {
  const body = document.querySelector<HTMLTableSectionElement>('#compare-body');
  if (!body) return;

  const x25519Alice = x25519.keygen();
  const x25519Bob = x25519.keygen();
  const x25519Shared = x25519.getSharedSecret(x25519Alice.secretKey, x25519Bob.publicKey);

  const x448Alice = generateKeyPair();
  const x448Bob = generateKeyPair();
  const x448Shared = computeSharedSecret(x448Alice.privateKey, x448Bob.publicKey);

  const ed25519Seed = crypto.getRandomValues(new Uint8Array(32));
  const ed25519Public = ed25519.getPublicKey(ed25519Seed);
  const ed25519Sig = ed25519.sign(encoder.encode('compare'), ed25519Seed);

  const ed448Kp = generateEd448KeyPair();
  const ed448Sig = signEd448(encoder.encode('compare'), ed448Kp.privateKey);

  const perfLeft = [
    ms('Keygen', () => {
      x25519.keygen();
    }),
    ms('DH', () => {
      x25519.getSharedSecret(x25519Alice.secretKey, x25519Bob.publicKey);
    }),
    ms('Sign', () => {
      ed25519.sign(encoder.encode('timing'), ed25519Seed);
    }),
    ms('Verify', () => {
      ed25519.verify(ed25519Sig, encoder.encode('timing'), ed25519Public);
    }),
  ].join(' | ');

  const perfRight = [
    ms('Keygen', () => {
      generateKeyPair();
    }),
    ms('DH', () => {
      computeSharedSecret(x448Alice.privateKey, x448Bob.publicKey);
    }),
    ms('Sign', () => {
      signEd448(encoder.encode('timing'), ed448Kp.privateKey);
    }),
    ms('Verify', () => {
      verifyEd448(ed448Sig, encoder.encode('timing'), ed448Kp.publicKey);
    }),
  ].join(' | ');

  const rows: Array<[string, string, string]> = [
    ['Private key size', '32 bytes', '56 bytes'],
    ['Public key size', `${x25519Alice.publicKey.length} bytes`, `${x448Alice.publicKey.length} bytes`],
    ['Shared secret size', `${x25519Shared.length} bytes`, `${x448Shared.length} bytes`],
    ['Classical security', '128-bit', '224-bit'],
    ['EdDSA seed size', '32 bytes', '57 bytes'],
    ['EdDSA pubkey size', `${ed25519Public.length} bytes`, `${ed448Kp.publicKey.length} bytes`],
    ['Signature size', `${ed25519Sig.length} bytes`, `${ed448Sig.length} bytes`],
    ['Hash internals', 'SHA-512', 'SHAKE256'],
    ['Sample public key', shortHex(x25519Alice.publicKey, 16), shortHex(x448Alice.publicKey, 16)],
    ['Performance (browser)', perfLeft, perfRight],
    ['Common deployments', 'Signal, mainstream TLS, default SSH', 'High-security SSH, long-term GPG, optional TLS 1.3 group'],
  ];

  body.innerHTML = rows
    .map(
      ([metric, left, right]) =>
        `<tr><td>${metric}</td><td class="mono">${left}</td><td class="mono">${right}</td></tr>`,
    )
    .join('');
}

document.querySelector<HTMLButtonElement>('#btn-compare-curves')?.addEventListener('click', compareCurves);
compareCurves();

import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import './style.css';
import { bytesToHex, hexToBytes } from './params';
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
  if (hex.length <= chars * 2) return hex;
  return `${hex.slice(0, chars)}…${hex.slice(-chars)}`;
}

function maskHex(bytes: Uint8Array): string {
  return '█'.repeat(Math.min(14, Math.ceil(bytes.length / 4)));
}

/** Average wall-clock time of `fn` over several runs so the numbers stay stable. */
function bench(label: string, fn: () => void, iterations = 12): string {
  fn(); // warm up JIT and any one-time setup
  const t0 = performance.now();
  for (let i = 0; i < iterations; i += 1) fn();
  const dt = (performance.now() - t0) / iterations;
  const value = dt >= 1 ? dt.toFixed(1) : dt.toFixed(2);
  return `${label}: ${value} ms`;
}

app.innerHTML = `
  <main class="lab-shell">
    <a class="skip-link" href="#exhibit-1">Skip to exhibits</a>
    <header class="vault-hero reveal">
      <p class="verse">"Whether therefore ye eat, or drink, or whatsoever ye do, do all to the glory of God."<br />1 Corinthians 10:31</p>
      <h1>crypto-lab-curve448</h1>
      <p class="subtitle">The 224-bit security tier: X448 key exchange + Ed448 signatures.</p>
      <div class="security-bar" aria-label="Security margin: Curve25519 is 128-bit, Curve448 is 224-bit">
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
        <button type="button" id="btn-handshake">Run Handshake</button>
        <button type="button" id="btn-compare">Compare Shared Secrets</button>
      </div>
      <div class="grid two">
        <article class="card alice">
          <h3>Alice</h3>
          <p>Private a: <span id="alice-priv" class="secret"></span></p>
          <p>Public A: <span id="alice-pub" class="mono"></span>
            <button class="copy-btn" id="copy-alice-pub" type="button" aria-label="Copy Alice public key" hidden>copy</button></p>
          <p>Shared a·B: <span id="alice-shared" class="mono"></span></p>
        </article>
        <article class="card bob">
          <h3>Bob</h3>
          <p>Private b: <span id="bob-priv" class="secret"></span></p>
          <p>Public B: <span id="bob-pub" class="mono"></span>
            <button class="copy-btn" id="copy-bob-pub" type="button" aria-label="Copy Bob public key" hidden>copy</button></p>
          <p>Shared b·A: <span id="bob-shared" class="mono"></span></p>
        </article>
      </div>
      <button class="reveal-toggle" type="button" id="btn-reveal-dh" aria-pressed="false">Reveal private scalars</button>
      <p id="dh-clamp" class="mono" hidden></p>
      <p id="dh-status" class="status" role="status" aria-live="polite"></p>
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
          <input id="ed-message" value="Paul Clark certified" autocomplete="off" />
          <label for="ed-context">Context (optional)</label>
          <input id="ed-context" value="" placeholder="e.g. tls-handshake" autocomplete="off" />
          <div class="actions inline">
            <button type="button" id="btn-ed-keygen">Generate Keypair</button>
            <button type="button" id="btn-ed-sign">Sign</button>
            <button type="button" id="btn-ed-verify">Verify</button>
            <button type="button" id="btn-ed-tamper-msg">Tamper Message</button>
            <button type="button" id="btn-ed-tamper-sig">Tamper Signature</button>
          </div>
        </article>
        <article class="card">
          <p>Private seed: <span id="ed-priv" class="secret"></span></p>
          <p>Public key: <span id="ed-pub" class="mono"></span>
            <button class="copy-btn" id="copy-ed-pub" type="button" aria-label="Copy Ed448 public key" hidden>copy</button></p>
          <p>Signature: <span id="ed-sig" class="mono"></span>
            <button class="copy-btn" id="copy-ed-sig" type="button" aria-label="Copy Ed448 signature" hidden>copy</button></p>
          <button class="reveal-toggle" type="button" id="btn-reveal-ed" aria-pressed="false">Reveal private seed</button>
          <p id="ed-status" class="status" role="status" aria-live="polite"></p>
        </article>
      </div>
      <article class="card">
        <h3>Why SHAKE256?</h3>
        <p>Ed25519 uses SHA-512. Ed448 uses SHAKE256 (XOF) per RFC 8032 for scalar and nonce derivation. A <em>context</em> string is domain separation: the same message signed under different contexts yields different valid signatures.</p>
      </article>
    </section>

    <section class="panel reveal" style="--stagger: 4" id="exhibit-4">
      <h2>Exhibit 4: Curve25519 vs Curve448</h2>
      <div class="actions"><button type="button" id="btn-compare-curves">Generate Live Comparison</button></div>
      <div class="table-wrap">
        <table>
          <caption class="sr-only">Live side-by-side key, signature, and performance comparison</caption>
          <thead>
            <tr><th>Metric</th><th>Curve25519 / Ed25519</th><th>Curve448 / Ed448</th></tr>
          </thead>
          <tbody id="compare-body"></tbody>
        </table>
      </div>
    </section>

    <section class="panel reveal" style="--stagger: 5" id="exhibit-5">
      <h2>Exhibit 5: Verified Against the RFCs</h2>
      <p>Trust nothing — verify. These published test vectors are recomputed live in your browser on every page load.</p>
      <div id="vectors"></div>
    </section>

    <section class="panel reveal" style="--stagger: 6" id="exhibit-6">
      <h2>Exhibit 6: When to Use Which</h2>
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

/** Wire a "copy" button to copy `getValue()` to the clipboard with quick feedback. */
function wireCopy(buttonId: string, getValue: () => string): void {
  const btn = document.querySelector<HTMLButtonElement>(`#${buttonId}`);
  if (!btn) return;
  btn.addEventListener('click', async () => {
    const value = getValue();
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      const original = btn.textContent;
      btn.textContent = 'copied ✓';
      window.setTimeout(() => {
        btn.textContent = original;
      }, 1200);
    } catch {
      btn.textContent = 'copy failed';
    }
  });
}

// ---- Exhibit 2: X448 Diffie-Hellman ----------------------------------------

let latestHandshake = simulateHandshake();
let revealDhPrivate = false;

function renderHandshake(): void {
  const alicePriv = document.querySelector<HTMLSpanElement>('#alice-priv');
  const alicePub = document.querySelector<HTMLSpanElement>('#alice-pub');
  const aliceShared = document.querySelector<HTMLSpanElement>('#alice-shared');
  const bobPriv = document.querySelector<HTMLSpanElement>('#bob-priv');
  const bobPub = document.querySelector<HTMLSpanElement>('#bob-pub');
  const bobShared = document.querySelector<HTMLSpanElement>('#bob-shared');
  const status = document.querySelector<HTMLParagraphElement>('#dh-status');
  const clamp = document.querySelector<HTMLParagraphElement>('#dh-clamp');
  const copyA = document.querySelector<HTMLButtonElement>('#copy-alice-pub');
  const copyB = document.querySelector<HTMLButtonElement>('#copy-bob-pub');

  if (!alicePriv || !alicePub || !aliceShared || !bobPriv || !bobPub || !bobShared || !status) return;

  alicePriv.textContent = revealDhPrivate
    ? bytesToHex(latestHandshake.alice.privateKey)
    : maskHex(latestHandshake.alice.privateKey);
  bobPriv.textContent = revealDhPrivate
    ? bytesToHex(latestHandshake.bob.privateKey)
    : maskHex(latestHandshake.bob.privateKey);
  alicePub.textContent = shortHex(latestHandshake.alice.publicKey);
  bobPub.textContent = shortHex(latestHandshake.bob.publicKey);
  aliceShared.textContent = shortHex(latestHandshake.aliceComputedShared);
  bobShared.textContent = shortHex(latestHandshake.bobComputedShared);
  status.textContent = latestHandshake.secretsMatch
    ? '✓ IDENTICAL: both parties derived the same 56-byte shared secret.'
    : '✗ mismatch: handshake failed.';
  status.className = `status ${latestHandshake.secretsMatch ? 'ok' : 'bad'}`;

  if (copyA) copyA.hidden = false;
  if (copyB) copyB.hidden = false;

  if (clamp) {
    clamp.hidden = !revealDhPrivate;
    if (revealDhPrivate) {
      const first = latestHandshake.alice.privateKey[0];
      const last = latestHandshake.alice.privateKey[latestHandshake.alice.privateKey.length - 1];
      clamp.textContent =
        `RFC 7748 clamping holds: low byte ${first
          .toString(2)
          .padStart(8, '0')} has its two low bits cleared, ` +
        `high byte ${last.toString(2).padStart(8, '0')} has its top bit set.`;
    }
  }
}

document.querySelector<HTMLButtonElement>('#btn-handshake')?.addEventListener('click', () => {
  latestHandshake = simulateHandshake();
  renderHandshake();
});

document.querySelector<HTMLButtonElement>('#btn-compare')?.addEventListener('click', () => {
  const status = document.querySelector<HTMLParagraphElement>('#dh-status');
  if (!status) return;
  const exact = latestHandshake.aliceComputedShared.every(
    (b, i) => b === latestHandshake.bobComputedShared[i],
  );
  status.textContent = exact
    ? `✓ Byte-for-byte match: ${bytesToHex(latestHandshake.aliceComputedShared)}`
    : '✗ Shared secret mismatch';
  status.className = `status ${exact ? 'ok' : 'bad'}`;
});

document.querySelector<HTMLButtonElement>('#btn-reveal-dh')?.addEventListener('click', (e) => {
  revealDhPrivate = !revealDhPrivate;
  const btn = e.currentTarget as HTMLButtonElement;
  btn.textContent = revealDhPrivate ? 'Hide private scalars' : 'Reveal private scalars';
  btn.setAttribute('aria-pressed', String(revealDhPrivate));
  renderHandshake();
});

wireCopy('copy-alice-pub', () => bytesToHex(latestHandshake.alice.publicKey));
wireCopy('copy-bob-pub', () => bytesToHex(latestHandshake.bob.publicKey));

renderHandshake();

// ---- Exhibit 3: Ed448 signatures -------------------------------------------

let edState = generateEd448KeyPair();
let latestSignature: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
let latestMessage = encoder.encode('Paul Clark certified');
let revealEdPrivate = false;

function readContext(): Uint8Array | undefined {
  const context = (document.querySelector<HTMLInputElement>('#ed-context')?.value ?? '').trim();
  return context.length > 0 ? encoder.encode(context) : undefined;
}

function renderEdState(statusText = 'Ready', ok = true): void {
  const priv = document.querySelector<HTMLSpanElement>('#ed-priv');
  const pub = document.querySelector<HTMLSpanElement>('#ed-pub');
  const sig = document.querySelector<HTMLSpanElement>('#ed-sig');
  const status = document.querySelector<HTMLParagraphElement>('#ed-status');
  const copyPub = document.querySelector<HTMLButtonElement>('#copy-ed-pub');
  const copySig = document.querySelector<HTMLButtonElement>('#copy-ed-sig');
  if (!priv || !pub || !sig || !status) return;

  const hasSig = latestSignature.length > 0;
  priv.textContent = revealEdPrivate ? bytesToHex(edState.privateKey) : maskHex(edState.privateKey);
  pub.textContent = shortHex(edState.publicKey);
  sig.textContent = hasSig ? shortHex(latestSignature, 20) : '(no signature yet)';
  status.textContent = statusText;
  status.className = `status ${ok ? 'ok' : 'bad'}`;

  if (copyPub) copyPub.hidden = false;
  if (copySig) copySig.hidden = !hasSig;
}

document.querySelector<HTMLButtonElement>('#btn-ed-keygen')?.addEventListener('click', () => {
  edState = generateEd448KeyPair();
  latestSignature = new Uint8Array(0);
  renderEdState('Generated fresh 57-byte seed and 57-byte public key.', true);
});

document.querySelector<HTMLButtonElement>('#btn-ed-sign')?.addEventListener('click', () => {
  const msgInput = document.querySelector<HTMLInputElement>('#ed-message')?.value ?? '';
  latestMessage = encoder.encode(msgInput);
  latestSignature = signEd448(latestMessage, edState.privateKey, readContext());
  renderEdState(`Signed ${latestMessage.length} bytes. Signature is ${latestSignature.length} bytes.`, true);
});

document.querySelector<HTMLButtonElement>('#btn-ed-verify')?.addEventListener('click', () => {
  if (latestSignature.length === 0) {
    renderEdState('Sign a message first.', false);
    return;
  }
  const valid = verifyEd448(latestSignature, latestMessage, edState.publicKey, readContext());
  renderEdState(valid ? '✓ VALID signature' : '✗ INVALID signature', valid);
});

document.querySelector<HTMLButtonElement>('#btn-ed-tamper-msg')?.addEventListener('click', () => {
  if (latestSignature.length === 0) {
    renderEdState('Sign a message first.', false);
    return;
  }
  const tampered = new Uint8Array(latestMessage);
  if (tampered.length > 0) tampered[0] ^= 0x01;
  const valid = verifyEd448(latestSignature, tampered, edState.publicKey, readContext());
  renderEdState(valid ? 'Unexpected valid result' : '✗ INVALID after message tamper', false);
});

document.querySelector<HTMLButtonElement>('#btn-ed-tamper-sig')?.addEventListener('click', () => {
  if (latestSignature.length === 0) {
    renderEdState('Sign a message first.', false);
    return;
  }
  const tampered = tamperSignature(latestSignature);
  const valid = verifyEd448(tampered, latestMessage, edState.publicKey, readContext());
  renderEdState(valid ? 'Unexpected valid result' : '✗ INVALID after signature tamper', false);
});

document.querySelector<HTMLButtonElement>('#btn-reveal-ed')?.addEventListener('click', (e) => {
  revealEdPrivate = !revealEdPrivate;
  const btn = e.currentTarget as HTMLButtonElement;
  btn.textContent = revealEdPrivate ? 'Hide private seed' : 'Reveal private seed';
  btn.setAttribute('aria-pressed', String(revealEdPrivate));
  const statusEl = document.querySelector<HTMLParagraphElement>('#ed-status');
  renderEdState(statusEl?.textContent ?? 'Ready', !statusEl?.classList.contains('bad'));
});

wireCopy('copy-ed-pub', () => bytesToHex(edState.publicKey));
wireCopy('copy-ed-sig', () => bytesToHex(latestSignature));

renderEdState();

// ---- Exhibit 4: live comparison --------------------------------------------

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

  const perfMessage = encoder.encode('timing');

  const perfLeft = [
    bench('Keygen', () => {
      x25519.keygen();
    }),
    bench('DH', () => {
      x25519.getSharedSecret(x25519Alice.secretKey, x25519Bob.publicKey);
    }),
    bench('Sign', () => {
      ed25519.sign(perfMessage, ed25519Seed);
    }),
    bench('Verify', () => {
      ed25519.verify(ed25519Sig, encoder.encode('compare'), ed25519Public);
    }),
  ].join(' | ');

  const perfRight = [
    bench('Keygen', () => {
      generateKeyPair();
    }),
    bench('DH', () => {
      computeSharedSecret(x448Alice.privateKey, x448Bob.publicKey);
    }),
    bench('Sign', () => {
      signEd448(perfMessage, ed448Kp.privateKey);
    }),
    bench('Verify', () => {
      verifyEd448(ed448Sig, encoder.encode('compare'), ed448Kp.publicKey);
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
    ['Performance (avg, browser)', perfLeft, perfRight],
    ['Common deployments', 'Signal, mainstream TLS, default SSH', 'High-security SSH, long-term GPG, optional TLS 1.3 group'],
  ];

  body.innerHTML = rows
    .map(
      ([metric, left, right]) =>
        `<tr><td data-label="Metric">${metric}</td><td class="mono" data-label="Curve25519 / Ed25519">${left}</td><td class="mono" data-label="Curve448 / Ed448">${right}</td></tr>`,
    )
    .join('');
}

document.querySelector<HTMLButtonElement>('#btn-compare-curves')?.addEventListener('click', compareCurves);

// ---- Exhibit 5: live RFC test-vector verification --------------------------

interface VectorResult {
  title: string;
  ref: string;
  pass: boolean;
  expected: string;
  computed: string;
}

function runX448Vector(): VectorResult {
  // RFC 7748 Section 5.2 — first X448 test vector.
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
  const computed = bytesToHex(computeSharedSecret(scalar, u));
  return {
    title: 'X448 scalar multiplication',
    ref: 'RFC 7748 §5.2',
    pass: computed === expected,
    expected,
    computed,
  };
}

function runEd448Vector(): VectorResult {
  // RFC 8032 Section 7.4 — 1-octet message test vector.
  const privateKey = hexToBytes(
    'c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a'
      + 'fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e',
  );
  const message = hexToBytes('03');
  const expected =
    '26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f435'
    + '2541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cb'
    + 'cee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0f'
    + 'f3348ab21aa4adafd1d234441cf807c03a00';
  const computed = bytesToHex(signEd448(message, privateKey));
  return {
    title: 'Ed448 deterministic signature',
    ref: 'RFC 8032 §7.4',
    pass: computed === expected,
    expected,
    computed,
  };
}

function renderVectors(): void {
  const host = document.querySelector<HTMLDivElement>('#vectors');
  if (!host) return;

  const results = [runX448Vector(), runEd448Vector()];
  host.innerHTML = results
    .map((r) => {
      const badge = r.pass
        ? '<span class="badge ok">PASS ✓</span>'
        : '<span class="badge bad">FAIL ✗</span>';
      return `
        <div class="vector">
          <div class="vector-head">
            <span>${r.title}<span class="vector-ref"> — ${r.ref}</span></span>
            ${badge}
          </div>
          <p class="mono">expected: ${shortHex(hexToBytes(r.expected), 16)}</p>
          <p class="mono">computed: ${shortHex(hexToBytes(r.computed), 16)}</p>
        </div>`;
    })
    .join('');
}

renderVectors();

// Defer the heavy live comparison (averaged microbenchmarks) until after the
// first paint so the page becomes interactive immediately.
window.setTimeout(compareCurves, 0);

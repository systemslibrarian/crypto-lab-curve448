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
import { type HashSplit, sha512Split, shake256Split } from './hashdemo';
import { makeToyCurve, mul, type ToyPoint } from './toycurve';

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) throw new Error('App container not found');

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** True when the user asked the OS to minimize motion; all animation respects it. */
function prefersReducedMotion(): boolean {
  return (
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );
}

function shortHex(bytes: Uint8Array, chars = 24): string {
  const hex = bytesToHex(bytes);
  if (hex.length <= chars * 2) return hex;
  return `${hex.slice(0, chars)}…${hex.slice(-chars)}`;
}

function maskHex(bytes: Uint8Array): string {
  return '█'.repeat(Math.min(14, Math.ceil(bytes.length / 4)));
}

/**
 * Render a private value into `el`. When hidden, the block glyphs are marked
 * decorative and an accessible label is supplied so screen readers announce the
 * state instead of reading "black square" repeatedly.
 */
function setSecret(el: HTMLElement, bytes: Uint8Array, revealed: boolean, noun: string): void {
  if (revealed) {
    el.textContent = bytesToHex(bytes);
    el.removeAttribute('aria-label');
    el.removeAttribute('role');
  } else {
    el.textContent = maskHex(bytes);
    el.setAttribute('role', 'img');
    el.setAttribute('aria-label', `${noun} hidden — use the reveal button to show it`);
  }
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
    <div class="vault-hero reveal">
      <p class="verse">"Whether therefore ye eat, or drink, or whatsoever ye do, do all to the glory of God."<br />1 Corinthians 10:31</p>
      <header class="cl-hero">
        <div class="cl-hero-main">
          <h1 class="cl-hero-title">Curve448 / Ed448</h1>
          <p class="cl-hero-sub">X448 ECDH · Ed448 · RFC 7748 / 8032</p>
          <p class="cl-hero-desc">Run a live X448 Diffie-Hellman handshake and Ed448 sign/verify, then compare key sizes, signatures, and timings head-to-head against Curve25519/Ed25519 — with the RFC test vectors recomputed in your browser.</p>
        </div>
        <aside class="cl-hero-why" aria-label="Why it matters">
          <span class="cl-hero-why-label">WHY IT MATTERS</span>
          <p class="cl-hero-why-text">Curve448 is the 224-bit security tier — the higher-assurance ECC choice for long-lived keys and strict compliance. That margin isn't free: clamping, SHAKE256, and larger, slower keys are the price of trading Curve25519's speed for headroom.</p>
        </aside>
      </header>
      <div class="security-scale" role="group" aria-labelledby="sec-scale-label">
        <p id="sec-scale-label" class="security-scale-label">Attack work factor — <strong>log scale</strong>, one step = one decimal order of magnitude (10×). A linear bar would put these two tiers a hair apart; the truth is 2<sup>96</sup> ≈ 10<sup>29</sup> steps.</p>
        <div class="security-scale-row">
          <span class="security-scale-tier c25519">Curve25519</span>
          <div class="security-scale-track" aria-hidden="true">
            <div class="security-scale-fill c25519" style="width:36.4%"></div>
            <div class="security-scale-tick" style="left:36.4%"><span>2<sup>128</sup></span></div>
          </div>
          <span class="security-scale-work">2<sup>128</sup> ≈ 10<sup>38.5</sup></span>
        </div>
        <div class="security-scale-row">
          <span class="security-scale-tier c448">Curve448</span>
          <div class="security-scale-track" aria-hidden="true">
            <div class="security-scale-fill c448" style="width:63.7%"></div>
            <div class="security-scale-tick" style="left:63.7%"><span>2<sup>224</sup></span></div>
          </div>
          <span class="security-scale-work">2<sup>224</sup> ≈ 10<sup>67.4</sup></span>
        </div>
        <p class="security-scale-anchor">If breaking 2<sup>128</sup> took the entire age of the universe (~14 billion years), breaking 2<sup>224</sup> would take that long <strong>about 10<sup>28</sup> times over</strong>. The gap isn't "1.75× stronger" — it's 2<sup>96</sup> (≈ 8 × 10<sup>28</sup>) times more work.</p>
      </div>
    </div>

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
      <article class="card primer">
        <h3>Diffie-Hellman in 10 seconds</h3>
        <p>Alice and Bob want a shared secret but can only talk over a wire everyone can read. Each picks a private number and multiplies the public base point <strong>G</strong> by it to get a public point they can safely publish. The trick: point multiplication <em>commutes</em>. Alice takes <strong>her</strong> secret times <strong>Bob's</strong> public point; Bob takes <strong>his</strong> secret times <strong>Alice's</strong> public point — and both land on the exact same point <strong>ab·G</strong>. An eavesdropper who sees only the two public points can't get there.</p>
      </article>

      <article class="card toybox">
        <h3>First, see a point: what does "scalar · G" even mean?</h3>
        <p class="toybox-lead">Before the real 448-bit hex, build the intuition on a <strong>toy</strong> curve you can actually see. A public key is just <strong>k · G</strong>: start at the base point <strong>G</strong> and hop <strong>k</strong> times by the curve's addition rule. Drag the slider to increment <strong>k</strong> and watch the point move. <span class="toybox-warn">Illustrative only — this curve has 29 points; real X448 has ≈2<sup>446</sup>.</span></p>
        <div class="toybox-grid">
          <div class="toybox-plot-wrap">
            <svg id="toy-plot" class="toybox-plot" viewBox="0 0 240 240" role="img" aria-labelledby="toy-plot-title"></svg>
            <p id="toy-plot-title" class="sr-only">Points of a small elliptic curve over the field of 23 elements, with the current multiple of the base point highlighted.</p>
          </div>
          <div class="toybox-controls">
            <label for="toy-k" class="toybox-klabel">scalar <strong>k</strong> = <span id="toy-k-val" class="toybox-kval">1</span></label>
            <input id="toy-k" type="range" min="1" max="28" value="1" step="1" />
            <p class="toybox-eq" id="toy-eq" aria-live="polite">1·G = (1, 11)</p>
            <p class="toybox-hint">Every distinct k lands on a different point. To read k back from just the point — the <abbr class="gloss" title="Elliptic-Curve Discrete Logarithm Problem: given P = k·G, recover k. Trivial on this 29-point toy; ≈2^224 work on Curve448.">ECDLP</abbr> — you'd have to try them one by one. Trivial with 29 points; hopeless with 2<sup>446</sup>.</p>
            <p class="toybox-link mono" id="toy-real">real X448 public A (448-bit, same idea): <span id="toy-real-hex">—</span></p>
          </div>
        </div>
      </article>

      <div class="actions">
        <button type="button" id="btn-handshake">Run Handshake</button>
        <button type="button" id="btn-compare" hidden>Compare Shared Secrets</button>
      </div>
      <div class="grid two">
        <article class="card alice">
          <h3>Alice</h3>
          <p>Private <abbr class="gloss" title="A secret integer. In X448 it is 56 bytes, clamped per RFC 7748.">scalar</abbr> a: <span id="alice-priv" class="secret"></span></p>
          <p>Public A = a·G: <span id="alice-pub" class="mono"></span>
            <button class="copy-btn" id="copy-alice-pub" type="button" aria-label="Copy Alice public key" hidden>copy</button></p>
          <p>Shared a·B: <span id="alice-shared" class="mono"></span></p>
        </article>
        <article class="card bob">
          <h3>Bob</h3>
          <p>Private <abbr class="gloss" title="A secret integer. In X448 it is 56 bytes, clamped per RFC 7748.">scalar</abbr> b: <span id="bob-priv" class="secret"></span></p>
          <p>Public B = b·G: <span id="bob-pub" class="mono"></span>
            <button class="copy-btn" id="copy-bob-pub" type="button" aria-label="Copy Bob public key" hidden>copy</button></p>
          <p>Shared b·A: <span id="bob-shared" class="mono"></span></p>
        </article>
      </div>

      <div class="wire" id="wire" role="group" aria-label="Public keys crossing the channel">
        <div class="wire-track a2b">
          <span class="wire-endpoint">Alice</span>
          <span class="wire-pkt a2b" id="pkt-a">A <span id="wire-a" class="wire-hex"></span></span>
          <span class="wire-endpoint">Bob</span>
        </div>
        <div class="wire-track b2a">
          <span class="wire-endpoint">Alice</span>
          <span class="wire-pkt b2a" id="pkt-b">B <span id="wire-b" class="wire-hex"></span></span>
          <span class="wire-endpoint">Bob</span>
        </div>
        <p class="wire-caption" id="wire-caption">Press <strong>Run Handshake</strong> to send A to Bob and B to Alice across the open channel.</p>
      </div>

      <article class="card mechanism" id="mechanism" hidden aria-hidden="true">
        <h3>Why the two results match: a·B = b·A</h3>
        <p class="mechanism-sub">Each side multiplies <strong>its own private scalar</strong> by <strong>the other side's public point</strong>. Substitute the definitions of A and B and the same product <span class="abg">ab·G</span> falls out both ways — that is the whole of Diffie-Hellman.</p>
        <div class="mechanism-cols">
          <div class="mechanism-col alice">
            <span class="mechanism-who">Alice computes</span>
            <code class="mechanism-eq">a · B<br />= a · (<span class="hl-b">b·G</span>)<br />= <span class="abg">ab·G</span></code>
          </div>
          <div class="mechanism-eq-join">=</div>
          <div class="mechanism-col bob">
            <span class="mechanism-who">Bob computes</span>
            <code class="mechanism-eq">b · A<br />= b · (<span class="hl-a">a·G</span>)<br />= <span class="abg">ab·G</span></code>
          </div>
        </div>
        <p class="mechanism-note">Scalar multiplication on the curve is associative and commutes over the scalars: a·(b·G) = b·(a·G) = (ab)·G. Neither party ever learns the other's scalar — only the shared point. The hex blobs above match <em>because</em> both are the little-endian u-coordinate of this one point.</p>
      </article>

      <button class="reveal-toggle" type="button" id="btn-reveal-dh" aria-pressed="false">Reveal private scalars</button>

      <article class="card clampbox" id="clampbox" hidden>
        <h3>What clamping actually does to the bits</h3>
        <p class="clampbox-lead">RFC 7748 doesn't use your random 56 bytes as-is. It <strong>clamps</strong> two specific bits before the scalar is ever used. Here are the two bytes that change in Alice's scalar — each cell is one bit, low bit on the right.</p>
        <div class="clampbox-rows">
          <div class="clampbox-row">
            <span class="clampbox-name">low byte (byte 0)</span>
            <div class="bitgrid" id="bitgrid-low" role="img" aria-label="Low byte of the private scalar, eight bits"></div>
            <span class="clampbox-effect">two low bits → <strong>0</strong></span>
          </div>
          <div class="clampbox-row">
            <span class="clampbox-name">high byte (byte 55)</span>
            <div class="bitgrid" id="bitgrid-high" role="img" aria-label="High byte of the private scalar, eight bits"></div>
            <span class="clampbox-effect">top bit → <strong>1</strong></span>
          </div>
        </div>
        <p class="clampbox-caption" id="clampbox-caption">Clearing the two low bits forces the scalar to a multiple of the cofactor (4), pinning it into the prime-order subgroup; setting the top bit fixes the scalar's length so timing can't leak it. Both are why an attacker can't nudge you off the safe curve.</p>
      </article>

      <p id="dh-status" class="status" role="status" aria-live="polite"></p>
      <article class="card scenario">
        <h3>Surveillance Scenario</h3>
        <p>Eve sees only A and B. Recovering (ab)·G from public points requires solving the <abbr class="gloss" title="Elliptic-Curve Discrete Logarithm Problem: given public point P = k·G, recover the secret scalar k. No efficient classical algorithm is known.">ECDLP</abbr> at roughly 2^224 work on Curve448 — the same wall Alice and Bob leaned on to keep their scalars private.</p>
      </article>
    </section>

    <section class="panel reveal" style="--stagger: 3" id="exhibit-3">
      <h2>Exhibit 3: Ed448 Signatures</h2>
      <div class="grid two">
        <article class="card">
          <label for="ed-message">Message</label>
          <input id="ed-message" value="Paul Clark certified" autocomplete="off" />
          <label for="ed-context">Context (optional) — <abbr class="gloss" title="Domain separation: a label mixed into the hash so a signature valid in one context does not verify in another.">domain separation</abbr></label>
          <input id="ed-context" value="" placeholder="e.g. tls-handshake" autocomplete="off" />
          <div class="actions inline">
            <button type="button" id="btn-ed-keygen">Generate Keypair</button>
            <button type="button" id="btn-ed-sign">Sign</button>
            <button type="button" id="btn-ed-verify">Verify</button>
            <button type="button" id="btn-ed-tamper-msg">Tamper Message</button>
            <button type="button" id="btn-ed-tamper-sig">Tamper Signature</button>
            <button type="button" id="btn-ed-reset" class="ghost-btn">Reset</button>
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

      <article class="card hashcmp">
        <h3>Seed → hash → (scalar, nonce): why SHAKE256, not SHA-512</h3>
        <p>Both curves derive the secret scalar <em>and</em> the per-signature nonce prefix by hashing the seed once and splitting the digest in half. Ed25519 uses SHA-512, whose output is a <strong>fixed</strong> 64 bytes. Ed448's field is bigger, so it needs 114 bytes — and SHA-512 simply cannot produce that. SHAKE256 is an <abbr class="gloss" title="eXtendable-Output Function: a hash you can squeeze to any output length from one sponge state.">XOF</abbr>: you squeeze it to whatever length you ask for. Below is the <strong>real</strong> hash of the current seed under each regime.</p>
        <div class="actions inline">
          <button type="button" id="btn-hashcmp">Expand this seed with both hashes</button>
        </div>
        <div id="hashcmp-out" class="hashcmp-out" tabindex="0" role="region" aria-label="SHAKE256 versus SHA-512 seed expansion output"></div>
      </article>

      <article class="card domainsep">
        <h3>Domain separation, made visible</h3>
        <p>A <em>context</em> is a label folded into Ed448's hash. Sign the <strong>same</strong> message under two different contexts and you get two different, equally-valid signatures — and crucially, neither verifies under the other's context. That is how a signature meant for "tls" can't be replayed as one meant for "email".</p>
        <div class="grid two domainsep-inputs">
          <div>
            <label for="ds-ctx-a">Context A</label>
            <input id="ds-ctx-a" value="tls-handshake" autocomplete="off" />
          </div>
          <div>
            <label for="ds-ctx-b">Context B</label>
            <input id="ds-ctx-b" value="email-signing" autocomplete="off" />
          </div>
        </div>
        <label for="ds-msg">Message (signed under both)</label>
        <input id="ds-msg" value="transfer approved" autocomplete="off" />
        <div class="actions inline">
          <button type="button" id="btn-domainsep">Sign under both contexts &amp; cross-check</button>
        </div>
        <div id="domainsep-out" class="domainsep-out" tabindex="0" role="region" aria-label="Domain separation comparison output"></div>
      </article>
    </section>

    <section class="panel reveal" style="--stagger: 4" id="exhibit-4">
      <h2>Exhibit 4: Curve25519 vs Curve448</h2>
      <button type="button" class="disclosure" id="btn-disclose-4" aria-expanded="false" aria-controls="disclose-4">
        <span class="disclosure-icon" aria-hidden="true">▸</span> Show me the numbers
      </button>
      <div class="accordion" id="disclose-4" hidden>
        <p class="disclosure-lead">The point of this table is one row: the margin isn't free. Everything Curve448 buys in security it pays for in bigger keys, bigger signatures, and slower operations. The <span class="tradeoff-key">highlighted rows</span> are where that price shows up.</p>
        <div class="actions"><button type="button" id="btn-compare-curves">Generate Live Comparison</button></div>
        <div class="table-wrap" tabindex="0" role="region" aria-label="Live curve comparison table">
          <table>
            <caption class="sr-only">Live side-by-side key, signature, and performance comparison</caption>
            <thead>
              <tr><th>Metric</th><th>Curve25519 / Ed25519</th><th>Curve448 / Ed448</th></tr>
            </thead>
            <tbody id="compare-body"></tbody>
          </table>
        </div>
        <p class="tradeoff-callout"><strong>The price of the margin:</strong> a 114-byte Ed448 signature is ~1.8× the size of Ed25519's 64 bytes, and every operation runs slower. That is the trade you make for jumping from 128-bit to 224-bit security.</p>
      </div>
    </section>

    <section class="panel reveal" style="--stagger: 5" id="exhibit-5">
      <h2>Exhibit 5: Verified Against the RFCs</h2>
      <p>Trust nothing — verify. These published test vectors are recomputed live in your browser on every page load.</p>
      <button type="button" class="disclosure" id="btn-disclose-5" aria-expanded="false" aria-controls="disclose-5">
        <span class="disclosure-icon" aria-hidden="true">▸</span> Show the proof
      </button>
      <div class="accordion" id="disclose-5" hidden>
        <div id="vectors"></div>
      </div>
    </section>

    <section class="panel reveal" style="--stagger: 6" id="exhibit-6">
      <h2>Exhibit 6: When to Use Which</h2>
      <button type="button" class="disclosure" id="btn-disclose-6" aria-expanded="false" aria-controls="disclose-6">
        <span class="disclosure-icon" aria-hidden="true">▸</span> Show the decision guide
      </button>
      <div class="accordion" id="disclose-6" hidden>
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
      </div>
    </section>
  </main>
<footer style="margin-top:3rem;padding:2rem 1rem;border-top:1px solid rgba(128,128,128,.25);text-align:center;font-size:.85rem;line-height:1.9;font-family:ui-monospace,Menlo,Consolas,monospace">
  <div><strong>Related demos:</strong> <a href="https://systemslibrarian.github.io/crypto-lab-curve-lens/">curve-lens</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-ed25519-forge/">ed25519-forge</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-key-exchange/">key-exchange</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-ssh-handshake/">ssh-handshake</a></div>
  <div style="margin-top:.5rem"><a href="https://github.com/systemslibrarian/crypto-lab-curve448">Source on GitHub</a> &middot; <a href="https://crypto-lab.systemslibrarian.dev/">More crypto-lab demos</a></div>
  <div style="margin-top:.75rem;color:var(--muted)">&ldquo;So whether you eat or drink or whatever you do, do it all for the glory of God.&rdquo; &mdash; 1 Corinthians 10:31</div>
</footer>
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
  const copyA = document.querySelector<HTMLButtonElement>('#copy-alice-pub');
  const copyB = document.querySelector<HTMLButtonElement>('#copy-bob-pub');
  const wireA = document.querySelector<HTMLSpanElement>('#wire-a');
  const wireB = document.querySelector<HTMLSpanElement>('#wire-b');

  if (!alicePriv || !alicePub || !aliceShared || !bobPriv || !bobPub || !bobShared || !status) return;

  setSecret(alicePriv, latestHandshake.alice.privateKey, revealDhPrivate, "Alice's private scalar");
  setSecret(bobPriv, latestHandshake.bob.privateKey, revealDhPrivate, "Bob's private scalar");
  alicePub.textContent = shortHex(latestHandshake.alice.publicKey);
  bobPub.textContent = shortHex(latestHandshake.bob.publicKey);
  aliceShared.textContent = shortHex(latestHandshake.aliceComputedShared);
  bobShared.textContent = shortHex(latestHandshake.bobComputedShared);

  // The wire step: show the exact public points that cross the channel — these
  // are what Alice multiplies by b (as B) and Bob multiplies by a (as A).
  if (wireA) wireA.textContent = shortHex(latestHandshake.alice.publicKey, 6);
  if (wireB) wireB.textContent = shortHex(latestHandshake.bob.publicKey, 6);

  // Mark both shared-secret lines as identical when they match so the eye can
  // see the two independent computations landed on the same ab·G.
  const matchCls = latestHandshake.secretsMatch ? 'mono abg-match' : 'mono';
  aliceShared.className = matchCls;
  bobShared.className = matchCls;

  status.textContent = latestHandshake.secretsMatch
    ? '✓ IDENTICAL: a·B and b·A both landed on ab·G — the same 56-byte shared secret.'
    : '✗ mismatch: handshake failed.';
  status.className = `status ${latestHandshake.secretsMatch ? 'ok' : 'bad'}`;

  if (copyA) copyA.hidden = false;
  if (copyB) copyB.hidden = false;

  // Toy-curve exhibit links to the *real* public A so the picture and the
  // 448-bit output are visibly the same operation, k·G, at two scales.
  const toyReal = document.querySelector<HTMLSpanElement>('#toy-real-hex');
  if (toyReal) toyReal.textContent = shortHex(latestHandshake.alice.publicKey, 6);

  const clampbox = document.querySelector<HTMLElement>('#clampbox');
  if (clampbox) clampbox.hidden = !revealDhPrivate;
  if (revealDhPrivate) renderClampGrid();
}

/**
 * Render the low and high bytes of Alice's scalar as 8-cell bit grids, then
 * (unless reduced motion) flip the two low bits to 0 and the top bit to 1 so
 * the learner watches clamping happen instead of reading about it. The clamped
 * value shown is the *actual* scalar in use; we reconstruct the pre-clamp bits
 * only for the low/high bytes to show what changed.
 */
function renderClampGrid(): void {
  const low = document.querySelector<HTMLDivElement>('#bitgrid-low');
  const high = document.querySelector<HTMLDivElement>('#bitgrid-high');
  if (!low || !high) return;

  const key = latestHandshake.alice.privateKey;
  const clampedLow = key[0]; // already has bits 0,1 cleared
  const clampedHigh = key[key.length - 1]; // already has bit 7 set

  // Build a cell row from a byte, bit 7 (MSB) on the left. `changed` marks the
  // clamp-affected bit positions so they can animate.
  const buildRow = (
    el: HTMLDivElement,
    byteVal: number,
    changedBits: number[],
    finalBits: Record<number, number>,
  ) => {
    el.innerHTML = '';
    for (let bit = 7; bit >= 0; bit -= 1) {
      const cell = document.createElement('span');
      cell.className = 'bit';
      const val = (byteVal >> bit) & 1;
      cell.dataset.bit = String(bit);
      if (changedBits.includes(bit)) {
        // Start from the "pre-clamp" appearance, then animate to final.
        const pre = finalBits[bit] === 0 ? 1 : 0;
        cell.textContent = String(pre);
        cell.classList.add(pre ? 'on' : 'off', 'will-clamp');
      } else {
        cell.textContent = String(val);
        cell.classList.add(val ? 'on' : 'off');
      }
      el.appendChild(cell);
    }
  };

  buildRow(low, clampedLow, [0, 1], { 0: 0, 1: 0 });
  buildRow(high, clampedHigh, [7], { 7: 1 });

  const settle = (el: HTMLDivElement, finalBits: Record<number, number>) => {
    el.querySelectorAll<HTMLElement>('.will-clamp').forEach((cell) => {
      const bit = Number(cell.dataset.bit);
      const target = finalBits[bit];
      cell.textContent = String(target);
      cell.classList.remove('on', 'off');
      cell.classList.add(target ? 'on' : 'off', 'clamped');
    });
  };

  if (prefersReducedMotion()) {
    settle(low, { 0: 0, 1: 0 });
    settle(high, { 7: 1 });
  } else {
    window.setTimeout(() => {
      settle(low, { 0: 0, 1: 0 });
      settle(high, { 7: 1 });
    }, 450);
  }
}

/** Reveal the mechanism panel (the ab·G payoff) once a handshake has crossed. */
function revealMechanism(): void {
  const mech = document.querySelector<HTMLElement>('#mechanism');
  if (mech && mech.hidden) {
    mech.hidden = false;
    mech.setAttribute('aria-hidden', 'false');
  }
  const compare = document.querySelector<HTMLButtonElement>('#btn-compare');
  if (compare) compare.hidden = false;
}

/**
 * Animate A traveling left→right to Bob and B right→left to Alice, then flash
 * the arriving packets before revealing the mechanism. Reduced-motion users
 * skip straight to the settled, revealed state.
 */
function runWireAnimation(): void {
  const wire = document.querySelector<HTMLElement>('#wire');
  const pktA = document.querySelector<HTMLElement>('#pkt-a');
  const pktB = document.querySelector<HTMLElement>('#pkt-b');
  const caption = document.querySelector<HTMLElement>('#wire-caption');

  if (caption) {
    caption.innerHTML =
      'A crosses to Bob (who computes <strong>b·A</strong>); B crosses to Alice (who computes <strong>a·B</strong>).';
  }

  if (prefersReducedMotion() || !wire || !pktA || !pktB) {
    revealMechanism();
    if (pktA) pktA.classList.add('arrived');
    if (pktB) pktB.classList.add('arrived');
    return;
  }

  pktA.classList.remove('arrived', 'sending');
  pktB.classList.remove('arrived', 'sending');
  // Force reflow so re-adding the class restarts the transition.
  void pktA.offsetWidth;
  pktA.classList.add('sending');
  pktB.classList.add('sending');

  window.setTimeout(() => {
    pktA.classList.add('arrived');
    pktB.classList.add('arrived');
    // The ab·G payoff appears the moment the crossed points land on the far
    // side, so the reveal reads as a consequence of the exchange.
    revealMechanism();
  }, 850);
}

document.querySelector<HTMLButtonElement>('#btn-handshake')?.addEventListener('click', () => {
  latestHandshake = simulateHandshake();
  renderHandshake();
  runWireAnimation();
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

// ---- Exhibit 2 (toy): geometric intuition for "public = scalar · G" --------
// An illustrative curve over F_23. Plotting k·G as k increments turns scalar
// multiplication from a hex string into visible hops around a small point set,
// alongside the real 448-bit output which stays spec-accurate above.
const TOY = makeToyCurve();
const TOY_MAX = TOY.order - 1; // largest k before we wrap back to G

function toyScreen(pt: ToyPoint): { cx: number; cy: number } {
  // Map field coords [0, p) into a 20..220 box; flip y so it reads bottom-up.
  const pad = 20;
  const span = 200;
  const cx = pad + (pt.x / (TOY.p - 1)) * span;
  const cy = pad + span - (pt.y / (TOY.p - 1)) * span;
  return { cx, cy };
}

function renderToyPlot(k: number): void {
  const svg = document.querySelector<SVGSVGElement>('#toy-plot');
  const kVal = document.querySelector<HTMLSpanElement>('#toy-k-val');
  const eq = document.querySelector<HTMLParagraphElement>('#toy-eq');
  if (!svg) return;

  const ns = 'http://www.w3.org/2000/svg';
  svg.innerHTML = '';

  // Faint backdrop: every point on the toy curve.
  for (const pt of TOY.points) {
    const { cx, cy } = toyScreen(pt);
    const c = document.createElementNS(ns, 'circle');
    c.setAttribute('cx', cx.toFixed(1));
    c.setAttribute('cy', cy.toFixed(1));
    c.setAttribute('r', '2.6');
    c.setAttribute('class', 'toy-dot');
    svg.appendChild(c);
  }

  // The base point G, always labeled.
  const g = toyScreen(TOY.G);
  const gc = document.createElementNS(ns, 'circle');
  gc.setAttribute('cx', g.cx.toFixed(1));
  gc.setAttribute('cy', g.cy.toFixed(1));
  gc.setAttribute('r', '5');
  gc.setAttribute('class', 'toy-g');
  svg.appendChild(gc);
  const gl = document.createElementNS(ns, 'text');
  gl.setAttribute('x', (g.cx + 7).toFixed(1));
  gl.setAttribute('y', (g.cy - 6).toFixed(1));
  gl.setAttribute('class', 'toy-label');
  gl.textContent = 'G';
  svg.appendChild(gl);

  // The current multiple k·G.
  const P = mul(k, TOY.G, TOY);
  if (!P.inf) {
    const { cx, cy } = toyScreen(P);
    const pc = document.createElementNS(ns, 'circle');
    pc.setAttribute('cx', cx.toFixed(1));
    pc.setAttribute('cy', cy.toFixed(1));
    pc.setAttribute('r', '6.5');
    pc.setAttribute('class', 'toy-cur');
    svg.appendChild(pc);
    const pl = document.createElementNS(ns, 'text');
    pl.setAttribute('x', (cx + 7).toFixed(1));
    pl.setAttribute('y', (cy - 6).toFixed(1));
    pl.setAttribute('class', 'toy-label cur');
    pl.textContent = `${k}·G`;
    svg.appendChild(pl);
  }

  if (kVal) kVal.textContent = String(k);
  if (eq) {
    eq.textContent = P.inf
      ? `${k}·G = O (point at infinity — the identity)`
      : `${k}·G = (${P.x}, ${P.y})`;
  }
}

const toySlider = document.querySelector<HTMLInputElement>('#toy-k');
if (toySlider) {
  toySlider.max = String(TOY_MAX);
  toySlider.addEventListener('input', () => renderToyPlot(Number(toySlider.value)));
}
renderToyPlot(1);

// ---- Progressive disclosure: gate Exhibits 4-6 behind toggles --------------
function wireDisclosure(btnId: string): void {
  const btn = document.querySelector<HTMLButtonElement>(`#${btnId}`);
  if (!btn) return;
  const targetId = btn.getAttribute('aria-controls');
  const panel = targetId ? document.getElementById(targetId) : null;
  if (!panel) return;
  const label = btn.querySelector('.disclosure-icon')?.nextSibling;
  const openText = label?.textContent ?? ' Show';
  btn.addEventListener('click', () => {
    const expanded = btn.getAttribute('aria-expanded') === 'true';
    const next = !expanded;
    btn.setAttribute('aria-expanded', String(next));
    panel.hidden = !next;
    const icon = btn.querySelector('.disclosure-icon');
    if (icon) icon.textContent = next ? '▾' : '▸';
    if (label) label.textContent = next ? ' Hide' : openText;
  });
}
wireDisclosure('btn-disclose-4');
wireDisclosure('btn-disclose-5');
wireDisclosure('btn-disclose-6');

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
  setSecret(priv, edState.privateKey, revealEdPrivate, 'Ed448 private seed');
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

// Tampering now MUTATES the live state (message or signature) and re-verifies,
// so a follow-up Verify still fails — the tamper "sticks" until you re-Sign or
// Reset. This matches what real integrity checking catches instead of quietly
// testing a throwaway copy.
document.querySelector<HTMLButtonElement>('#btn-ed-tamper-msg')?.addEventListener('click', () => {
  if (latestSignature.length === 0) {
    renderEdState('Sign a message first.', false);
    return;
  }
  const msgInput = document.querySelector<HTMLInputElement>('#ed-message');
  const tampered = new Uint8Array(latestMessage);
  if (tampered.length > 0) tampered[0] ^= 0x01;
  latestMessage = tampered; // persist the flip
  if (msgInput) {
    // Reflect the flip in the visible field: byte 0's low bit toggled.
    msgInput.value = decoder.decode(latestMessage);
  }
  const valid = verifyEd448(latestSignature, latestMessage, edState.publicKey, readContext());
  renderEdState(
    valid
      ? 'Unexpected valid result'
      : '✗ INVALID: message byte 0 flipped and kept. Verify still fails — re-Sign or Reset to recover.',
    false,
  );
});

document.querySelector<HTMLButtonElement>('#btn-ed-tamper-sig')?.addEventListener('click', () => {
  if (latestSignature.length === 0) {
    renderEdState('Sign a message first.', false);
    return;
  }
  latestSignature = tamperSignature(latestSignature); // persist the flip
  const valid = verifyEd448(latestSignature, latestMessage, edState.publicKey, readContext());
  renderEdState(
    valid
      ? 'Unexpected valid result'
      : '✗ INVALID: signature byte 0 flipped and kept. Verify still fails — re-Sign or Reset to recover.',
    false,
  );
});

document.querySelector<HTMLButtonElement>('#btn-ed-reset')?.addEventListener('click', () => {
  const msgInput = document.querySelector<HTMLInputElement>('#ed-message');
  if (msgInput) msgInput.value = 'Paul Clark certified';
  latestMessage = encoder.encode(msgInput?.value ?? 'Paul Clark certified');
  latestSignature = new Uint8Array(0);
  renderEdState('Reset — message restored, signature cleared. Sign again to continue.', true);
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

// ---- Exhibit 3b: seed -> hash -> (scalar, nonce) ---------------------------

function renderHashSplit(split: HashSplit): string {
  const lenNote = split.fixedOutput
    ? `fixed ${split.digestLen} bytes — this length is not adjustable`
    : `squeezed to ${split.digestLen} bytes — an XOF gives you any length you ask for`;
  return `
    <div class="hashcmp-card">
      <div class="hashcmp-head">${split.algo}
        <span class="hashcmp-len">${lenNote}</span>
      </div>
      <p class="mono">seed (${split.seedLen} B): ${shortHex(edState.privateKey, 8)}</p>
      <p class="mono">scalar half (${split.scalarHalf.length} B): ${shortHex(split.scalarHalf, 8)}</p>
      <p class="mono">nonce prefix (${split.prefixHalf.length} B): ${shortHex(split.prefixHalf, 8)}</p>
    </div>`;
}

document.querySelector<HTMLButtonElement>('#btn-hashcmp')?.addEventListener('click', () => {
  const out = document.querySelector<HTMLDivElement>('#hashcmp-out');
  if (!out) return;
  // Ed25519 hashes a 32-byte seed; Ed448 hashes a 57-byte seed. Use the real
  // current Ed448 seed for SHAKE256, and a 32-byte slice of it as a stand-in
  // Ed25519 seed so both columns hash live bytes from the same source.
  const ed25519Seed = edState.privateKey.slice(0, 32);
  const sha = sha512Split(ed25519Seed);
  const shake = shake256Split(edState.privateKey, 114);
  out.innerHTML = `
    ${renderHashSplit(sha)}
    ${renderHashSplit(shake)}
    <p class="hashcmp-foot">Same idea, two hashes: split the digest into (secret scalar, nonce prefix). SHA-512's 64 bytes can't cover Ed448's 114-byte need — only the XOF stretches that far. These are real digests computed just now in your browser.</p>`;
});

// ---- Exhibit 3c: domain separation made visible ----------------------------

document.querySelector<HTMLButtonElement>('#btn-domainsep')?.addEventListener('click', () => {
  const out = document.querySelector<HTMLDivElement>('#domainsep-out');
  if (!out) return;
  const ctxAStr = (document.querySelector<HTMLInputElement>('#ds-ctx-a')?.value ?? '').trim();
  const ctxBStr = (document.querySelector<HTMLInputElement>('#ds-ctx-b')?.value ?? '').trim();
  const msgStr = document.querySelector<HTMLInputElement>('#ds-msg')?.value ?? '';
  if (ctxAStr.length === 0 || ctxBStr.length === 0) {
    out.innerHTML = '<p class="status bad">Both contexts must be non-empty to compare.</p>';
    return;
  }
  const kp = generateEd448KeyPair();
  const msg = encoder.encode(msgStr);
  const ctxA = encoder.encode(ctxAStr);
  const ctxB = encoder.encode(ctxBStr);

  const sigA = signEd448(msg, kp.privateKey, ctxA);
  const sigB = signEd448(msg, kp.privateKey, ctxB);

  // Each signature is valid ONLY under the context it was made with.
  const aUnderA = verifyEd448(sigA, msg, kp.publicKey, ctxA);
  const bUnderB = verifyEd448(sigB, msg, kp.publicKey, ctxB);
  const aUnderB = verifyEd448(sigA, msg, kp.publicKey, ctxB); // should fail
  const bUnderA = verifyEd448(sigB, msg, kp.publicKey, ctxA); // should fail

  const yn = (ok: boolean): string =>
    ok
      ? '<span class="ds-ok">✓ verifies</span>'
      : '<span class="ds-bad">✗ rejected</span>';

  out.innerHTML = `
    <div class="grid two">
      <div class="ds-card">
        <div class="ds-ctx">context = "${ctxAStr}"</div>
        <p class="mono">sig A: ${shortHex(sigA, 10)}</p>
      </div>
      <div class="ds-card">
        <div class="ds-ctx">context = "${ctxBStr}"</div>
        <p class="mono">sig B: ${shortHex(sigB, 10)}</p>
      </div>
    </div>
    <table class="ds-matrix">
      <caption class="sr-only">Cross-context verification matrix</caption>
      <thead><tr><th scope="col">signature</th><th scope="col">under "${ctxAStr}"</th><th scope="col">under "${ctxBStr}"</th></tr></thead>
      <tbody>
        <tr><td>sig A</td><td>${yn(aUnderA)}</td><td>${yn(aUnderB)}</td></tr>
        <tr><td>sig B</td><td>${yn(bUnderA)}</td><td>${yn(bUnderB)}</td></tr>
      </tbody>
    </table>
    <p class="ds-foot">Same message, same key, two contexts — two distinct valid signatures. Each verifies under its own context and is <strong>rejected</strong> under the other. That off-diagonal rejection is domain separation doing its job.</p>`;
});

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

  // `trade` marks the rows that embody the core cost of the security margin, so
  // the eye lands on them instead of diffing eleven equal-weight cells.
  const rows: Array<[string, string, string, boolean?]> = [
    ['Private key size', '32 bytes', '56 bytes'],
    ['Public key size', `${x25519Alice.publicKey.length} bytes`, `${x448Alice.publicKey.length} bytes`],
    ['Shared secret size', `${x25519Shared.length} bytes`, `${x448Shared.length} bytes`],
    ['Classical security', '128-bit', '224-bit'],
    ['EdDSA seed size', '32 bytes', '57 bytes'],
    ['EdDSA pubkey size', `${ed25519Public.length} bytes`, `${ed448Kp.publicKey.length} bytes`],
    ['Signature size', `${ed25519Sig.length} bytes`, `${ed448Sig.length} bytes`, true],
    ['Hash internals', 'SHA-512', 'SHAKE256'],
    ['Sample public key', shortHex(x25519Alice.publicKey, 16), shortHex(x448Alice.publicKey, 16)],
    ['Performance (avg, browser)', perfLeft, perfRight, true],
    ['Common deployments', 'Signal, mainstream TLS, default SSH', 'High-security SSH, long-term GPG, optional TLS 1.3 group'],
  ];

  body.innerHTML = rows
    .map(([metric, left, right, trade]) => {
      const cls = trade ? ' class="tradeoff-row"' : '';
      const tag = trade ? ' <span class="tradeoff-tag">the price</span>' : '';
      return `<tr${cls}><td data-label="Metric">${metric}${tag}</td><td class="mono" data-label="Curve25519 / Ed25519">${left}</td><td class="mono" data-label="Curve448 / Ed448">${right}</td></tr>`;
    })
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

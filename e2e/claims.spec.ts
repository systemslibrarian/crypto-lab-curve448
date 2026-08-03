import { expect, test, type Page } from '@playwright/test';

/**
 * Functional gate: assert the claims the page actually makes.
 *
 * The a11y suite proves the page is reachable; this suite proves it is
 * *right*. Every assertion here is either (a) a headline verdict checked
 * against a value the page itself computed, (b) a failure path driven to its
 * failure state and read for its stated reason, (c) a counter or statistic
 * checked for internal consistency (parts summing to the whole, a row count
 * matching the number the copy claims), or (d) cross-path agreement, where the
 * page derives the same quantity twice by different routes and the two must
 * match. Hardcoded expected strings are avoided wherever the page has the real
 * number available.
 */

// ---- helpers ---------------------------------------------------------------

/** Mirror of `shortHex` in src/main.ts: head…tail abbreviation of a hex blob. */
function shortHexOf(hex: string, chars: number): string {
  if (hex.length <= chars * 2) return hex;
  return `${hex.slice(0, chars)}…${hex.slice(-chars)}`;
}

/** Pull the first capture group out of `text`, failing loudly if absent. */
function grab(text: string, re: RegExp, what: string): string {
  const m = re.exec(text);
  expect(m, `expected to find ${what} in: ${JSON.stringify(text)}`).not.toBeNull();
  return (m as RegExpExecArray)[1];
}

function grabInt(text: string, re: RegExp, what: string): number {
  return Number.parseInt(grab(text, re, what), 10);
}

async function textOf(page: Page, selector: string): Promise<string> {
  return ((await page.locator(selector).first().textContent()) ?? '').trim();
}

/** Reveal the Ed448 seed and return it as hex. */
async function revealEdSeed(page: Page): Promise<string> {
  await page.locator('#btn-reveal-ed').click();
  const seed = await textOf(page, '#ed-priv');
  expect(seed).toMatch(/^[0-9a-f]+$/);
  return seed;
}

/** Read one row of the live comparison table as [metric, curve25519, curve448]. */
async function compareRow(page: Page, metric: string): Promise<[string, string, string]> {
  const row = page.locator('#compare-body tr', { hasText: metric }).first();
  await expect(row).toHaveCount(1);
  const cells = await row.locator('td').allTextContents();
  expect(cells).toHaveLength(3);
  return [cells[0].trim(), cells[1].trim(), cells[2].trim()];
}

// ---- Exhibit 1: the security-margin claim ----------------------------------

test('the Goldilocks prime shown is really 2^448 - 2^224 - 1', async ({ page }) => {
  await page.goto('.');
  const rendered = await textOf(page, '#prime-value');
  // Recompute in the page itself rather than pasting a 135-digit literal into
  // the test: the assertion then checks arithmetic, not a copy of a copy.
  const truth = await page.evaluate(() => (2n ** 448n - 2n ** 224n - 1n).toString());
  expect(rendered).toBe(truth);
  expect(rendered).toHaveLength(135);
});

test('the log-scale work-factor bars agree with their own labels', async ({ page }) => {
  await page.goto('.');
  const rows = page.locator('.security-scale-row');
  await expect(rows).toHaveCount(2);

  const read = async (i: number) => {
    const row = rows.nth(i);
    const work = (await row.locator('.security-scale-work').innerHTML()).replace(/\s+/g, ' ');
    const bits = grabInt(work, /^2<sup>(\d+)<\/sup>/, 'the 2^N work factor');
    const decades = Number.parseFloat(
      grab(work, /10<sup>([\d.]+)<\/sup>/, 'the 10^N restatement'),
    );
    const width = Number.parseFloat(
      grab(
        await row.locator('.security-scale-fill').getAttribute('style') ?? '',
        /width:\s*([\d.]+)%/,
        'the fill width',
      ),
    );
    return { bits, decades, width };
  };

  const weak = await read(0);
  const strong = await read(1);

  // Each "2^N ~ 10^M" restatement must actually be log10(2^N).
  expect((weak.bits * Math.log10(2)).toFixed(1)).toBe(weak.decades.toFixed(1));
  expect((strong.bits * Math.log10(2)).toFixed(1)).toBe(strong.decades.toFixed(1));

  // The bars are log scale, so both fills must sit on ONE decades-per-percent
  // ruler. A regression to a linear-in-work-factor bar breaks this instantly.
  const rulerWeak = weak.decades / weak.width;
  const rulerStrong = strong.decades / strong.width;
  expect(Math.abs(rulerWeak - rulerStrong)).toBeLessThan(0.01);
  expect(strong.width).toBeGreaterThan(weak.width);

  // The headline gap: the prose claims 2^96, which must be the real difference.
  // Anchored to the "it's 2^96 (~ 8 x 10^28)" clause specifically: the same
  // paragraph also mentions 2^128 and 10^28 in other roles.
  const anchor = (await page.locator('.security-scale-anchor').innerHTML()).replace(/\s+/g, ' ');
  const gap = /it's 2<sup>(\d+)<\/sup> \(. (\d+) . 10<sup>(\d+)<\/sup>\)/.exec(anchor);
  expect(gap, `expected the "it's 2^N (~ M x 10^E)" gap clause in: ${anchor}`).not.toBeNull();
  const [, gapBits, gapMantissa, gapExp] = (gap as RegExpExecArray).map(Number);
  expect(gapBits).toBe(strong.bits - weak.bits);
  expect(Math.round(2 ** gapBits / 10 ** gapExp)).toBe(gapMantissa);
});

// ---- Exhibit 2: X448 Diffie-Hellman ----------------------------------------

test('the ab.G payoff stays gated until the public points cross the wire', async ({ page }) => {
  await page.goto('.');
  // README: "the a.B = b.A = ab.G payoff is gated behind that crossing".
  await expect(page.locator('#mechanism')).toBeHidden();
  await expect(page.locator('#btn-compare')).toBeHidden();
  await expect(page.locator('#wire-caption')).toContainText('Press');

  await page.locator('#btn-handshake').click();

  await expect(page.locator('#mechanism')).toBeVisible();
  await expect(page.locator('#btn-compare')).toBeVisible();
  await expect(page.locator('#wire-caption')).toContainText('A crosses to Bob');
  await expect(page.locator('#wire-caption')).toContainText('B crosses to Alice');
});

test('the handshake verdict is backed by the secret the page computed', async ({ page }) => {
  await page.goto('.');
  await page.locator('#btn-handshake').click();

  const status = page.locator('#dh-status');
  await expect(status).toHaveClass(/\bok\b/);
  const headline = await textOf(page, '#dh-status');
  expect(headline).toContain('IDENTICAL');

  // The verdict names a length. Drive the "Compare Shared Secrets" path, which
  // prints the FULL secret, and check the headline's own number against it.
  const claimedBytes = grabInt(headline, /same (\d+)-byte shared secret/, 'the claimed byte length');
  await page.locator('#btn-compare').click();
  const compared = await textOf(page, '#dh-status');
  const fullHex = grab(compared, /Byte-for-byte match: ([0-9a-f]+)/, 'the full shared secret');
  expect(fullHex.length % 2).toBe(0);
  expect(fullHex.length / 2).toBe(claimedBytes);
  await expect(status).toHaveClass(/\bok\b/);

  // Cross-path: the two per-party panels abbreviate the same secret, computed
  // independently as a.B and b.A. Both must abbreviate the full hex exactly.
  const abbreviated = shortHexOf(fullHex, 24);
  expect(await textOf(page, '#alice-shared')).toBe(abbreviated);
  expect(await textOf(page, '#bob-shared')).toBe(abbreviated);
  await expect(page.locator('#alice-shared')).toHaveClass(/abg-match/);
  await expect(page.locator('#bob-shared')).toHaveClass(/abg-match/);
});

test('the wire packet and the toy-curve callout show the same real public key', async ({ page }) => {
  await page.goto('.');
  await page.locator('#btn-handshake').click();

  // Two independent render sites for Alice's public point: the packet on the
  // wire and the "real X448 public A" line under the toy curve. They must agree
  // or the toy exhibit is illustrating a different key than the one exchanged.
  const onWire = await textOf(page, '#wire-a');
  const underToy = await textOf(page, '#toy-real-hex');
  expect(onWire).toMatch(/^[0-9a-f]+…[0-9a-f]+$/);
  expect(underToy).toBe(onWire);

  // Re-running must produce a fresh key pair, and both sites must follow it.
  await page.locator('#btn-handshake').click();
  const onWire2 = await textOf(page, '#wire-a');
  expect(onWire2).not.toBe(onWire);
  expect(await textOf(page, '#toy-real-hex')).toBe(onWire2);
});

test('the clamping bit-grid matches the scalar actually in use', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#alice-priv')).toHaveText(/^█+$/);
  await expect(page.locator('#clampbox')).toBeHidden();

  await page.locator('#btn-reveal-dh').click();
  await expect(page.locator('#clampbox')).toBeVisible();

  const hex = await textOf(page, '#alice-priv');
  expect(hex).toMatch(/^[0-9a-f]{112}$/); // 56-byte X448 scalar
  const bytes = hex.match(/../g) as string[];
  const lowByte = Number.parseInt(bytes[0], 16);
  const highByte = Number.parseInt(bytes[bytes.length - 1], 16);

  // RFC 7748 clamping, asserted on the real scalar rather than on the caption.
  expect(lowByte & 0b11).toBe(0);
  expect(highByte & 0b1000_0000).toBe(0b1000_0000);

  // The grid animates from the pre-clamp bits; wait for the settled cells.
  await expect(page.locator('#bitgrid-low .bit.clamped')).toHaveCount(2);
  await expect(page.locator('#bitgrid-high .bit.clamped')).toHaveCount(1);

  // Cross-path: the rendered bit cells must spell the real bytes, MSB first.
  const lowBits = (await page.locator('#bitgrid-low .bit').allTextContents()).join('');
  const highBits = (await page.locator('#bitgrid-high .bit').allTextContents()).join('');
  expect(lowBits).toBe(lowByte.toString(2).padStart(8, '0'));
  expect(highBits).toBe(highByte.toString(2).padStart(8, '0'));

  // ...and the two cells the caption promises change are the clamped ones.
  const lowClamped = await page.locator('#bitgrid-low .bit.clamped').allTextContents();
  expect(lowClamped).toEqual(['0', '0']);
  expect(await page.locator('#bitgrid-high .bit.clamped').allTextContents()).toEqual(['1']);

  // Hiding again re-masks the scalar and re-closes the grid.
  await page.locator('#btn-reveal-dh').click();
  await expect(page.locator('#clampbox')).toBeHidden();
  await expect(page.locator('#alice-priv')).toHaveText(/^█+$/);
});

test('the toy curve has as many points as the copy claims, all distinct', async ({ page }) => {
  await page.goto('.');

  // The copy says "this curve has N points". The backdrop dots are the affine
  // points; the group also holds the point at infinity. N must be dots + 1.
  const warn = await textOf(page, '.toybox-warn');
  const claimed = grabInt(warn, /this curve has (\d+) points/, 'the claimed point count');
  const dots = await page.locator('#toy-plot .toy-dot').count();
  expect(dots + 1).toBe(claimed);

  // The slider walks k over the whole non-identity range: 1..order-1.
  expect(await page.locator('#toy-k').getAttribute('max')).toBe(String(claimed - 1));

  // "Every distinct k lands on a different point." Drive every k and check.
  const seen = new Set<string>();
  for (let k = 1; k <= claimed - 1; k += 1) {
    await page.locator('#toy-k').evaluate((el, v) => {
      (el as HTMLInputElement).value = String(v);
      el.dispatchEvent(new Event('input', { bubbles: true }));
    }, k);
    const eq = await textOf(page, '#toy-eq');
    const point = grab(eq, /^\d+·G = (.+)$/, 'the k.G point');
    expect(eq.startsWith(`${k}·G =`)).toBe(true);
    expect(await textOf(page, '#toy-k-val')).toBe(String(k));
    seen.add(point);
  }
  expect(seen.size).toBe(claimed - 1);
});

// ---- Exhibit 3: Ed448 signatures -------------------------------------------

test('sign and verify report the real message and signature sizes', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#ed-sig')).toHaveText('(no signature yet)');

  const message = await page.locator('#ed-message').inputValue();
  await page.locator('#btn-ed-sign').click();
  const signed = await textOf(page, '#ed-status');

  // Both numbers in the status line are claims about bytes the page holds.
  const msgBytes = grabInt(signed, /Signed (\d+) bytes/, 'the signed message length');
  const sigBytes = grabInt(signed, /Signature is (\d+) bytes/, 'the signature length');
  expect(msgBytes).toBe(new TextEncoder().encode(message).length);
  expect(sigBytes).toBe(114); // RFC 8032 Ed448 signature size

  // The abbreviated signature on screen must abbreviate a 114-byte blob.
  const shown = await textOf(page, '#ed-sig');
  expect(shown).toMatch(/^[0-9a-f]{20}…[0-9a-f]{20}$/);

  await page.locator('#btn-ed-verify').click();
  await expect(page.locator('#ed-status')).toContainText('VALID');
  await expect(page.locator('#ed-status')).toHaveClass(/\bok\b/);
});

test('verifying or tampering before signing fails with the reason why', async ({ page }) => {
  await page.goto('.');
  for (const id of ['#btn-ed-verify', '#btn-ed-tamper-msg', '#btn-ed-tamper-sig']) {
    await page.locator(id).click();
    await expect(page.locator('#ed-status'), id).toHaveText('Sign a message first.');
    await expect(page.locator('#ed-status'), id).toHaveClass(/\bbad\b/);
  }
});

test('a verdict is about the message on screen, not the one signed earlier', async ({ page }) => {
  await page.goto('.');
  const original = await page.locator('#ed-message').inputValue();
  await page.locator('#btn-ed-sign').click();
  await page.locator('#btn-ed-verify').click();
  const status = page.locator('#ed-status');
  await expect(status).toContainText('VALID');
  await expect(status).toHaveClass(/\bok\b/);

  // The message field stays editable after signing. Editing it by hand is the
  // same forgery the Tamper button performs, so it must reach the same verdict:
  // "✓ VALID" sitting above a message the page never checked is a claim nobody
  // computed, and it contradicts the exhibit's entire point.
  await page.locator('#ed-message').fill(`${original} — and then some`);
  await page.locator('#btn-ed-verify').click();
  await expect(status).toContainText('INVALID signature');
  await expect(status).toHaveClass(/\bbad\b/);

  // Restoring the exact signed bytes verifies again, so the check really is
  // reading the field rather than latching to a failure once it has seen one.
  await page.locator('#ed-message').fill(original);
  await page.locator('#btn-ed-verify').click();
  await expect(status).toContainText('VALID');
  await expect(status).toHaveClass(/\bok\b/);

  // A single-character edit is enough — signatures do not round off.
  await page.locator('#ed-message').fill(original.slice(0, -1) + original.slice(-1).toUpperCase());
  await page.locator('#btn-ed-verify').click();
  await expect(status).toContainText('INVALID signature');

  // Signing the edited message adopts it, and the verdict follows.
  await page.locator('#btn-ed-sign').click();
  await page.locator('#btn-ed-verify').click();
  await expect(status).toContainText('VALID');
});

test('a tampered message fails, says why, and sticks until reset', async ({ page }) => {
  await page.goto('.');
  const original = await page.locator('#ed-message').inputValue();
  await page.locator('#btn-ed-sign').click();
  await page.locator('#btn-ed-verify').click();
  await expect(page.locator('#ed-status')).toContainText('VALID');

  await page.locator('#btn-ed-tamper-msg').click();
  const status = page.locator('#ed-status');
  await expect(status).toHaveClass(/\bbad\b/);
  const text = await textOf(page, '#ed-status');
  expect(text).toContain('INVALID');
  // The stated reason, and the visible field, must agree about what changed.
  expect(text).toContain('message byte 0 flipped');
  const flipped = await page.locator('#ed-message').inputValue();
  const expected =
    String.fromCharCode(original.charCodeAt(0) ^ 0x01) + original.slice(1);
  expect(flipped).toBe(expected);
  expect(flipped).not.toBe(original);

  // README: "tampering now sticks until you re-sign or Reset".
  await page.locator('#btn-ed-verify').click();
  await expect(status).toContainText('INVALID signature');
  await expect(status).toHaveClass(/\bbad\b/);

  // Re-signing the tampered message recovers a valid state.
  await page.locator('#btn-ed-sign').click();
  await page.locator('#btn-ed-verify').click();
  await expect(status).toContainText('VALID');
  await expect(status).toHaveClass(/\bok\b/);
});

test('a tampered signature fails, says why, and sticks until reset', async ({ page }) => {
  await page.goto('.');
  const original = await page.locator('#ed-message').inputValue();
  await page.locator('#btn-ed-sign').click();
  const before = await textOf(page, '#ed-sig');

  await page.locator('#btn-ed-tamper-sig').click();
  const status = page.locator('#ed-status');
  await expect(status).toHaveClass(/\bbad\b/);
  const text = await textOf(page, '#ed-status');
  expect(text).toContain('INVALID');
  expect(text).toContain('signature byte 0 flipped');

  // The flip is real and visible: only the leading byte of the blob changed.
  const after = await textOf(page, '#ed-sig');
  expect(after).not.toBe(before);
  expect(after.slice(2)).toBe(before.slice(2));
  expect(Number.parseInt(after.slice(0, 2), 16)).toBe(
    Number.parseInt(before.slice(0, 2), 16) ^ 0x01,
  );
  // The message was untouched — only the signature was corrupted.
  expect(await page.locator('#ed-message').inputValue()).toBe(original);

  await page.locator('#btn-ed-verify').click();
  await expect(status).toContainText('INVALID signature');

  // Reset restores the message and clears the signature.
  await page.locator('#btn-ed-reset').click();
  await expect(status).toContainText('Reset');
  await expect(status).toHaveClass(/\bok\b/);
  await expect(page.locator('#ed-sig')).toHaveText('(no signature yet)');
  expect(await page.locator('#ed-message').inputValue()).toBe(original);

  // And after Reset, Verify is back to the "nothing to check" failure path.
  await page.locator('#btn-ed-verify').click();
  await expect(status).toHaveText('Sign a message first.');
});

test('the seed expansion panel is internally consistent and hashes what it shows', async ({
  page,
}) => {
  await page.goto('.');
  const seed = await revealEdSeed(page);
  await page.locator('#btn-hashcmp').click();

  const cards = page.locator('#hashcmp-out .hashcmp-card');
  await expect(cards).toHaveCount(2);

  const read = async (i: number) => {
    const t = (await cards.nth(i).textContent() ?? '').replace(/\s+/g, ' ');
    return {
      algo: grab(t, /^\s*(\S+)/, 'the algorithm name'),
      digest: grabInt(t, /(?:fixed|squeezed to) (\d+) bytes/, 'the digest length'),
      seedLen: grabInt(t, /seed \((\d+) B\)/, 'the seed length'),
      seedHex: grab(t, /seed \(\d+ B\): (\S+)/, 'the seed hex'),
      scalar: grabInt(t, /scalar half \((\d+) B\)/, 'the scalar-half length'),
      prefix: grabInt(t, /nonce prefix \((\d+) B\)/, 'the prefix-half length'),
    };
  };

  const sha = await read(0);
  const shake = await read(1);
  expect(sha.algo).toBe('SHA-512');
  expect(shake.algo).toBe('SHAKE256');

  // The halves must sum to the whole in both regimes...
  expect(sha.scalar + sha.prefix).toBe(sha.digest);
  expect(shake.scalar + shake.prefix).toBe(shake.digest);
  // ...and EdDSA squeezes exactly two seed-widths out of the hash.
  expect(sha.digest).toBe(2 * sha.seedLen);
  expect(shake.digest).toBe(2 * shake.seedLen);
  // SHA-512's output is fixed at 64 bytes, which is the whole point being made:
  // it cannot reach the 114 Ed448 needs.
  expect(sha.digest).toBe(64);
  expect(shake.digest).toBeGreaterThan(sha.digest);

  // Regression guard: each card must display the bytes IT hashed. The Ed25519
  // column hashes a 32-byte slice of the seed, so printing the full 57-byte key
  // there would label bytes that were never fed to SHA-512 as "seed (32 B)".
  expect(seed.length / 2).toBe(shake.seedLen);
  expect(shake.seedHex).toBe(shortHexOf(seed, 8));
  expect(sha.seedHex).toBe(shortHexOf(seed.slice(0, sha.seedLen * 2), 8));
  expect(sha.seedHex).not.toBe(shake.seedHex);
});

test('domain separation rejects exactly the off-diagonal, for contexts you choose', async ({
  page,
}) => {
  await page.goto('.');

  // Failure path first: an empty context is refused with a reason.
  await page.locator('#ds-ctx-a').fill('');
  await page.locator('#btn-domainsep').click();
  await expect(page.locator('#domainsep-out')).toHaveText(
    'Both contexts must be non-empty to compare.',
  );
  await page.locator('#ds-ctx-a').fill('alpha-context');
  await page.locator('#ds-ctx-b').fill('');
  await page.locator('#btn-domainsep').click();
  await expect(page.locator('#domainsep-out')).toHaveText(
    'Both contexts must be non-empty to compare.',
  );

  // Contexts supplied through the page's own inputs, so nothing is hardcoded.
  await page.locator('#ds-ctx-b').fill('beta-context');
  await page.locator('#ds-msg').fill('transfer approved');
  await page.locator('#btn-domainsep').click();

  const headers = await page.locator('#domainsep-out .ds-matrix thead th').allTextContents();
  expect(headers).toEqual(['signature', 'under "alpha-context"', 'under "beta-context"']);

  const rows = page.locator('#domainsep-out .ds-matrix tbody tr');
  await expect(rows).toHaveCount(2);
  const grid: string[][] = [];
  for (const row of await rows.all()) {
    grid.push((await row.locator('td').allTextContents()).map((c) => c.trim()));
  }
  // Diagonal verifies, off-diagonal is rejected — the whole claim, asserted.
  expect(grid[0]).toEqual(['sig A', '✓ verifies', '✗ rejected']);
  expect(grid[1]).toEqual(['sig B', '✗ rejected', '✓ verifies']);

  // "two distinct valid signatures" for the same message under the same key.
  const sigs = await page.locator('#domainsep-out .ds-card .mono').allTextContents();
  expect(sigs).toHaveLength(2);
  expect(sigs[0]).not.toBe(sigs[1]);
  const ctxLabels = await page.locator('#domainsep-out .ds-ctx').allTextContents();
  expect(ctxLabels).toEqual(['context = "alpha-context"', 'context = "beta-context"']);
});

// ---- Exhibit 4: the comparison table ---------------------------------------

test('the comparison table agrees with the live exhibits it summarizes', async ({ page }) => {
  await page.goto('.');
  await page.locator('#btn-disclose-4').click();
  await expect(page.locator('#disclose-4')).toBeVisible();
  await page.locator('#btn-compare-curves').click();

  // Every metric row renders — a truncated table would silently drop a claim.
  await expect(page.locator('#compare-body tr')).toHaveCount(11);
  for (const row of await page.locator('#compare-body tr').all()) {
    const cells = await row.locator('td').allTextContents();
    expect(cells).toHaveLength(3);
    for (const c of cells) expect(c.trim().length).toBeGreaterThan(0);
  }

  const bytesOf = (cell: string, what: string) => grabInt(cell, /^(\d+) bytes$/, what);

  // Cross-path 1: the table's X448 private-key size vs the scalar the DH
  // exhibit actually revealed.
  await page.locator('#btn-reveal-dh').click();
  const scalarHex = await textOf(page, '#alice-priv');
  const [, , privRight] = await compareRow(page, 'Private key size');
  expect(bytesOf(privRight, 'X448 private key size')).toBe(scalarHex.length / 2);

  // Cross-path 2: the table's shared-secret size vs the secret the handshake
  // printed in full.
  await page.locator('#btn-handshake').click();
  await page.locator('#btn-compare').click();
  const fullSecret = grab(
    await textOf(page, '#dh-status'),
    /Byte-for-byte match: ([0-9a-f]+)/,
    'the full shared secret',
  );
  const [, , sharedRight] = await compareRow(page, 'Shared secret size');
  expect(bytesOf(sharedRight, 'X448 shared secret size')).toBe(fullSecret.length / 2);

  // Cross-path 3: the table's Ed448 seed size vs the seed the signing exhibit
  // revealed, and its signature size vs the one signing reported.
  const seedHex = await revealEdSeed(page);
  const [, , seedRight] = await compareRow(page, 'EdDSA seed size');
  expect(bytesOf(seedRight, 'Ed448 seed size')).toBe(seedHex.length / 2);

  await page.locator('#btn-ed-sign').click();
  const sigBytes = grabInt(
    await textOf(page, '#ed-status'),
    /Signature is (\d+) bytes/,
    'the signature length',
  );
  const [, sigLeft, sigRight] = await compareRow(page, 'Signature size');
  expect(bytesOf(sigRight, 'Ed448 signature size')).toBe(sigBytes);

  // The "price of the margin" callout claims ~1.8x. Check it against the two
  // sizes the table just computed rather than trusting the prose.
  const ratio = bytesOf(sigRight, 'Ed448 sig') / bytesOf(sigLeft, 'Ed25519 sig');
  const claimed = Number.parseFloat(
    grab(await textOf(page, '.tradeoff-callout'), /~([\d.]+)× the size/, 'the claimed ratio'),
  );
  expect(ratio.toFixed(1)).toBe(claimed.toFixed(1));

  // The two "the price" rows are the ones the copy points at.
  await expect(page.locator('#compare-body tr.tradeoff-row')).toHaveCount(2);

  // Curve448 must be the bigger side on every size row — that IS the trade-off.
  for (const metric of ['Public key size', 'Shared secret size', 'EdDSA pubkey size']) {
    const [, left, right] = await compareRow(page, metric);
    expect(bytesOf(right, metric), metric).toBeGreaterThan(bytesOf(left, metric));
  }

  // The timing row must report all four operations for both curves.
  const [, perfLeft, perfRight] = await compareRow(page, 'Performance (avg, browser)');
  for (const op of ['Keygen', 'DH', 'Sign', 'Verify']) {
    expect(perfLeft, `left ${op}`).toMatch(new RegExp(`${op}: [\\d.]+ ms`));
    expect(perfRight, `right ${op}`).toMatch(new RegExp(`${op}: [\\d.]+ ms`));
  }
});

// ---- Exhibit 5: the RFC vectors --------------------------------------------

test('both RFC vectors pass because computed equals expected', async ({ page }) => {
  await page.goto('.');
  await page.locator('#btn-disclose-5').click();
  await expect(page.locator('#disclose-5')).toBeVisible();

  const vectors = page.locator('#vectors .vector');
  await expect(vectors).toHaveCount(2);

  for (const vector of await vectors.all()) {
    const head = ((await vector.locator('.vector-head').textContent()) ?? '').replace(/\s+/g, ' ');
    // The badge is a verdict; the two hex lines are the evidence for it.
    expect(head).toContain('PASS');
    await expect(vector.locator('.badge.ok')).toHaveCount(1);
    await expect(vector.locator('.badge.bad')).toHaveCount(0);
    expect(head).toMatch(/RFC \d+ §[\d.]+/);

    const lines = await vector.locator('.mono').allTextContents();
    expect(lines).toHaveLength(2);
    const expected = grab(lines[0], /expected: (\S+)/, 'the expected value');
    const computed = grab(lines[1], /computed: (\S+)/, 'the computed value');
    expect(computed).toBe(expected);
    expect(computed).toMatch(/^[0-9a-f]+…[0-9a-f]+$/);
  }
});

// ---- Exhibit 6 + disclosures -----------------------------------------------

test('every advanced exhibit stays collapsed until asked for', async ({ page }) => {
  await page.goto('.');
  for (const [btn, panel] of [
    ['#btn-disclose-4', '#disclose-4'],
    ['#btn-disclose-5', '#disclose-5'],
    ['#btn-disclose-6', '#disclose-6'],
  ]) {
    await expect(page.locator(panel), panel).toBeHidden();
    await expect(page.locator(btn), btn).toHaveAttribute('aria-expanded', 'false');
    await page.locator(btn).click();
    await expect(page.locator(panel), panel).toBeVisible();
    await expect(page.locator(btn), btn).toHaveAttribute('aria-expanded', 'true');
    await page.locator(btn).click();
    await expect(page.locator(panel), panel).toBeHidden();
    await expect(page.locator(btn), btn).toHaveAttribute('aria-expanded', 'false');
  }
});

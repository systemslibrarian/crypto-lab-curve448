// @vitest-environment happy-dom
import { beforeAll, describe, expect, it } from 'vitest';

/**
 * Smoke tests for the rendered demo. main.ts runs its UI wiring as a top-level
 * side effect, so we mount an #app container, import it once, and then assert
 * against the live DOM it produced.
 */
beforeAll(async () => {
  document.body.innerHTML = '<div id="app"></div>';
  await import('../src/main');
  // main.ts defers the live comparison table to a macrotask.
  await new Promise((resolve) => setTimeout(resolve, 0));
});

describe('demo UI', () => {
  it('renders all six exhibits', () => {
    for (let i = 1; i <= 6; i += 1) {
      expect(document.querySelector(`#exhibit-${i}`), `exhibit-${i}`).not.toBeNull();
    }
  });

  it('fills in the Goldilocks prime', () => {
    const prime = document.querySelector('#prime-value')?.textContent ?? '';
    expect(prime.startsWith('72683872429560689')).toBe(true);
  });

  it('shows a matching live X448 handshake', () => {
    const status = document.querySelector('#dh-status');
    expect(status?.textContent).toContain('IDENTICAL');
    expect(status?.classList.contains('ok')).toBe(true);
  });

  it('reveals clamped private scalars on demand', () => {
    const before = document.querySelector('#alice-priv')?.textContent ?? '';
    expect(before).toMatch(/^█+$/); // masked by default

    document.querySelector<HTMLButtonElement>('#btn-reveal-dh')?.click();
    const after = document.querySelector('#alice-priv')?.textContent ?? '';
    expect(after).toMatch(/^[0-9a-f]{112}$/); // 56-byte scalar as hex
    // Revealing also opens the live clamping bit-grid and renders 8 cells/byte.
    expect(document.querySelector('#clampbox')?.hidden).toBe(false);
    expect(document.querySelectorAll('#bitgrid-low .bit')).toHaveLength(8);
    expect(document.querySelectorAll('#bitgrid-high .bit')).toHaveLength(8);
  });

  it('signs and verifies a message end to end', () => {
    document.querySelector<HTMLButtonElement>('#btn-ed-sign')?.click();
    expect(document.querySelector('#ed-status')?.textContent).toContain('Signed');

    document.querySelector<HTMLButtonElement>('#btn-ed-verify')?.click();
    const status = document.querySelector('#ed-status');
    expect(status?.textContent).toContain('VALID');
    expect(status?.classList.contains('ok')).toBe(true);
  });

  it('rejects a tampered signature', () => {
    document.querySelector<HTMLButtonElement>('#btn-ed-sign')?.click();
    document.querySelector<HTMLButtonElement>('#btn-ed-tamper-sig')?.click();
    const status = document.querySelector('#ed-status');
    expect(status?.textContent).toContain('INVALID');
    expect(status?.classList.contains('bad')).toBe(true);
  });

  it('plots the toy curve so scalar·G is a picture, not just hex', () => {
    // The illustrative curve renders a backdrop of points plus the base point G.
    const svg = document.querySelector('#toy-plot');
    expect(svg?.querySelector('.toy-g')).not.toBeNull();
    expect(svg?.querySelectorAll('.toy-dot').length ?? 0).toBeGreaterThan(10);
    // Incrementing the scalar moves k·G to a different point.
    const before = document.querySelector('#toy-eq')?.textContent ?? '';
    const slider = document.querySelector<HTMLInputElement>('#toy-k');
    if (slider) {
      slider.value = '5';
      slider.dispatchEvent(new Event('input'));
    }
    const after = document.querySelector('#toy-eq')?.textContent ?? '';
    expect(after).toContain('5·G');
    expect(after).not.toEqual(before);
  });

  it('gates the ab·G mechanism reveal behind the first handshake', async () => {
    const mech = document.querySelector<HTMLElement>('#mechanism');
    expect(mech?.textContent ?? '').toContain('ab·G');
    // The wire step carries the real public points across the channel.
    document.querySelector<HTMLButtonElement>('#btn-handshake')?.click();
    const wireA = document.querySelector('#wire-a')?.textContent ?? '';
    expect(wireA).toMatch(/[0-9a-f]/);
    // The reveal is deferred until the crossing lands; flush the timers.
    await new Promise((resolve) => setTimeout(resolve, 900));
    expect(mech?.hidden).toBe(false);
  });

  it('expands the seed with both SHAKE256 and SHA-512', () => {
    document.querySelector<HTMLButtonElement>('#btn-hashcmp')?.click();
    const out = document.querySelector('#hashcmp-out')?.textContent ?? '';
    expect(out).toContain('SHAKE256');
    expect(out).toContain('SHA-512');
    // The XOF-vs-fixed distinction must be observable, not just asserted.
    expect(out).toContain('114');
    expect(out).toContain('fixed');
  });

  it('demonstrates domain separation with an off-diagonal rejection', () => {
    document.querySelector<HTMLButtonElement>('#btn-domainsep')?.click();
    const out = document.querySelector('#domainsep-out')?.textContent ?? '';
    // Two distinct valid sigs and cross-context rejection.
    expect(out).toContain('verifies');
    expect(out).toContain('rejected');
  });

  it('tampering the message sticks: re-verify still fails until reset', () => {
    document.querySelector<HTMLButtonElement>('#btn-ed-sign')?.click();
    document.querySelector<HTMLButtonElement>('#btn-ed-tamper-msg')?.click();
    expect(document.querySelector('#ed-status')?.textContent).toContain('INVALID');
    // Verify again — the tamper persisted, so it must still fail.
    document.querySelector<HTMLButtonElement>('#btn-ed-verify')?.click();
    const status = document.querySelector('#ed-status');
    expect(status?.textContent).toContain('INVALID');
    expect(status?.classList.contains('bad')).toBe(true);
    // Reset restores a signable state.
    document.querySelector<HTMLButtonElement>('#btn-ed-reset')?.click();
    expect(document.querySelector('#ed-status')?.textContent).toContain('Reset');
  });

  it('passes both RFC vectors live in the browser', () => {
    const badges = Array.from(document.querySelectorAll('#vectors .badge'));
    expect(badges).toHaveLength(2);
    for (const badge of badges) {
      expect(badge.textContent).toContain('PASS');
      expect(badge.classList.contains('ok')).toBe(true);
    }
  });

  it('renders the live comparison table', () => {
    const rows = document.querySelectorAll('#compare-body tr');
    expect(rows.length).toBeGreaterThan(5);
    expect(document.querySelector('#compare-body')?.textContent).toContain('SHAKE256');
  });
});

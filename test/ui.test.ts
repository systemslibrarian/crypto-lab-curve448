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
    expect(document.querySelector('#dh-clamp')?.hidden).toBe(false);
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

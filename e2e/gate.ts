import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/**
 * Shared machinery for the WCAG gate.
 *
 * Three rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The previous version of
 *     this gate pushed `.reveal, .panel { opacity: 1 !important }` plus a
 *     blanket `animation: none; transition: none` before running axe. That does
 *     not suppress a check, it fabricates the input: partial opacity is real
 *     rendering, and forcing it opaque hands axe a foreground colour the page
 *     never paints. On this lab the injection was load-bearing in the worst
 *     way — every `.reveal` block genuinely renders at `opacity: 0` under
 *     `prefers-reduced-motion: reduce`, so the hero and all six exhibits were
 *     blank for any reader with that preference set, and the injection painted
 *     them back in for the scanner alone. Motion is settled honestly now (see
 *     `settle`), and the composite-aware arithmetic in contrast.ts measures the
 *     colours the page actually paints.
 *
 *  2. EVERY SCAN ASSERTS ITS CONTENT IS PRESENT FIRST, and there are scans well
 *     past first paint. axe over an empty or `display: none` container passes
 *     having checked nothing. The states this page is interesting in — the
 *     a·B = b·A mechanism card, the clamping bit-grid, a revealed scalar, the
 *     two hash-comparison outputs, a tampered-signature verdict, a 380px
 *     viewport — are all reached by a click, and none of them load with the page.
 *
 *  3. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 *
 * The 20s ceiling is deliberately generous rather than tight: on a loaded
 * machine the raf cadence stretches, and the correct response to that is a
 * longer wait, never a narrower scan.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Load the page in a known theme with reduced motion actually in effect.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1 — at
 * file level and inside `test.describe` alike — so the emulation is applied
 * imperatively and then *asserted* from inside the page. Without that assertion
 * a gate can believe it is testing a reduced-motion rendering while the page
 * happily animates; here that assertion is the one that proves the six panels
 * are being scanned in the state a reduced-motion reader actually gets.
 */
export async function boot(
  page: Page,
  theme: 'dark' | 'light',
  /**
   * How the light theme is reached. 'toggle' clicks the header button, which is
   * the interesting path because it fires the theme-swap transitions `settle`
   * has to drain. 'stored' seeds localStorage so the theme is applied by the
   * pre-paint inline script instead — needed by the tab-order test, because
   * clicking the toggle leaves it as the sequential focus navigation starting
   * point and Chromium keeps that even after `blur()`.
   */
  via: 'toggle' | 'stored' = 'toggle'
): Promise<void> {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  if (theme === 'light' && via === 'stored') {
    await page.addInitScript(() => localStorage.setItem('theme', 'light'));
  }
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);

  // The whole page is injected by JS. Assert the parts every scan relies on are
  // really there, so no scan can pass over an empty shell.
  await expect(page.locator('#exhibit-1')).toBeVisible();
  await expect(page.locator('#exhibit-6')).toBeVisible();
  await expect(page.locator('#prime-value')).not.toBeEmpty();
  await expect(page.locator('#toy-plot .toy-label')).toHaveCount(2);
  await expect(page.locator('#vectors .vector')).toHaveCount(2);
  // compareCurves() is deferred to a setTimeout(0) after first paint, so the
  // comparison table fills asynchronously. Measured: it always lands before
  // `goto` resolves, but "always so far" is not an invariant worth trusting.
  await expect(page.locator('#compare-body tr')).not.toHaveCount(0);

  if (theme === 'light' && via === 'toggle') {
    await page.locator('#cl-theme-toggle').click();
  }
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  await settle(page);

  // Reduced motion must leave the content visible, not merely un-animated.
  // Cancelling the `rise` animation without restoring its end state left every
  // `.reveal` block at opacity 0.
  const faded = await page.evaluate(() =>
    Array.from(document.querySelectorAll('.reveal'))
      .filter((el) => parseFloat(getComputedStyle(el).opacity) < 1)
      .map((el) => el.id || el.className)
  );
  expect(faded, 'no .reveal block may stay transparent under reduced motion').toEqual([]);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this, and it is invisible at
 * first paint: the defect that lived here was a revealed 112-character private
 * scalar with no break opportunity, which dragged the document to 1739px inside
 * a 1280px viewport and to 1158px inside a 380px one — but only after the
 * "Reveal private scalars" button had been pressed.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;
    const widest = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right)[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''} @${Math.round(widest.r.width)}px`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Scan the page as it currently stands.
 *
 * Three assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the third assertion computes those
 *    ratios arithmetically. That exemption is doing a lot of work on this page:
 *    the body paints a three-layer gradient, so axe declined to compute a ratio
 *    for *every single text node* — 159 nodes at first paint, 292 with every
 *    disclosure open. Not one contrast result had ever reached `violations`
 *    here, which is why five genuine AA failures survived a green gate.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node,
 *    measured against the surface the text is genuinely painted on, including
 *    SVG `<text>` (which takes its ink from `fill`, not `color`).
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  expect(violations, `axe violations in state: ${label}`).toEqual([]);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  expect(unexplainedIncomplete, `axe incomplete results in state: ${label}`).toEqual([]);

  const contrast = formatContrastFailures(await auditContrast(page));
  expect(contrast, `measured contrast failures in state: ${label}`).toEqual([]);

  await expectNoHorizontalOverflow(page, label);
}

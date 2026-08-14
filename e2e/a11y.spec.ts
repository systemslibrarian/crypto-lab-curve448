import { expect, test } from '@playwright/test';
import { boot, expectBaselineNotStale, scan } from './gate';

/**
 * WCAG regression gate — first paint and focus states.
 *
 * The driven states (handshake, clamping, signature verdicts, disclosures,
 * narrow viewports) live in a11y-dynamic.spec.ts. This file covers what the
 * page looks like on arrival, in both themes, plus the two skip links, which
 * are parked off-screen at `left: -9999px` until focus and are therefore only
 * really rendered — and only really measurable — once focused.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations at first paint in ${theme} theme`, async ({ page }) => {
    await boot(page, theme);
    await scan(page, `${theme} first paint`);

    // The non-text baseline's third rule: a listed finding that no longer
    // appears fails, so a fixed entry has to be deleted and the file can only
    // shrink. `expectBaselineNotStale` was exported from `gate.ts` and never
    // imported, so of the three rules `nontext-baseline.ts` advertises only the
    // first two had ever run.
    //
    // It belongs here rather than in `a11y-dynamic.spec.ts`. `nonTextSeen` is
    // module state, so a call only sees what its own test drove — and both
    // baselined entries are the shared top bar, which is painted at first paint
    // in both themes. This test is the one whose whole subject is that state,
    // so it sees everything the baseline lists and needs nothing driven.
    expectBaselineNotStale();
  });

  test(`skip links are accessible when focused in ${theme} theme`, async ({ page }) => {
    // 'stored' rather than 'toggle': this test asserts tab order from a
    // pristine focus state, and clicking the theme button would leave it as the
    // sequential focus navigation starting point.
    await boot(page, theme, 'stored');

    // The shared site header's skip link is the first focusable element.
    await page.keyboard.press('Tab');
    await expect(page.locator('.cl-skip-link')).toBeFocused();
    await scan(page, `${theme} site skip link focused`);

    await page.locator('.skip-link').focus();
    await expect(page.locator('.skip-link')).toBeFocused();
    // Focused, it leaves its off-screen parking spot and becomes real content.
    const box = await page.locator('.skip-link').boundingBox();
    expect(box, 'the focused skip link must be on screen').not.toBeNull();
    expect(box!.x).toBeGreaterThanOrEqual(0);
    await scan(page, `${theme} in-page skip link focused`);
  });
}

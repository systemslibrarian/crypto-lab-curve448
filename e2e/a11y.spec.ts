import { expect, test } from '@playwright/test';
import { boot, scan } from './gate';

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

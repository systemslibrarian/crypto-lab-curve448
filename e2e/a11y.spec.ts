import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Scans the full page in both themes with every
 * collapsible / animated region revealed. This lab has no <details>; its
 * sections use class-toggled `.panel.reveal` blocks that animate in from
 * opacity:0, so we neutralize the animations (and reveal any native
 * disclosure widgets, just in case) before scanning so nothing is measured
 * mid-transition.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function revealAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    // Expand any native disclosure widgets.
    for (const details of document.querySelectorAll('details')) {
      (details as HTMLDetailsElement).open = true;
    }
    // Neutralize the rise/fade animations and any transitions so panels are
    // scanned in their settled, fully-opaque state (what a user sees once the
    // animation completes) rather than mid-transition.
    const style = document.createElement('style');
    style.textContent =
      '*, *::before, *::after { animation: none !important; transition: none !important; }' +
      '.reveal, .panel { opacity: 1 !important; transform: none !important; }';
    document.head.appendChild(style);
    // Reveal any class-toggled or [hidden] panels/accordions so their content
    // is scanned. (Interactive-only widgets such as copy buttons stay hidden.)
    for (const panel of document.querySelectorAll('.panel, .accordion, .tab-panel')) {
      panel.classList.add('open', 'active');
      panel.removeAttribute('hidden');
    }
  });
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await revealAll(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await revealAll(page);
  await scan(page);
});

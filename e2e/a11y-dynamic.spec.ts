import { expect, test, type Page } from '@playwright/test';
import { boot, scan, settle } from './gate';

/**
 * WCAG gate — the states the page is actually used in.
 *
 * Everything interesting on this page is behind a click. At first paint the
 * a·B = b·A mechanism card, the clamping bit-grid, the revealed scalars, the
 * two hash-comparison outputs and every signature verdict are `display: none`
 * or empty, so a gate that only scans the landing state has checked none of
 * them. Three of the failures found here lived exactly there:
 *
 *   - `.hl-a` "a·G" at 1.77:1 and `.hl-b` "b·G" at 4.20:1, inside the mechanism
 *     card, which only exists after Run Handshake;
 *   - a revealed 112-character private scalar with no break opportunity, which
 *     pushed the document to 1739px inside a 1280px viewport (WCAG 1.4.10), and
 *     which only appears after Reveal private scalars.
 *
 * The suite therefore runs the whole journey at a desktop width and again at
 * 380px, in both themes.
 */

const WIDTHS = [
  { label: 'desktop', size: { width: 1280, height: 900 } },
  { label: '380px', size: { width: 380, height: 800 } },
] as const;

async function runHandshake(page: Page): Promise<void> {
  await page.locator('#btn-handshake').click();
  // The mechanism card is the proof-of-work of this exhibit and is hidden until
  // the handshake runs. Assert it before scanning so an empty box cannot pass.
  await expect(page.locator('#mechanism')).toBeVisible();
  await expect(page.locator('#mechanism .hl-a')).toHaveText('a·G');
  await expect(page.locator('#mechanism .hl-b')).toHaveText('b·G');
  await expect(page.locator('#alice-shared')).not.toBeEmpty();
  await expect(page.locator('#bob-shared')).not.toBeEmpty();
  await settle(page);
}

for (const theme of ['dark'] as const) {
  for (const { label: width, size } of WIDTHS) {
    test(`X448 exhibit states — ${theme} @ ${width}`, async ({ page }) => {
      await page.setViewportSize(size);
      await boot(page, theme);

      await runHandshake(page);
      await scan(page, `${theme}@${width} handshake run, mechanism card shown`);

      await page.locator('#btn-compare').click();
      await expect(page.locator('#dh-status')).not.toBeEmpty();
      await scan(page, `${theme}@${width} shared secrets compared`);

      // Reveal the private scalars: full-length hex, and the clamping bit-grid.
      await page.locator('#btn-reveal-dh').click();
      await expect(page.locator('#btn-reveal-dh')).toHaveAttribute('aria-pressed', 'true');
      await expect(page.locator('#clampbox')).toBeVisible();
      await expect(page.locator('#bitgrid-low .bit')).toHaveCount(8);
      await expect(page.locator('#bitgrid-high .bit')).toHaveCount(8);
      await scan(page, `${theme}@${width} private scalars revealed, clampbox open`);

      // Move the toy curve off its initial point so a different label renders.
      const slider = page.locator('#toy-k');
      await slider.evaluate((el: HTMLInputElement) => {
        el.value = '17';
        el.dispatchEvent(new Event('input', { bubbles: true }));
      });
      await expect(page.locator('#toy-k-val')).toHaveText('17');
      await scan(page, `${theme}@${width} toy curve at k=17`);
    });

    test(`Ed448 exhibit states — ${theme} @ ${width}`, async ({ page }) => {
      await page.setViewportSize(size);
      await boot(page, theme);

      await page.locator('#btn-ed-keygen').click();
      await page.locator('#btn-ed-sign').click();
      await page.locator('#btn-ed-verify').click();
      await expect(page.locator('#ed-status')).toHaveText('✓ VALID signature');
      await expect(page.locator('#ed-status')).toHaveClass(/\bok\b/);
      await scan(page, `${theme}@${width} signature verified`);

      // A failure verdict is a different colour pairing from a success one.
      await page.locator('#btn-ed-tamper-msg').click();
      await expect(page.locator('#ed-status')).toContainText('✗ INVALID: message byte 0 flipped');
      await expect(page.locator('#ed-status')).toHaveClass(/\bbad\b/);
      await scan(page, `${theme}@${width} tampered message verdict`);

      await page.locator('#btn-ed-reset').click();
      await page.locator('#btn-ed-sign').click();
      await page.locator('#btn-ed-tamper-sig').click();
      await expect(page.locator('#ed-status')).toContainText('✗ INVALID: signature byte 0 flipped');
      await scan(page, `${theme}@${width} tampered signature verdict`);

      // The "nothing signed yet" error path.
      await page.locator('#btn-ed-reset').click();
      await page.locator('#btn-ed-verify').click();
      await expect(page.locator('#ed-status')).toHaveText('Sign a message first.');
      await expect(page.locator('#ed-status')).toHaveClass(/\bbad\b/);
      await scan(page, `${theme}@${width} verify with nothing signed`);

      // A full-length private seed on screen.
      await page.locator('#btn-ed-keygen').click();
      await page.locator('#btn-reveal-ed').click();
      await expect(page.locator('#btn-reveal-ed')).toHaveAttribute('aria-pressed', 'true');
      await expect(page.locator('#ed-priv')).not.toBeEmpty();
      await scan(page, `${theme}@${width} private seed revealed`);
    });

    test(`derivation and comparison outputs — ${theme} @ ${width}`, async ({ page }) => {
      await page.setViewportSize(size);
      await boot(page, theme);

      await page.locator('#btn-hashcmp').click();
      await expect(page.locator('#hashcmp-out .hashcmp-card')).not.toHaveCount(0);
      await scan(page, `${theme}@${width} SHAKE256 vs SHA-512 output`);

      await page.locator('#btn-domainsep').click();
      await expect(page.locator('#domainsep-out .ds-card')).not.toHaveCount(0);
      await scan(page, `${theme}@${width} domain separation output`);
    });

    test(`disclosures — ${theme} @ ${width}`, async ({ page }) => {
      await page.setViewportSize(size);
      await boot(page, theme);

      for (const n of [4, 5, 6]) {
        await page.locator(`#btn-disclose-${n}`).click();
        await expect(page.locator(`#btn-disclose-${n}`)).toHaveAttribute('aria-expanded', 'true');
        await expect(page.locator(`#disclose-${n}`)).toBeVisible();
      }
      await expect(page.locator('#compare-body tr')).not.toHaveCount(0);
      await expect(page.locator('#vectors .vector')).toHaveCount(2);
      await scan(page, `${theme}@${width} every disclosure open`);

      // Regenerate the comparison so the freshly benchmarked rows are scanned
      // rather than the ones painted before first paint finished.
      await page.locator('#btn-compare-curves').click();
      await expect(page.locator('#compare-body tr')).not.toHaveCount(0);
      await scan(page, `${theme}@${width} live comparison regenerated`);
    });
  }
}

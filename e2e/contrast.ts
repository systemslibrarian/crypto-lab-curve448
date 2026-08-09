import type { Page } from '@playwright/test';

/**
 * Composite-aware WCAG 1.4.3 contrast measurement.
 *
 * This exists because axe is not a complete contrast oracle. Two classes of
 * text never reach the `violations` array a gate asserts on:
 *
 *  - text over a background *gradient* — axe declines to compute a ratio and
 *    files the node under `incomplete`;
 *  - text faded by an ancestor's `opacity` — axe reads the declared `color`,
 *    which is not the colour that lands on screen.
 *
 * So: walk every element that owns text, composite the real painted result
 * (translucent colours, gradient stops and opacity groups included), and
 * compute the ratio against the surface the text is genuinely sitting on
 * rather than against white. A gradient is judged at its worst stop.
 *
 * Opacity is modelled the way the compositor actually does it: an element with
 * `opacity < 1` renders its subtree into a group, then composites the group
 * over the backdrop. That means the *text* and the *background beside it* fade
 * onto the same backdrop independently — which is why both are carried through
 * the walk as a pair rather than fading the foreground alone.
 *
 * The ancestor walk is geometry-aware, because DOM ancestry is not the same
 * thing as "painted underneath". An absolutely positioned child can render
 * entirely outside its parent's box, and then the parent's background is simply
 * not behind it. This page has exactly that: `.security-scale-tick` is a 3x22px
 * bar painted in `--heading`, and its label `span` is pushed clear above the bar
 * by `top: -1.35rem`, so it lands on the panel. A purely ancestral walk composited
 * the label's `--heading` text onto the tick's `--heading` bar and reported a
 * fabricated 1:1 for text that a screenshot shows plainly legible. So an
 * ancestor's own paint is applied only when its border box actually intersects
 * the text's box; a partial intersection still counts, so the judgement stays
 * worst-case. Opacity is unconditional either way — an opacity group fades its
 * whole subtree wherever that subtree happens to paint.
 */

export interface ContrastFailure {
  selector: string;
  text: string;
  foreground: string;
  background: string;
  fontSize: number;
  fontWeight: number;
  required: number;
  ratio: number;
}

export async function auditContrast(page: Page): Promise<ContrastFailure[]> {
  return page.evaluate(() => {
    interface RGBA {
      r: number;
      g: number;
      b: number;
      a: number;
    }

    const TRANSPARENT: RGBA = { r: 0, g: 0, b: 0, a: 0 };
    const WHITE: RGBA = { r: 255, g: 255, b: 255, a: 1 };

    const parse = (c: string): RGBA | null => {
      const m = c.match(/rgba?\(([^)]+)\)/);
      if (!m) return null;
      const p = m[1]
        .split(/[ ,/]+/)
        .filter(Boolean)
        .map(Number);
      if (p.length < 3 || p.some((n) => Number.isNaN(n))) return null;
      return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 };
    };

    /** Standard source-over compositing of a (possibly translucent) src on dst. */
    const over = (src: RGBA, dst: RGBA): RGBA => {
      const a = src.a + dst.a * (1 - src.a);
      if (a === 0) return TRANSPARENT;
      return {
        r: (src.r * src.a + dst.r * dst.a * (1 - src.a)) / a,
        g: (src.g * src.a + dst.g * dst.a * (1 - src.a)) / a,
        b: (src.b * src.a + dst.b * dst.a * (1 - src.a)) / a,
        a,
      };
    };

    const fade = (c: RGBA, o: number): RGBA => (o >= 1 ? c : { ...c, a: c.a * o });

    const luminance = (c: RGBA): number => {
      const f = (v: number): number => {
        const s = v / 255;
        return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
      };
      return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
    };

    const ratio = (a: RGBA, b: RGBA): number => {
      const l1 = luminance(a);
      const l2 = luminance(b);
      return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
    };

    const gradientStops = (cs: CSSStyleDeclaration): RGBA[] | null => {
      const bi = cs.backgroundImage;
      if (!bi || bi === 'none' || !/gradient/.test(bi)) return null;
      const cols = bi.match(/rgba?\([^)]+\)/g);
      if (!cols) return null;
      const stops = cols.map(parse).filter((c): c is RGBA => c !== null && c.a > 0);
      return stops.length ? stops : null;
    };

    /**
     * Every paint this element's own box could put behind its text: the
     * background-color, plus one candidate per gradient stop layered on top of
     * it, so a gradient is judged at its worst point rather than at an average
     * that renders nowhere.
     */
    const ownPaints = (cs: CSSStyleDeclaration): RGBA[] => {
      const color = parse(cs.backgroundColor) ?? TRANSPARENT;
      const grad = gradientStops(cs);
      if (!grad) return [color];
      return grad.map((g) => over(g, color));
    };

    /** Do two border boxes share any painted area at all? */
    const intersects = (a: DOMRect, b: DOMRect): boolean =>
      Math.max(0, Math.min(a.right, b.right) - Math.max(a.left, b.left)) > 0 &&
      Math.max(0, Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top)) > 0;

    /**
     * Does this element's own `clip` / `clip-path` reduce it to zero area?
     *
     * `clip: rect(t, r, b, l)` applies only to absolutely positioned boxes and
     * is what the classic `.sr-only` recipe uses; `clip-path: inset(50%)` is the
     * modern spelling of the same trick. Either at zero area means the
     * compositor draws nothing, so there is no painted ink to measure — but the
     * box still has a 1x1 rect, a non-zero opacity and passes
     * `checkVisibility()`, so every other test in `isVisible` says "visible".
     * Without this the walk composites visually-hidden text against whatever
     * surface it happens to sit on and INVENTS failures: 1.15:1 for a card's
     * screen-reader-only suit name, 4.39:1 for an `.sr-only` twin of an
     * `aria-hidden` glyph. Deliberately narrow — only a ZERO-area clip
     * qualifies, so a real partial clip is still measured.
     */
    const clippedToNothing = (cs: CSSStyleDeclaration): boolean => {
      const clip = cs.clip;
      if (clip && clip !== 'auto') {
        const nums = clip.match(/-?[\d.]+/g)?.map(Number);
        if (nums && nums.length === 4) {
          // Tuple-typed: under `noUncheckedIndexedAccess` a plain destructure of
          // `number[]` yields `number | undefined` for each name, which fails
          // `tsc --noEmit` in the repos whose build typechecks the e2e tree.
          const [top, right, bottom, left] = nums as [number, number, number, number];
          if (bottom - top <= 0 || right - left <= 0) return true;
        }
      }
      const path = cs.clipPath;
      if (path && path.startsWith('inset(')) {
        const pct = path.match(/([\d.]+)%/g)?.map((v) => parseFloat(v)) ?? [];
        if (pct.length && pct.every((v) => v >= 50)) return true;
      }
      return false;
    };

    const isVisible = (el: Element): boolean => {
      const cs = getComputedStyle(el);
      if (cs.display === 'none' || cs.visibility === 'hidden') return false;
      if (parseFloat(cs.opacity) === 0) return false;
      // Visually hidden: a real box that paints no pixels. See above.
      if (clippedToNothing(cs)) return false;
      // A closed <details> hides its body with `content-visibility: hidden`
      // rather than `display: none`, and Chromium keeps the last laid-out
      // geometry for that subtree — so every test above passes for text that
      // paints nothing. The stale rect is stale in the way that hurts most: it
      // sits where the OPEN panel used to be, which on a narrow page can fall
      // outside the collapsed panel's box entirely. The geometry-aware ancestor
      // walk below then correctly finds no panel behind it and composites the
      // text onto the page gradient, reporting a ratio nothing on screen has.
      //
      // Found in e91, where it produced a 3.86:1 for a collapsed disclosure's
      // <code> at 380px. Ported back here because this helper is the model the
      // sweep copies from, and the same misfire is latent in any lab whose
      // <details> sits low enough on a narrow viewport.
      //
      // The open state is a real state; the gate scans it explicitly, and this
      // same element is measured for real there.
      if ((el as HTMLElement).checkVisibility?.() === false) return false;
      const r = el.getBoundingClientRect();
      if (r.width <= 0 || r.height <= 0) return false;
      // Text parked off the left/top edge of the page paints no pixels. This is
      // the WCAG-sanctioned "visually hidden until focused" idiom — both skip
      // links on this page sit at `left: -9999px` until focus makes them
      // `position: static`. Measuring the parked copy invented a failure for
      // text that is not on screen; the focused rendering is a real state and
      // the gate scans it explicitly instead.
      // DOCUMENT space, not viewport space. `getBoundingClientRect()` is
      // viewport-relative, so once Playwright scrolls a control into view every
      // element ABOVE the viewport has `bottom <= 0` and this guard silently
      // dropped it from the walk. Measured on one lab: 27 of 105 text-owning
      // elements — 26% of the page — vanished from the oracle at the end of a
      // drive. A green contrast run on a page taller than the viewport could
      // not be trusted. Adding the scroll offset restores the original intent
      // (text parked off the top/left of the DOCUMENT — the "visually hidden
      // until focused" idiom) without hiding the part of the page that has
      // merely been scrolled past.
      if (r.right + window.scrollX <= 0 || r.bottom + window.scrollY <= 0) return false;
      return true;
    };

    const ownText = (el: Element): string => {
      let t = '';
      for (const n of Array.from(el.childNodes)) {
        if (n.nodeType === Node.TEXT_NODE) t += n.textContent ?? '';
      }
      return t.trim();
    };

    const describe = (el: Element): string => {
      let s = el.tagName.toLowerCase();
      if (el.id) s += `#${el.id}`;
      const cls = el.getAttribute('class');
      if (cls) s += `.${cls.trim().split(/\s+/).join('.')}`;
      return s;
    };

    /**
     * WCAG 1.4.3 exempts text that is part of an *inactive* user-interface
     * component, and axe skips disabled controls for the same reason. Honour
     * that here so a deliberately dimmed disabled control is not reported as a
     * failure the spec does not actually require fixing.
     */
    const inactive = (el: Element): boolean => {
      let n: Element | null = el;
      while (n) {
        if ((n as HTMLInputElement).disabled === true) return true;
        if (n.getAttribute('aria-disabled') === 'true') return true;
        n = n.parentElement;
      }
      return false;
    };

    const failures: unknown[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const text = ownText(el);
      if (!text) continue;
      if (!isVisible(el)) continue;
      if (inactive(el)) continue;

      const cs = getComputedStyle(el);
      // SVG text takes its ink from `fill`, not `color`. The toy-curve plot
      // labels its points with real, informative `<text>` nodes, and reading
      // `color` there measures an inherited value the glyphs are not painted in.
      const svgText = el.namespaceURI === 'http://www.w3.org/2000/svg';
      const fgRaw = parse(svgText ? cs.fill : cs.color);
      if (!fgRaw) continue;

      const size = parseFloat(cs.fontSize);
      const weight = parseInt(cs.fontWeight, 10) || 400;
      const large = size >= 24 || (size >= 18.66 && weight >= 700);
      const required = large ? 3 : 4.5;

      // Carry (text, adjacent background) as a pair up the ancestor chain,
      // painting each ancestor's own background beneath both and applying that
      // ancestor's opacity to both, exactly as the compositor would.
      const textBox = el.getBoundingClientRect();
      let pairs: { fg: RGBA; bg: RGBA }[] = [{ fg: fgRaw, bg: TRANSPARENT }];
      let node: Element | null = el;
      while (node) {
        const ncs = getComputedStyle(node);
        const opacity = parseFloat(ncs.opacity);
        // An ancestor that does not overlap the text paints nothing behind it.
        const paints =
          node === el || intersects(textBox, node.getBoundingClientRect())
            ? ownPaints(ncs)
            : [TRANSPARENT];
        const next: { fg: RGBA; bg: RGBA }[] = [];
        for (const p of pairs) {
          for (const paint of paints) {
            next.push({
              fg: fade(over(p.fg, paint), opacity),
              bg: fade(over(p.bg, paint), opacity),
            });
          }
        }
        pairs = next;
        // Stop once the accumulated backdrop is fully opaque: nothing further
        // out can change the painted result.
        if (pairs.every((p) => p.bg.a >= 1)) break;
        node = node.parentElement;
      }

      let worst: { r: number; fg: RGBA; bg: RGBA } | null = null;
      for (const p of pairs) {
        const fg = over(p.fg, WHITE);
        const bg = over(p.bg, WHITE);
        const r = ratio(fg, bg);
        if (!worst || r < worst.r) worst = { r, fg, bg };
      }
      if (!worst) continue;

      // Round to 2dp before comparing so a value that is exactly on the floor
      // (e.g. 4.50) is not failed by float noise, and one just under it is not
      // rounded up into a pass.
      const rounded = Math.round(worst.r * 100) / 100;
      if (rounded >= required) continue;

      const show = (c: RGBA): string =>
        `rgb(${[c.r, c.g, c.b].map((v) => Math.round(v)).join(', ')})`;

      failures.push({
        selector: describe(el),
        text: text.slice(0, 60),
        foreground: show(worst.fg),
        background: show(worst.bg),
        fontSize: size,
        fontWeight: weight,
        required,
        ratio: rounded,
      });
    }
    return failures as never;
  });
}

/** Render failures as short strings so an assertion diff is readable. */
export function formatContrastFailures(failures: ContrastFailure[]): string[] {
  return failures.map(
    (f) =>
      `${f.ratio}:1 (needs ${f.required}:1) ${f.selector} — fg ${f.foreground} on ${f.background} — "${f.text}"`
  );
}

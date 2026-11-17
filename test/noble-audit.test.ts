/* What "audited" covers for the @noble/curves this lab ships.
 *
 * The README said "The app uses `@noble/curves` for audited arithmetic", with
 * no version. The library records its latest independent audit as "at version
 * 2.3.0, in Aug 2026, by [Trail of Bits]", scope "everything"; this lab pins
 * ^2.4.0, one release past it.
 *
 * Both sides are read — the README and the installed library's own README — so
 * an upgrade that changes the audit record fails here rather than passing.
 */
import { describe, expect, it } from 'vitest';

import nobleReadme from '../node_modules/@noble/curves/README.md?raw';
import readmeSource from '../README.md?raw';
import pkg from '../package.json';

describe('the @noble/curves audit claim', () => {
  it('pins a version later than the latest audit the library records', () => {
    expect(pkg.dependencies['@noble/curves']).toBe('^2.4.0');
    expect(nobleReadme).toContain('The library has been audited');
    expect(nobleReadme).toMatch(/at version 2\.3\.0, in Aug 2026, by \[Trail of Bits\]/);
    expect(nobleReadme).not.toMatch(/at version 2\.4\.\d+, in [A-Z]/);
  });

  it('states that version in the README', () => {
    const flat = readmeSource.replace(/\s+/g, ' ');
    expect(flat).not.toContain('for audited arithmetic');
    expect(flat).toContain('at version 2.3.0, in Aug 2026, by [Trail of Bits]');
    expect(flat).toContain('pinned `^2.4.0`');
  });
});

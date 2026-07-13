/// <reference types="vitest/config" />
import { defineConfig } from 'vite';

export default defineConfig({
  base: '/crypto-lab-curve448/',
  test: {
    // Vitest owns the unit/DOM smoke tests under test/. The Playwright axe
    // suite under e2e/ is driven by `npm run test:a11y`, not Vitest — exclude it
    // so `npm test` doesn't try to collect Playwright's test() as a Vitest spec.
    include: ['test/**/*.test.ts'],
  },
});

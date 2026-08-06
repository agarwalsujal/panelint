import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    // A scan must stay cheap enough to run on every commit (DESIGN.md §1).
    // A test that takes longer than this is a signal, not an inconvenience.
    testTimeout: 20_000,
    reporters: ['default'],
  },
});

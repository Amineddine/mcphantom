import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    testTimeout: 30_000,
    hookTimeout: 30_000,
    // Integration tests spawn real child MCP servers; keep files isolated in forks, but cap how many
    // run at once. Unbounded file parallelism starves CPU on small machines (and CI runners), which
    // makes child-process MCP startup exceed its timeout and produces flaky failures.
    pool: 'forks',
    maxWorkers: 2,
  },
});

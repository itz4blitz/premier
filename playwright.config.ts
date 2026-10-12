import { defineConfig } from '@playwright/test';

const e2ePort = Number(process.env.PREMIER_E2E_PORT ?? 4318);
const e2eBaseUrl = `http://127.0.0.1:${e2ePort}`;

const ci = Boolean(process.env.CI);

export default defineConfig({
  testDir: './tests',
  testIgnore: 'docs/**',
  // A stray `test.only` must not turn a CI run green by skipping everything else.
  forbidOnly: ci,
  // One retry in CI separates a flake from a failure; locally a failure should be seen at once.
  retries: ci ? 1 : 0,
  timeout: 30_000,
  expect: { timeout: 5_000 },
  use: {
    baseURL: e2eBaseUrl,
    httpCredentials: { username: 'premier', password: 'e2e-secret' },
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure'
  },
  webServer: {
    command: 'node scripts/e2e-server.mjs',
    url: `${e2eBaseUrl}/api/health`,
    // The seed builds the viewer and the CLI before it records seven traces; a cold cargo build
    // alone can take longer than three minutes. PREMIER_E2E_SERVER_TIMEOUT_MS overrides it.
    timeout: Number(process.env.PREMIER_E2E_SERVER_TIMEOUT_MS ?? 600_000),
    reuseExistingServer: false
  },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }]
});

import { defineConfig, devices } from '@playwright/test'

// The suite mocks the API at the browser level (page.route), so only the Vite
// dev server is required — no Go backend or live LLM. This makes the E2E
// deterministic and runnable in CI after `npx playwright install chromium`.
export default defineConfig({
  testDir: './e2e',
  timeout: 30_000,
  fullyParallel: true,
  use: {
    baseURL: 'http://localhost:5173',
    trace: 'on-first-retry',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'npm run dev',
    url: 'http://localhost:5173',
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
})

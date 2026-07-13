import { test, expect, type Page } from '@playwright/test'

// A canned classification the mocked backend returns for any /classify call.
const classified = {
  severity: 'P1',
  attack_type: 'Brute Force',
  confidence: 0.94,
  mitre: { tactic: 'Credential Access', technique_id: 'T1110.001', technique: 'Password Guessing' },
  iocs: ['8.8.8.8', 'root'],
  remediation: 'Block the offending source IP immediately and rotate the affected credentials.',
  summary: 'SSH brute force detected from 8.8.8.8 targeting root',
  event: {
    raw: 'Jan 1 00:00:00 host sshd[1]: Failed password for root from 8.8.8.8',
    timestamp: '2026-07-06T00:00:00Z', message: 'Failed password for root', source: 'syslog',
  },
  processed_at: '2026-07-06T00:00:00Z',
}

// mockApi stubs every network call the dashboard makes so no backend is needed.
async function mockApi(page: Page) {
  await page.route('**/api/classify', (r) => r.fulfill({ json: classified }))
  await page.route('**/api/health', (r) => r.fulfill({ json: { status: 'ok' } }))
  await page.route('**/api/analytics/summary', (r) =>
    r.fulfill({ json: { total_events: 0, attack_type_counts: {}, timeline: [], mitre_tactics: {} } }),
  )
}

test.beforeEach(async ({ page }) => {
  await mockApi(page)
  await page.goto('/')
})

test('classifying a log line shows an event card with severity and MITRE', async ({ page }) => {
  await page.getByPlaceholder(/Paste a log line/i).fill(classified.event.raw)
  await page.getByRole('button', { name: /Classify/i }).click()

  await expect(page.getByText('Brute Force').first()).toBeVisible()
  await expect(page.getByText(/Critical/).first()).toBeVisible()
  await expect(page.getByText(/T1110\.001/).first()).toBeVisible()
})

test('the detail panel shows the recommended action', async ({ page }) => {
  await page.getByPlaceholder(/Paste a log line/i).fill(classified.event.raw)
  await page.getByRole('button', { name: /Classify/i }).click()

  await expect(page.getByText(/Block the offending source IP/i)).toBeVisible()
})

test('the MITRE ATT&CK heatmap renders', async ({ page }) => {
  await expect(page.getByText(/MITRE ATT&CK Heatmap/i)).toBeVisible()
})

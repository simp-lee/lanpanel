import { defineConfig, devices } from '@playwright/test';
const executablePath = process.env.LANPANEL_CHROMIUM_PATH;
export default defineConfig({
  testDir: './tests/playwright', testMatch: '**/*.spec.js', fullyParallel: false, workers: 1, reporter: 'line',
  projects: [{ name: 'local_fixture', use: { ...devices['Desktop Chrome'], browserName: 'chromium', headless: true, launchOptions: executablePath ? { executablePath } : {} } }],
});

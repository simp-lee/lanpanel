import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './specs',
  timeout: 60_000,
  use: {
    baseURL: process.env.LANPANEL_UI_URL || 'http://127.0.0.1:18080',
    trace: 'off',
  },
});

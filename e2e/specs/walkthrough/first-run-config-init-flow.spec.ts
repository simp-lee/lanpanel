import { expect, test } from '@playwright/test';
import * as path from 'node:path';
import {
  appendEvidence,
  copyLatestJobArtifacts,
  csrfToken,
  expectJobText,
  expectJobsPage,
  inputValue,
  loginWithStartupToken,
  postJob,
  prepareJourneyArtifacts,
  scanArtifactDir,
  screenshot,
  stateDirFromResourcesPage,
} from './helpers';

test.describe('walkthrough: first-run-config-init-flow', () => {
  test('captures missing-config recovery for main and app config', async ({ page }, testInfo) => {
    const dir = await prepareJourneyArtifacts(testInfo, 'first-run-config-init-flow');
    await appendEvidence(dir, [
      '- Required testserver flags: `E2E_TESTSERVER_FLAGS=-preseed-configs=false`',
      '',
    ]);
    await loginWithStartupToken(page);

    await page.goto('/settings');
    await expect(page.getByRole('button', { name: 'Create Example Main Config' })).toBeVisible();
    await screenshot(page, dir, '01-settings-missing-config.png');
    const configPath = await inputValue(page, 'config_path');
    const stateDir = path.join(path.dirname(configPath), 'state');
    const token = await csrfToken(page);

    await page.getByRole('button', { name: 'Create Example Main Config' }).click();
    await expectJobsPage(page);
    await expectJobText(page, 'wrote example config');
    await copyLatestJobArtifacts(stateDir, dir, 'main-init', 'config_save');
    await screenshot(page, dir, '02-main-init-job.png');

    await page.goto('/settings');
    await expect(page.getByRole('button', { name: 'Save' })).toBeVisible();
    await screenshot(page, dir, '03-settings-form-after-init.png');

    await page.goto('/resources');
    await expect(page.getByRole('button', { name: 'Create Example App Config' })).toBeVisible();
    await screenshot(page, dir, '04-resources-missing-app-config.png');
    const appConfigPath = await inputValue(page, 'app_config_path');

    await page.getByRole('button', { name: 'Create Example App Config' }).click();
    await expectJobsPage(page);
    await expectJobText(page, 'App example config written');
    await copyLatestJobArtifacts(stateDir, dir, 'app-init', 'app_init');
    await screenshot(page, dir, '05-app-init-job.png');

    await page.goto('/resources');
    await expect(page.locator('select[name="access_mode"]')).toBeVisible();
    await expect(page.getByText('Browser Auth Credentials')).toBeVisible();
    await screenshot(page, dir, '06-resources-form-after-init.png');

    const outsideMain = await postJob(page, token, {
      operation: 'main_init',
      config_path: path.join(path.dirname(configPath), 'outside-lanpanel.yaml'),
    });
    expect(outsideMain.status()).toBe(500);
    const outsideApp = await postJob(page, token, {
      operation: 'app_init',
      app_config_path: path.join(path.dirname(appConfigPath), 'outside.yaml'),
    });
    expect(outsideApp.status()).toBe(500);

    await appendEvidence(dir, [
      '',
      '## Result',
      '',
      '- Status: asset smoke passed',
      '- Generated files: main and app example configs were created through UI jobs',
      '- Negative path: out-of-scope main/app init requests returned HTTP 500 before mutation',
      '- Redaction: config snapshots and job records scanned before archive',
    ]);
    await stateDirFromResourcesPage(page);
    await scanArtifactDir(dir);
  });
});

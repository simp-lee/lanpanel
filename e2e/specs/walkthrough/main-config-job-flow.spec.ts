import { expect, test } from '@playwright/test';
import { writeFile } from 'node:fs/promises';
import * as path from 'node:path';
import {
  appendEvidence,
  copyLatestJobArtifacts,
  csrfToken,
  expectJobText,
  expectJobsPage,
  inputValue,
  loginWithStartupToken,
  operationForm,
  postJob,
  prepareJourneyArtifacts,
  scanArtifactDir,
  screenshot,
  stateDirFromResourcesPage,
} from './helpers';

test.describe('walkthrough: main-config-job-flow', () => {
  test('captures save, verify, deploy, fail-fast validation, and path-scope evidence', async ({
    page,
  }, testInfo) => {
    const dir = await prepareJourneyArtifacts(testInfo, 'main-config-job-flow');
    await loginWithStartupToken(page);
    const stateDir = await stateDirFromResourcesPage(page);

    await page.goto('/settings');
    await expect(page.getByRole('button', { name: 'Save' })).toBeVisible();
    await screenshot(page, dir, '01-settings-form.png');
    const token = await csrfToken(page);
    const configPath = await inputValue(page, 'config_path');

    await page.locator('input[name="package_probe_reachability_timeout"]').fill('7s');
    await page.getByRole('button', { name: 'Save' }).click();
    await expectJobsPage(page);
    await expectJobText(page, 'main config saved');
    await copyLatestJobArtifacts(stateDir, dir, 'config-save', 'config_save');
    await screenshot(page, dir, '02-config-save-job.png');

    await page.goto('/settings');
    await operationForm(page, 'main_verify').getByRole('button', { name: 'Verify' }).click();
    await expectJobsPage(page);
    await expectJobText(page, 'configuration, runtime assets, and onboarding readiness checks passed');
    await copyLatestJobArtifacts(stateDir, dir, 'main-verify', 'verify');
    await screenshot(page, dir, '03-verify-result.png');

    await page.goto('/settings');
    await operationForm(page, 'main_deploy').getByRole('button', { name: 'Deploy' }).click();
    await expectJobsPage(page);
    await expectJobText(page, 'e2e main deploy simulated');
    await expect(page.locator('body')).not.toContainText('hskey-auth');
    await copyLatestJobArtifacts(stateDir, dir, 'main-deploy', 'deploy');
    await screenshot(page, dir, '04-deploy-job-history.png');

    await writeFile(configPath, 'api_version: lanpanel/v1alpha2\nunknown_field: true\n', 'utf8');
    const knownField = await postJob(page, token, { operation: 'main_verify', config_path: configPath });
    expect(knownField.status()).toBe(303);
    await expectJobText(page, 'field unknown_field not found');
    await copyLatestJobArtifacts(stateDir, dir, 'main-known-fields-failure', 'verify');

    const outsidePath = await postJob(page, token, {
      operation: 'main_verify',
      config_path: path.join(path.dirname(configPath), 'outside-lanpanel.yaml'),
    });
    expect(outsidePath.status()).toBe(500);

    await appendEvidence(dir, [
      '',
      '## Result',
      '',
      '- Status: asset smoke passed',
      '- Jobs copied: config save, main verify, main deploy, known-fields failure',
      '- Boundary: main deploy job history contains no preauth key material',
      '- Negative path: out-of-scope main config path rejected before job creation',
    ]);
    await scanArtifactDir(dir);
  });
});

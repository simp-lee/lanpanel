import { expect, test } from '@playwright/test';
import {
  appendEvidence,
  appConfigPathFromResourcesPage,
  copyLatestJobArtifacts,
  csrfToken,
  expectJobText,
  loginWithStartupToken,
  postJob,
  prepareJourneyArtifacts,
  scanArtifactDir,
  screenshot,
  stateDirFromResourcesPage,
  validAppSaveForm,
  writeArtifactFile,
  writeArtifactJSON,
} from './helpers';

test.describe('walkthrough: jobs-history-redaction-recovery', () => {
  test.setTimeout(120_000);

  test('captures interrupted recovery, polling, success/failure jobs, artifacts, and lock contention', async ({
    page,
  }, testInfo) => {
    const dir = await prepareJourneyArtifacts(testInfo, 'jobs-history-redaction-recovery');
    await appendEvidence(dir, [
      '- Required testserver flags for lock contention: `E2E_TESTSERVER_FLAGS=-slow-main-deploy=3s`',
      '',
    ]);
    await loginWithStartupToken(page);
    const stateDir = await stateDirFromResourcesPage(page);
    const appConfigPath = await appConfigPathFromResourcesPage(page);
    const token = await csrfToken(page);

    await page.goto('/jobs');
    await expect(page.locator('body')).toContainText('interrupted');
    await expect(page.locator('body')).toContainText('job was interrupted while lanpanel ui was not running');
    await copyLatestJobArtifacts(stateDir, dir, 'seeded-interrupted', 'app_deploy');
    await screenshot(page, dir, '01-jobs-history-interrupted.png');

    const fragment = await page.request.get('/fragments/job-status');
    expect(fragment.status()).toBe(200);
    await writeArtifactFile(dir, 'job-fragment.html', await fragment.text());
    await screenshot(page, dir, '02-job-fragment-polling.png');

    expect(
      (
        await postJob(page, token, {
          operation: 'main_status',
        })
      ).status(),
    ).toBe(303);
    await expectJobText(page, 'e2e main status simulated');
    await copyLatestJobArtifacts(stateDir, dir, 'status-success', 'status');

    const missingAccessModeForm = validAppSaveForm(appConfigPath);
    delete missingAccessModeForm.access_mode;
    expect((await postJob(page, token, missingAccessModeForm)).status()).toBe(303);
    await expectJobText(page, 'access.access_mode is required');
    await copyLatestJobArtifacts(stateDir, dir, 'validation-failure', 'app_config_save');
    await screenshot(page, dir, '03-job-detail-success-failure.png');

    const slowJob = await page.request.post('/jobs/run', {
      maxRedirects: 0,
      form: {
        csrf_token: token,
        operation: 'main_deploy',
      },
    });
    expect(slowJob.status()).toBe(303);
    const lockResponse = await page.request.post('/jobs/run', {
      maxRedirects: 0,
      form: {
        csrf_token: token,
        operation: 'app_deploy',
        app_config_path: appConfigPath,
      },
    });
    expect(lockResponse.status()).toBe(500);
    const lockText = await lockResponse.text();
    expect(lockText).toContain('active');
    await writeArtifactJSON(dir, 'lock-contention-response.json', {
      status: lockResponse.status(),
      body: lockText,
    });
    await page.goto('/jobs');
    await screenshot(page, dir, '04-lock-contention.png');

    await appendEvidence(dir, [
      '',
      '## Result',
      '',
      '- Status: asset smoke passed',
      '- Recovery: seeded running job was marked interrupted on server startup',
      '- Lock: concurrent host mutation returned explicit active-lock failure',
      '- Redaction: copied job state scanned for raw secrets',
    ]);
    await scanArtifactDir(dir);
  });
});

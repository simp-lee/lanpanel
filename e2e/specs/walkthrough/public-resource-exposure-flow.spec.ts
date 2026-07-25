import { expect, test } from '@playwright/test';
import {
  appendEvidence,
  appConfigPathFromResourcesPage,
  copyLatestJobArtifacts,
  csrfToken,
  expectJobText,
  expectJobsPage,
  loginWithStartupToken,
  operationForm,
  postJob,
  prepareJourneyArtifacts,
  scanArtifactDir,
  screenshot,
  stateDirFromResourcesPage,
  validAppSaveForm,
  writeArtifactFile,
} from './helpers';

test.describe('walkthrough: public-resource-exposure-flow', () => {
  test('captures public app exposure preview, validation failures, save, upstream summary, and deploy', async ({
    page,
  }, testInfo) => {
    const dir = await prepareJourneyArtifacts(testInfo, 'public-resource-exposure-flow');
    await loginWithStartupToken(page);
    const stateDir = await stateDirFromResourcesPage(page);
    const appConfigPath = await appConfigPathFromResourcesPage(page);
    const token = await csrfToken(page);

    await page.goto('/resources');
    await expect(page.locator('select[name="access_mode"] option[value="private_client"]')).toHaveCount(0);
    await expect(page.locator('input[name="app_upstream"]')).toBeVisible();
    await screenshot(page, dir, '01-resources-public-form.png');

    const preview = await page.request.post('/fragments/exposure-preview', {
      form: {
        csrf_token: token,
        ...validAppSaveForm(appConfigPath),
      },
    });
    expect(preview.status()).toBe(200);
    const previewBody = await preview.text();
    expect(previewBody).toContain('lanpanel.exposure_plan.v1');
    expect(previewBody).toContain('Resource ID');
    expect(previewBody).toContain('configured_unknown');
    expect(previewBody).toContain('Blocks activation');
    await writeArtifactFile(dir, 'exposure-preview.html', previewBody);
    await page.getByRole('button', { name: 'Preview Exposure' }).click();
    await expect(page.locator('#exposure-preview')).toContainText('Blocks activation');
    await screenshot(page, dir, '02-exposure-preview-blocked.png');

	    const missingPublicRiskForm = validAppSaveForm(appConfigPath);
	    delete missingPublicRiskForm.public_risk_confirmed;
	    const missingPublicRiskPreview = await page.request.post('/fragments/exposure-preview', {
	      form: {
	        csrf_token: token,
	        ...missingPublicRiskForm,
	      },
	    });
	    expect(missingPublicRiskPreview.status()).toBe(200);
	    expect(await missingPublicRiskPreview.text()).toContain('public-app-risk');
	    expect((await postJob(page, token, missingPublicRiskForm)).status()).toBe(303);
	    await expectJobText(page, 'app config saved');
	    await copyLatestJobArtifacts(stateDir, dir, 'public-risk-manual-save', 'app_config_save');
	    await screenshot(page, dir, '03-manual-risk-save-job.png');

    const missingOriginModeForm = validAppSaveForm(appConfigPath);
    delete missingOriginModeForm.origin_mode;
    expect((await postJob(page, token, missingOriginModeForm)).status()).toBe(303);
    await expectJobText(page, 'access.origin_protection.mode is required');

	    const missingDirectOriginForm = {
	      ...validAppSaveForm(appConfigPath),
	      app_acme_challenge: 'http-01',
	      origin_mode: 'none',
	      direct_origin_risk_confirmed: '',
	      edgeone_profile: '',
	      edgeone_profile_enabled: '',
	      edgeone_zone_id: '',
	      edgeone_env_file: '',
	      app_dns01_provider: '',
	      app_dns01_env_file: '',
	    };
	    const missingDirectOriginPreview = await page.request.post('/fragments/exposure-preview', {
	      form: {
	        csrf_token: token,
	        ...missingDirectOriginForm,
	      },
	    });
	    expect(missingDirectOriginPreview.status()).toBe(200);
	    expect(await missingDirectOriginPreview.text()).toContain('direct-origin-risk');
	    expect((await postJob(page, token, missingDirectOriginForm)).status()).toBe(303);
	    await expectJobText(page, 'app config saved');

    expect(
      (
        await postJob(page, token, {
          ...validAppSaveForm(appConfigPath),
          access_mode: 'private_client',
        })
      ).status(),
    ).toBe(303);
	    await expectJobText(page, 'reserved for P1');

    expect((await postJob(page, token, validAppSaveForm(appConfigPath))).status()).toBe(303);
    await expectJobText(page, 'app config saved');
    await copyLatestJobArtifacts(stateDir, dir, 'public-save', 'app_config_save');

    expect(
      (
        await postJob(page, token, {
          ...validAppSaveForm(appConfigPath),
          app_target_mode: 'upstream',
          app_listen: '',
          app_upstream: '100.64.10.20:18001',
          service_exec_start: '',
          service_working_directory: '',
          tailscale_login_server: 'https://hs.example.com',
        })
      ).status(),
    ).toBe(303);
    await expectJobText(page, 'app config saved');
    await page.goto('/resources');
    await expect(page.locator('body')).toContainText('upstream http://100.64.10.20:18001');
    await screenshot(page, dir, '05-resources-upstream-summary.png');

    expect((await postJob(page, token, validAppSaveForm(appConfigPath))).status()).toBe(303);
    await expectJobText(page, 'app config saved');
    await page.goto('/resources');
    const appDeployForm = operationForm(page, 'app_deploy');
    await appDeployForm.locator('input[name="confirmation"][value="origin-protection-manual"]').check();
    await appDeployForm.getByRole('button', { name: 'Deploy', exact: true }).click();
    await expectJobsPage(page);
    await expectJobText(page, 'e2e app deploy simulated');
    await expect(page.locator('body')).toContainText('manual confirmation submitted: origin-protection-manual');
    await copyLatestJobArtifacts(stateDir, dir, 'public-deploy', 'app_deploy');
    await screenshot(page, dir, '04-public-deploy-manual-confirmation.png');

    await appendEvidence(dir, [
      '',
      '## Result',
      '',
      '- Status: asset smoke passed',
	      '- Public validation branches: manual risk confirmation, missing origin mode, manual direct-origin confirmation, private_client rejection',
      '- Continuity: upstream summary rendered on Resources after save and deploy used manual origin confirmation',
    ]);
    await scanArtifactDir(dir);
  });
});

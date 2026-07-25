import { expect, test } from '@playwright/test';
import {
  appendEvidence,
  appConfigPathFromResourcesPage,
  copyLatestJobArtifacts,
  csrfToken,
  expectJobText,
  expectJobsPage,
  loginWithStartupToken,
  postJob,
  prepareJourneyArtifacts,
  scanArtifactDir,
  screenshot,
  stateDirFromResourcesPage,
} from './helpers';

const referencePath = '/var/lib/lanpanel/realip/edgeone-prod/references/example-app.json';

test.describe('walkthrough: realip-goaccess-flow', () => {
  test('captures GoAccess, RealIP diagnostics, refresh, and validate-reference evidence', async ({
    page,
  }, testInfo) => {
    const dir = await prepareJourneyArtifacts(testInfo, 'realip-goaccess-flow');
    await loginWithStartupToken(page);
    const stateDir = await stateDirFromResourcesPage(page);
    const appConfigPath = await appConfigPathFromResourcesPage(page);
    const token = await csrfToken(page);

    await page.goto('/resources');
    await expect(page.locator('body')).toContainText('GoAccess enabled');
    await expect(page.locator('body')).toContainText('Browser Auth Credentials');
    await screenshot(page, dir, '01-goaccess-realip-controls.png');

    expect(
      (
        await postJob(page, token, {
          operation: 'realip_diagnostics',
          app_config_path: appConfigPath,
          profile: 'edgeone-prod',
        })
      ).status(),
    ).toBe(303);
    await expectJobText(page, 'e2e realip diagnostics simulated');
    await copyLatestJobArtifacts(stateDir, dir, 'realip-diagnostics-success', 'realip_diagnostics');
    await screenshot(page, dir, '02-realip-diagnostics-success.png');

    expect(
      (
        await postJob(page, token, {
          operation: 'realip_diagnostics',
          app_config_path: appConfigPath,
          profile: 'missing-profile',
        })
      ).status(),
    ).toBe(303);
    await expectJobText(page, 'realip profile missing-profile is not defined');
    await copyLatestJobArtifacts(stateDir, dir, 'realip-diagnostics-failure', 'realip_diagnostics');

    expect(
      (
        await postJob(page, token, {
          operation: 'realip_refresh',
          app_config_path: appConfigPath,
          profile: 'edgeone-prod',
        })
      ).status(),
    ).toBe(303);
    await expectJobText(page, 'e2e realip refresh simulated with rollback reference');
    await copyLatestJobArtifacts(stateDir, dir, 'realip-refresh', 'realip_refresh');
    await screenshot(page, dir, '03-realip-refresh.png');

    expect(
      (
        await postJob(page, token, {
          operation: 'realip_validate_reference',
          app_config_path: appConfigPath,
          profile: 'edgeone-prod',
          realip_reference_app: 'example-app',
          realip_reference_path: referencePath,
        })
      ).status(),
    ).toBe(303);
    await expectJobText(page, 'realip reference validation passed');
    await expectJobText(page, 'result detail: domains: abc.com, www.abc.com');
    await copyLatestJobArtifacts(stateDir, dir, 'realip-validate-reference-success', 'realip_validate_reference');
    await screenshot(page, dir, '04-realip-validate-reference.png');

    expect(
      (
        await postJob(page, token, {
          operation: 'realip_validate_reference',
          app_config_path: appConfigPath,
          profile: 'edgeone-prod',
          realip_reference_app: 'example-app',
          realip_reference_path: '/tmp/example-app.json',
        })
      ).status(),
    ).toBe(303);
    await expectJobText(page, 'realip reference validation failed');
    await copyLatestJobArtifacts(stateDir, dir, 'realip-validate-reference-failure', 'realip_validate_reference');

    await page.goto('/diagnostics');
    await expect(page.locator('body')).toContainText('RealIP');
    await page.goto('/services');
    await expect(page.locator('body')).toContainText('GoAccess');
    await page.goto('/certificates');
    await expect(page.locator('body')).toContainText('dns01');
    await screenshot(page, dir, '05-services-diagnostics-observability.png');

    await appendEvidence(dir, [
      '',
      '## Result',
      '',
      '- Status: asset smoke passed',
      '- RealIP reference success uses e2e build hook, not host `/var/lib` mutation',
      '- Provider credential values are not shown or archived',
    ]);
    await scanArtifactDir(dir);
  });
});

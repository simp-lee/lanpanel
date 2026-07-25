import { expect, test } from '@playwright/test';
import {
  appendEvidence,
  copyLatestJobArtifacts,
  csrfToken,
  expectJobText,
  expectJobsPage,
  loginWithStartupToken,
  operationForm,
  prepareJourneyArtifacts,
  scanArtifactDir,
  screenshot,
  stateDirFromResourcesPage,
} from './helpers';

test.describe('walkthrough: overview-runtime-readonly', () => {
  test('captures overview, host health, diagnostics, services, and certificates evidence', async ({
    page,
  }, testInfo) => {
    const dir = await prepareJourneyArtifacts(testInfo, 'overview-runtime-readonly');
    await loginWithStartupToken(page);
    const stateDir = await stateDirFromResourcesPage(page);

    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
    await expect(page.locator('main')).toContainText('Control Center');
    await expect(page.locator('main .control-card')).toHaveCount(5);
    await expect(page.locator('main')).toContainText('Detailed resource exposure map and per-resource controls are on');
    await expect(page.locator('main')).not.toContainText('lanpanel.exposure.v1');
    await expect(page.locator('main')).not.toContainText('configured_unknown');
    await screenshot(page, dir, '01-overview-summary.png');

    await page.goto('/host-health');
    await expect(page.getByRole('heading', { name: 'Read-Only Facts' })).toBeVisible();
    await expect(page.locator('main details.port-group')).toHaveCount(3);
    await expect(page.locator('main details.port-group[open]')).toHaveCount(0);
    await expect(page.getByRole('button', { name: /disk cleanup/i })).toHaveCount(0);
    await expect(page.getByRole('button', { name: /package manager/i })).toHaveCount(0);
    await expect(page.getByRole('button', { name: /systemd/i })).toHaveCount(0);
    await expect(page.getByRole('button', { name: /network settings/i })).toHaveCount(0);
    await screenshot(page, dir, '02-host-health-readonly.png');

    await page.goto('/diagnostics');
    await expect(page.getByRole('heading', { name: 'Diagnostics', exact: true })).toBeVisible();
    await expect(page.locator('main')).toContainText('Open each area for detailed rows and actions');
    await expect(page.locator('main')).not.toContainText('staged_file');
    await expect(page.getByText('responsible_party')).toHaveCount(0);
    await screenshot(page, dir, '03-diagnostics-summary.png');

    await page.goto('/services');
    await expect(page.getByRole('heading', { name: 'Services', exact: true })).toBeVisible();
    await operationForm(page, 'main_status').getByRole('button', { name: 'Refresh Status' }).click();
    await expectJobsPage(page);
    await expectJobText(page, 'e2e main status simulated');
    await copyLatestJobArtifacts(stateDir, dir, 'main-status', 'status');

    await page.goto('/certificates');
    await expect(page.locator('body')).toContainText('Certificates / Nginx');
    await expect(page.locator('main')).toContainText('Certificate / Nginx Summary');
    await operationForm(page, 'main_verify').getByRole('button', { name: 'Run Verify' }).click();
    await expectJobsPage(page);
    await expectJobText(page, 'configuration, runtime assets, and onboarding readiness checks passed');
    await copyLatestJobArtifacts(stateDir, dir, 'main-verify', 'verify');
    await page.goto('/certificates');
    await screenshot(page, dir, '04-services-certificates.png');

    await csrfToken(page);
    await appendEvidence(dir, [
      '',
      '## Result',
      '',
      '- Status: asset smoke passed',
      '- Boundary: read-only pages expose no generic host action buttons',
      '- Jobs copied: `main-status-*`, `main-verify-*`',
      '- Redaction: job artifacts scanned before archive',
    ]);
    await scanArtifactDir(dir);
  });
});

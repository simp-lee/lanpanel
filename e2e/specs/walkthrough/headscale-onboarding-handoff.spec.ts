import { expect, test } from '@playwright/test';
import {
  appendEvidence,
  copyLatestJobArtifacts,
  expectJobText,
  expectJobsPage,
  loginWithStartupToken,
  oneTimeSecret,
  prepareJourneyArtifacts,
  revealOneTimeHandoff,
  scanArtifactDir,
  screenshot,
  stateDirFromResourcesPage,
} from './helpers';

test.describe('walkthrough: headscale-onboarding-handoff', () => {
  test('captures onboarding readiness and one-time preauth handoff redaction', async ({ page }, testInfo) => {
    const dir = await prepareJourneyArtifacts(testInfo, 'headscale-onboarding-handoff');
    await loginWithStartupToken(page);
    const stateDir = await stateDirFromResourcesPage(page);

    await page.goto('/onboarding');
    await expect(
      page.getByRole('cell', { name: 'Tailscale-compatible client >= v1.80.0', exact: true }),
    ).toBeVisible();
    await expect(page.getByRole('row', { name: /^MagicDNS suffix tailnet\.example\.com$/ })).toBeVisible();
    await screenshot(page, dir, '01-onboarding-readiness.png');

    await page.getByRole('button', { name: 'Create One-Time Key' }).click();
    await expectJobsPage(page);
    await expectJobText(page, 'preauth_key_create');
    await revealOneTimeHandoff(page);
    const handoff = await oneTimeSecret(page);
    expect(handoff.value).toContain('hskey-auth-e2e');
    await screenshot(page, dir, '02-preauth-handoff-masked.png', { maskSecrets: true });

    await page.goto(page.url());
    await expect(page.locator('body')).toContainText('Secret is no longer available');
    await expect(page.locator('body')).not.toContainText(handoff.value);
    await screenshot(page, dir, '03-preauth-secret-consumed.png');

    await page.goto('/jobs');
    await expect(page.locator('body')).toContainText('[redacted]');
    await expect(page.locator('body')).not.toContainText(handoff.value);
    await copyLatestJobArtifacts(stateDir, dir, 'preauth-key-create', 'preauth_key_create');
    await screenshot(page, dir, '04-history-redacted.png');

    await appendEvidence(dir, [
      '',
      '## Result',
      '',
      '- Status: asset smoke passed',
      '- Raw preauth key was visible only before masked screenshot capture and absent after consumption',
      '- Job history stores fingerprint/redacted summary only',
    ]);
    await scanArtifactDir(dir);
  });
});

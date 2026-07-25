import { expect, test } from '@playwright/test';
import {
  appendEvidence,
  csrfToken,
  expectJobText,
  loginWithStartupToken,
  postJob,
  prepareJourneyArtifacts,
  scanArtifactDir,
  screenshot,
  writeArtifactJSON,
} from './helpers';

test.describe('walkthrough: migration-boundary-flow', () => {
  test('captures read-only migration boundary, exposure pointers, and unsupported operation absence', async ({
    page,
  }, testInfo) => {
    const dir = await prepareJourneyArtifacts(testInfo, 'migration-boundary-flow');
    await loginWithStartupToken(page);
    await page.goto('/settings');
    const token = await csrfToken(page);
    expect((await postJob(page, token, { operation: 'main_status' })).status()).toBe(303);
    await expectJobText(page, 'e2e main status simulated');

    await page.goto('/migration');
    await expect(page.getByRole('row', { name: /Main config .*lanpanel\.yaml$/ })).toBeVisible();
    await expect(page.getByRole('row', { name: /App config .*lanpanel-app\.yaml$/ })).toBeVisible();
    await expect(page.getByRole('row', { name: /UI state .*\/state$/ })).toBeVisible();
    await expect(page.getByRole('row', { name: /^Browser auth \/etc\/lanpanel\/browser-auth\/$/ })).toBeVisible();
    await screenshot(page, dir, '01-migration-boundary.png');

    await expect(page.locator('body')).toContainText('Resource exposure details stay in');
    await expect(page.locator('body')).toContainText('Overview only shows rollup counts');
    await expect(page.locator('main').getByRole('link', { name: 'Overview' })).toHaveCount(0);
    await expect(page.locator('main').getByRole('link', { name: 'Resources' })).toBeVisible();
    await screenshot(page, dir, '02-migration-exposure-pointer.png');

    await expect(page.getByText('No machine-readable export manifest')).toBeVisible();
    await expect(page.getByText('No raw secrets')).toBeVisible();
    await expect(page.locator('button[value="export"]')).toHaveCount(0);
    await expect(page.locator('input[name="operation"][value="export"]')).toHaveCount(0);
    await expect(page.locator('input[name="operation"][value="audit_log"]')).toHaveCount(0);
    await expect(page.locator('select[name="access_mode"] option[value="private_client"]')).toHaveCount(0);
    await screenshot(page, dir, '03-no-export-manifest.png');

    const inventory = await page.evaluate(() => ({
      links: Array.from(document.querySelectorAll('a[href]')).map((link) => link.getAttribute('href')),
      operations: Array.from(document.querySelectorAll('input[name="operation"]')).map((input) =>
        input.getAttribute('value'),
      ),
      buttons: Array.from(document.querySelectorAll('button')).map((button) => button.textContent?.trim() || ''),
    }));
    await writeArtifactJSON(dir, 'route-nav-operation-inventory.json', inventory);

    await appendEvidence(dir, [
      '',
      '## Result',
      '',
      '- Status: asset smoke passed',
      '- Boundary: page is read-only and exposes no export/audit/private_client write path',
      '- Migration copy states that P0 does not export raw secrets, logs, htpasswd content, or machine-readable export manifest',
    ]);
    await scanArtifactDir(dir);
  });
});

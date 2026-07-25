import { expect, test } from '@playwright/test';
import { rm } from 'node:fs/promises';
import * as path from 'node:path';
import {
  appendEvidence,
  appConfigPathFromResourcesPage,
  copyLatestJobArtifacts,
  csrfToken,
  expectJobText,
  expectJobsPage,
  loginWithStartupToken,
  oneTimeSecret,
  operationForm,
  postJob,
  prepareJourneyArtifacts,
  revealOneTimeHandoff,
  scanArtifactDir,
  screenshot,
  stateDirFromResourcesPage,
  validAppSaveForm,
} from './helpers';

test.describe('walkthrough: browser-auth-resource-flow', () => {
  test('captures managed browser auth create, rotate, deploy render evidence, and delete boundaries', async ({
    page,
  }, testInfo) => {
    const dir = await prepareJourneyArtifacts(testInfo, 'browser-auth-resource-flow');
    await loginWithStartupToken(page);
    const browserAuthDir = process.env.LANPANEL_BROWSER_AUTH_DIR;
    if (!browserAuthDir) {
      throw new Error('LANPANEL_BROWSER_AUTH_DIR is required');
    }
    const runtimeHtpasswdPath = `${browserAuthDir.replace(/\/$/, '')}/e2e-auth.htpasswd`;
    const unusedHtpasswdPath = `${browserAuthDir.replace(/\/$/, '')}/unused-auth.htpasswd`;
    const appManagedHtpasswdPath = runtimeHtpasswdPath;
    const stateDir = await stateDirFromResourcesPage(page);
    const appConfigPath = await appConfigPathFromResourcesPage(page);
    const token = await csrfToken(page);
    await rm(path.join(path.dirname(appConfigPath), 'unknown-field-lanpanel-app.yaml'), { force: true });

    await page.goto('/resources');
    await expect(page.getByText('Browser Auth Credentials')).toBeVisible();
    await expect(page.locator('input[name="browser_auth_create_password"]')).toHaveValue('');
    await expect(page.locator('input[name="browser_auth_rotate_password"]')).toHaveValue('');
    await screenshot(page, dir, '01-browser-auth-forms.png');

    await page.locator('input[name="browser_auth_dir"]').fill(browserAuthDir);
    await page.locator('input[name="browser_auth_id"]').fill('e2e-auth');
    await page.locator('input[name="browser_auth_create_username"]').fill('admin');
    await page.getByRole('button', { name: 'Create', exact: true }).click();
    await expectJobsPage(page);
    await expectJobText(page, 'browser auth credential created');
    await revealOneTimeHandoff(page);
    const created = await oneTimeSecret(page);
    await screenshot(page, dir, '02-create-handoff-masked.png', { maskSecrets: true });
    await page.goto(page.url());
    await expect(page.locator('body')).toContainText('Secret is no longer available');
    await expect(page.locator('body')).not.toContainText(created.value);
    await screenshot(page, dir, '03-secret-consumed.png');
    await copyLatestJobArtifacts(stateDir, dir, 'browser-auth-create', 'browser_auth_create');

    const fragment = await page.request.get('/fragments/job-status');
    expect(fragment.status()).toBe(200);
    expect(await fragment.text()).not.toContain(created.value);

    expect(
      (
        await postJob(page, token, {
          ...validAppSaveForm(appConfigPath),
          access_mode: 'browser',
          public_risk_confirmed: '',
          browser_auth_credential_id: 'e2e-auth',
          browser_auth_managed_path: appManagedHtpasswdPath,
          browser_auth_username: 'admin',
          browser_auth_password_fingerprint: created.fingerprint,
          goaccess_enabled: '',
        })
      ).status(),
    ).toBe(303);
    await expectJobText(page, 'app config saved');
    await copyLatestJobArtifacts(stateDir, dir, 'browser-mode-save', 'app_config_save');
    await page.goto('/resources');
    await screenshot(page, dir, '04-browser-mode-save.png');

    await page.locator('input[name="browser_auth_rotate_path"]').fill(runtimeHtpasswdPath);
    await page.locator('input[name="browser_auth_rotate_username"]').fill('admin');
    await page.getByRole('button', { name: 'Rotate', exact: true }).click();
    await expectJobsPage(page);
    await expectJobText(page, 'browser auth credential rotated');
    await revealOneTimeHandoff(page);
    const rotated = await oneTimeSecret(page);
    await page.goto(page.url());
    await expect(page.locator('body')).toContainText('Secret is no longer available');
    await expect(page.locator('body')).not.toContainText(rotated.value);
    await copyLatestJobArtifacts(stateDir, dir, 'browser-auth-rotate', 'browser_auth_rotate');

    expect(
      (
        await postJob(page, token, {
          ...validAppSaveForm(appConfigPath),
          access_mode: 'browser',
          public_risk_confirmed: '',
          browser_auth_credential_id: 'e2e-auth',
          browser_auth_managed_path: appManagedHtpasswdPath,
          browser_auth_username: 'admin',
          browser_auth_password_fingerprint: rotated.fingerprint,
          goaccess_enabled: '',
        })
      ).status(),
    ).toBe(303);
    await expectJobText(page, 'app config saved');

    await page.goto('/resources');
    await page.getByRole('button', { name: 'Verify', exact: true }).click();
    await expectJobsPage(page);
    await expectJobText(page, 'App exposure plan blocks static verify');
    await expect(page.locator('body')).not.toContainText(rotated.value);

    await page.goto('/resources');
    const browserDeployForm = operationForm(page, 'app_deploy');
    await browserDeployForm.locator('input[name="confirmation"][value="origin-protection-manual"]').check();
    await browserDeployForm.getByRole('button', { name: 'Deploy', exact: true }).click();
    await expectJobsPage(page);
    await expectJobText(page, 'e2e app deploy simulated');
    await expectJobText(page, 'proxy credential header cleared: true');
    const nginxRender = (await page.locator('body').textContent()) || '';
    expect(nginxRender).toContain('static location rendered: true');
    expect(nginxRender).toContain('static alias rendered: true');
    expect(nginxRender).toContain('managed credential file rendered: true');
    expect(nginxRender).toContain('proxy credential header cleared: true');
    expect(Number(nginxRender.match(/browser gate count: (\d+)/)?.[1] || '0')).toBeGreaterThanOrEqual(2);
    await copyLatestJobArtifacts(stateDir, dir, 'browser-app-deploy', 'app_deploy');
    await screenshot(page, dir, '05-browser-deploy-render-evidence.png');

    expect(
      (
        await postJob(page, token, {
          ...validAppSaveForm(appConfigPath),
          access_mode: 'browser',
          public_risk_confirmed: '',
          browser_auth_file: runtimeHtpasswdPath,
          browser_auth_credential_id: '',
          browser_auth_managed_path: '',
          browser_auth_username: '',
          browser_auth_password_fingerprint: '',
          goaccess_enabled: '',
        })
      ).status(),
    ).toBe(303);
    await expectJobText(page, 'app config saved');

    expect(
      (
        await postJob(page, token, {
          operation: 'browser_auth_delete',
          browser_auth_delete_path: runtimeHtpasswdPath,
        })
      ).status(),
    ).toBe(303);
    await expectJobText(page, 'still referenced by an active or staged browser app');
    await copyLatestJobArtifacts(stateDir, dir, 'browser-auth-delete-referenced', 'browser_auth_delete');
    await screenshot(page, dir, '06-delete-fail-closed.png');

    await page.goto('/resources');
    await page.locator('input[name="browser_auth_dir"]').fill(browserAuthDir);
    await page.locator('input[name="browser_auth_id"]').fill('unused-auth');
    await page.locator('input[name="browser_auth_create_username"]').fill('admin');
    await page.getByRole('button', { name: 'Create', exact: true }).click();
    await expectJobsPage(page);
    await expectJobText(page, 'browser auth credential created');
    expect(
      (
        await postJob(page, token, {
          operation: 'browser_auth_delete',
          browser_auth_delete_path: unusedHtpasswdPath,
        })
      ).status(),
    ).toBe(303);
    await expectJobText(page, 'browser auth credential deleted');
    await copyLatestJobArtifacts(stateDir, dir, 'browser-auth-delete-unreferenced', 'browser_auth_delete');

    await appendEvidence(dir, [
      '',
      '## Result',
      '',
      '- Status: asset smoke passed',
      '- One-time browser password was masked before screenshot capture and absent after consumption',
      '- Render evidence captured: browser gate count, managed credential file rendered, upstream Authorization cleared',
      '- Delete boundary captured for referenced and unreferenced managed credentials',
    ]);
    await scanArtifactDir(dir);
  });
});

import { expect, test } from '@playwright/test';
import type { APIResponse, Browser, Page } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { homedir } from 'node:os';
import * as path from 'node:path';

type JobForm = Record<string, string>;
type JobRecord = {
  job_id: string;
  kind: string;
  status: string;
  result_summary?: string;
  error_summary?: string;
};
type JobEvent = {
  status: string;
  message: string;
};

const forbiddenWithoutCSRF = async (page: Page, targetPath: string, form: JobForm = { app_name: 'example-app' }) => {
  const response = await page.request.post(targetPath, {
    form,
  });
  expect(response.status()).toBe(403);
};

const csrfToken = async (page: Page) => page.locator('input[name="csrf_token"]').first().inputValue();

const inputValue = async (page: Page, name: string) => page.locator(`[name="${name}"]`).first().inputValue();

const oneTimeSecret = async (page: Page) => {
  const value = (await page.locator('.secret').textContent())?.trim() || '';
  expect(value.length).toBeGreaterThan(15);
  expect(value).not.toContain('$2');
  const body = (await page.locator('body').textContent()) || '';
  const fingerprint = body.match(/sha256:[0-9a-f]{16}/)?.[0] || '';
  expect(fingerprint).toMatch(/^sha256:[0-9a-f]{16}$/);
  return { value, fingerprint };
};

const validAppSaveForm = (appConfigPath: string): JobForm => ({
  operation: 'app_config_save',
  app_config_path: appConfigPath,
  app_name: 'example-app',
  app_domains: 'abc.com\nwww.abc.com',
  app_certificate_email: 'ops@example.com',
  app_acme_challenge: 'dns-01',
  app_target_mode: 'listen',
  app_listen: '127.0.0.1:18001',
  app_upstream: '',
  access_mode: 'public',
  public_risk_confirmed: 'on',
  cidr_allowlist: '',
  browser_auth_file: '',
  browser_auth_credential_id: '',
  browser_auth_managed_path: '',
  browser_auth_username: '',
  browser_auth_password_fingerprint: '',
  origin_mode: 'edgeone',
  edgeone_profile: 'edgeone-prod',
  edgeone_profile_enabled: 'on',
  edgeone_zone_id: 'zone-2abcDEF123',
  edgeone_env_file: '/etc/lanpanel/realip/edgeone-prod.env',
  edgeone_refresh_interval: '72h',
  service_exec_start: '/opt/example-app/example-app --listen 127.0.0.1:18001',
  service_working_directory: '/opt/example-app',
  service_env_file: '',
  nginx_client_max_body_size: '20m',
  nginx_http2: 'on',
  nginx_access_log: '',
  nginx_error_log: '',
  proxy_connect_timeout: '',
  proxy_read_timeout: '600s',
  proxy_send_timeout: '600s',
  goaccess_enabled: 'on',
  goaccess_language: 'en',
  goaccess_log_format: 'enhanced',
  goaccess_auth_file: '/etc/example-app/goaccess.htpasswd',
  goaccess_cidr_allowlist: '203.0.113.0/24',
  goaccess_path: '',
  goaccess_websocket_path: '',
  goaccess_websocket_listen: '',
  app_dns01_provider: 'tencentcloud',
  app_dns01_env_file: '/etc/lanpanel/dns/tencentcloud.env',
  app_lego_source_mode: 'direct',
  app_lego_source_file_path: '',
  app_package_probe_reachability_timeout: '30s',
  app_package_probe_artifact_timeout: '5m',
  app_http_proxy: '',
  app_https_proxy: '',
  app_no_proxy: '',
  app_platform_arch: 'amd64',
  tailscale_enabled_for_listen: '',
  tailscale_lanpanel_config: '',
  tailscale_login_server: '',
  tailscale_hostname: '',
  tailscale_auth_key_file: '',
});

const postJob = async (page: Page, token: string, form: JobForm) => {
  let lastResponse = await page.request.post('/jobs/run', {
    maxRedirects: 0,
    form: {
      csrf_token: token,
      ...form,
    },
  });
  for (let attempt = 0; attempt < 20 && lastResponse.status() === 500; attempt += 1) {
    const body = await lastResponse.text();
    if (!body.includes('active') || !body.includes('job already exists')) {
      return lastResponse;
    }
    await page.waitForTimeout(100);
    lastResponse = await page.request.post('/jobs/run', {
      maxRedirects: 0,
      form: {
        csrf_token: token,
        ...form,
      },
    });
  }
  return lastResponse;
};

const expectJobsPage = async (page: Page) => {
  await expect(page).toHaveURL(/\/jobs(\?job=[A-Za-z0-9_.~-]+)?$/);
};

const expectJobText = async (page: Page, text: string) => {
  const deadline = Date.now() + 10_000;
  let body = '';
  while (Date.now() < deadline) {
    await page.goto('/jobs');
    body = (await page.locator('body').textContent()) || '';
    if (body.includes(text)) {
      return;
    }
    await page.waitForTimeout(250);
  }
  expect(body).toContain(text);
};

const jobIDFromResponse = (response: APIResponse) => {
  const location = response.headers().location || '';
  expect(location).toMatch(/^\/jobs\?job=/);
  const jobID = new URL(location, 'http://127.0.0.1').searchParams.get('job') || '';
  expect(jobID).toMatch(/^job_[A-Za-z0-9_.~-]+$/);
  return jobID;
};

const readJobRecord = async (stateDir: string, jobID: string): Promise<JobRecord> =>
  JSON.parse(await readFile(path.join(stateDir, 'jobs', jobID, 'record.json'), 'utf8'));

const jobEvidenceText = async (stateDir: string, jobID: string, record: JobRecord) => {
  const values = [record.kind, record.status, record.result_summary || '', record.error_summary || ''];
  const eventsDir = path.join(stateDir, 'jobs', jobID, 'events');
  for (const file of (await readdir(eventsDir)).filter((entry) => entry.endsWith('.json')).sort()) {
    const event: JobEvent = JSON.parse(await readFile(path.join(eventsDir, file), 'utf8'));
    values.push(event.status, event.message);
  }
  return values.join('\n');
};

const expectJobRecord = async (stateDir: string, jobID: string, summaryText: string) => {
  const deadline = Date.now() + 10_000;
  let record: JobRecord | undefined;
  let evidence = '';
  while (Date.now() < deadline) {
    record = await readJobRecord(stateDir, jobID);
    evidence = await jobEvidenceText(stateDir, jobID, record);
    if (record.status !== 'queued' && record.status !== 'running') {
      if (evidence.includes(summaryText)) {
        return record;
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  expect(record?.status).not.toMatch(/^(queued|running)$/);
  expect(evidence).toContain(summaryText);
  return record;
};

const expectPostedJob = async (stateDir: string, response: APIResponse, summaryText: string) => {
  expect(response.status()).toBe(303);
  return expectJobRecord(stateDir, jobIDFromResponse(response), summaryText);
};

const expectCurrentPageJob = async (stateDir: string, page: Page, summaryText: string) => {
  await expectJobsPage(page);
  const jobID = new URL(page.url()).searchParams.get('job') || '';
  expect(jobID).toMatch(/^job_[A-Za-z0-9_.~-]+$/);
  return expectJobRecord(stateDir, jobID, summaryText);
};

const operationForm = (page: Page, operation: string) =>
  page.locator('form', { has: page.locator(`input[name="operation"][value="${operation}"]`) });

const revealOneTimeHandoff = async (page: Page) => {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    await page.goto('/jobs');
    const reveal = page.getByRole('link', { name: 'Reveal one-time handoff' }).first();
    if (await reveal.count()) {
      await reveal.click();
      await expect(page).toHaveURL(/\/jobs\?secret=/);
      return;
    }
    await page.waitForTimeout(250);
  }
  await expect(page.getByRole('link', { name: 'Reveal one-time handoff' }).first()).toBeVisible();
  await expect(page).toHaveURL(/\/jobs\?secret=/);
};

const assertUnauthenticatedRoutes = async (browser: Browser, baseURL: string) => {
  const context = await browser.newContext({ baseURL });
  const unauthenticated = await context.newPage();
  try {
    for (const protectedPath of [
      '/',
      '/settings',
      '/resources',
      '/diagnostics',
      '/services',
      '/certificates',
      '/host-health',
      '/onboarding',
      '/jobs',
      '/migration',
    ]) {
      const response = await unauthenticated.request.get(protectedPath, { maxRedirects: 0 });
      expect(response.status(), protectedPath).toBe(401);
    }

    const jobFragment = await unauthenticated.request.get('/fragments/job-status', { maxRedirects: 0 });
    expect(jobFragment.status()).toBe(401);

    const exposureFragment = await unauthenticated.request.post('/fragments/exposure-preview', {
      maxRedirects: 0,
      form: {
        app_name: 'example-app',
      },
    });
    expect(exposureFragment.status()).toBe(401);

    const runJob = await unauthenticated.request.post('/jobs/run', {
      maxRedirects: 0,
      form: {
        operation: 'main_status',
      },
    });
    expect(runJob.status()).toBe(401);

    const createJob = await unauthenticated.request.post('/jobs/create', {
      maxRedirects: 0,
      form: {
        operation: 'main_status',
      },
    });
    expect(createJob.status()).toBe(401);
    return 2;
  } finally {
    await context.close();
  }
};

const assertLocalScriptsOnly = async (page: Page) => {
  const scriptSources = await page.locator('script[src]').evaluateAll((scripts) =>
    scripts.map((script) => script.getAttribute('src') || ''),
  );
  expect(scriptSources).toEqual(['/static/vendor/htmx/htmx.min.js']);
  for (const source of scriptSources) {
    expect(source).not.toMatch(/^(https?:)?\/\//);
  }
  await expect(page.locator('script[src^="https://"]')).toHaveCount(0);
  await expect(page.locator('script[src^="http://"]')).toHaveCount(0);
  await expect(page.locator('script[src^="//"]')).toHaveCount(0);
};

const assertJobStateMetadata = async (stateDir: string) => {
  const jobsDir = path.join(stateDir, 'jobs');
  const jobIDs = (await readdir(jobsDir)).filter((entry) => entry.startsWith('job_')).sort().reverse();
  expect(jobIDs.length).toBeGreaterThan(0);

  let jobID = '';
  let record: any;
  for (const candidate of jobIDs) {
    const candidateRecord = JSON.parse(await readFile(path.join(jobsDir, candidate, 'record.json'), 'utf8'));
    if (candidateRecord.kind === 'app_deploy' && candidateRecord.checkpoint_ref?.kind === 'checkpoint') {
      jobID = candidate;
      record = candidateRecord;
      break;
    }
  }
  expect(jobID).toMatch(/^job_/);
  expect(record.schema_version).toBe('lanpanel.job.v1');
  expect(record.job_id).toBe(jobID);
  expect(record.actor.source).toBe('ui');
  expect(record.actor.session_id_fingerprint).toMatch(/^sha256:[0-9a-f]{16}$/);
  expect(record.checkpoint_ref.kind).toBe('checkpoint');
  expect(record.checkpoint_ref.path || '').toMatch(/\.checkpoint\.json$/);
  expect(record.redaction_status).toBe('no_sensitive_data');

  const eventFiles = (await readdir(path.join(jobsDir, jobID, 'events'))).filter((entry) => entry.endsWith('.json')).sort();
  expect(eventFiles.length).toBeGreaterThan(0);
  const event = JSON.parse(await readFile(path.join(jobsDir, jobID, 'events', eventFiles[0]), 'utf8'));
  expect(event.schema_version).toBe('lanpanel.job_event.v1');
  expect(event.job_id).toBe(jobID);
};

const jobRecordCount = async (stateDir: string) => {
  const jobsDir = path.join(stateDir, 'jobs');
  const entries = await readdir(jobsDir);
  return entries.filter((entry) => entry.startsWith('job_')).length;
};

const latestJobRecord = async (stateDir: string) => {
  const jobsDir = path.join(stateDir, 'jobs');
  const jobIDs = (await readdir(jobsDir)).filter((entry) => entry.startsWith('job_')).sort().reverse();
  expect(jobIDs.length).toBeGreaterThan(0);
  return JSON.parse(await readFile(path.join(jobsDir, jobIDs[0], 'record.json'), 'utf8'));
};

const expectRejectedListenAddress = async (addr: string) => {
  const root = await mkdtemp(path.join(homedir(), '.lanpanel-e2e-listen-'));
  try {
    const result = spawnSync('go', [
      'run',
      '-tags',
      'e2e',
      './internal/ui/testserver',
      '-listen',
      addr,
      '-state-dir',
      path.join(root, 'state'),
      '-config',
      path.join(root, 'lanpanel.yaml'),
      '-app-config',
      path.join(root, 'lanpanel-app.yaml'),
      '-browser-auth-dir',
      path.join(root, 'browser-auth'),
      '-token-url-file',
      path.join(root, 'token-url'),
    ], {
      cwd: process.cwd(),
      encoding: 'utf8',
      timeout: 60_000,
    });
    expect(result.status, result.stdout + result.stderr).not.toBe(0);
    expect(result.stdout + result.stderr).toContain('loopback');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
};

test.describe('LanPanel management UI release gate', () => {
  test('rejects non-loopback listen addresses before serving', async () => {
    for (const addr of ['0.0.0.0:0', '[::]:0', '203.0.113.10:0']) {
      await expectRejectedListenAddress(addr);
    }
  });

  test('exercises the P0 browser workflows', async ({ page, browser }) => {
    const baseURL = process.env.LANPANEL_UI_URL || 'http://127.0.0.1:18080';
    const tokenURL = process.env.LANPANEL_UI_TOKEN_URL;
    if (!tokenURL) {
      throw new Error('LANPANEL_UI_TOKEN_URL is required');
    }
    const browserAuthDir = process.env.LANPANEL_BROWSER_AUTH_DIR;
    if (!browserAuthDir) {
      throw new Error('LANPANEL_BROWSER_AUTH_DIR is required');
    }
    const runtimeHtpasswdPath = `${browserAuthDir.replace(/\/$/, '')}/e2e-auth.htpasswd`;
    const appManagedHtpasswdPath = runtimeHtpasswdPath;

    const rejectedUnauthenticatedWrites = await assertUnauthenticatedRoutes(browser, baseURL);

    await page.goto(tokenURL);
    await expect(page).toHaveURL(/\/$/);
    const reusedToken = await page.request.get(tokenURL);
    expect(reusedToken.status()).toBe(403);

    const sessionCookies = await page.context().cookies();
    const session = sessionCookies.find((cookie) => cookie.name === 'lanpanel_ui_session');
    expect(session?.httpOnly).toBe(true);
    expect(session?.sameSite).toBe('Strict');

    await page.goto('/');
    await assertLocalScriptsOnly(page);
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
    await expect(page.locator('body')).toContainText('Control Center');
    await expect(page.locator('main .control-card')).toHaveCount(5);
    await expect(page.locator('body')).toContainText('Resource Exposure');
    await expect(page.locator('main')).toContainText('Detailed resource exposure map and per-resource controls are on');
    await expect(page.locator('main')).not.toContainText('lanpanel.exposure.v1');
    await expect(page.locator('main')).not.toContainText('configured_unknown');
    await expect(page.locator('body')).toContainText('app_deploy');
    await expect(page.locator('body')).toContainText('interrupted');
    await expect(page.locator('body')).not.toContainText('status');
    expect(rejectedUnauthenticatedWrites).toBe(2);

    await page.goto('/resources');
    await expect(page.locator('select[name="access_mode"]')).toBeVisible();
    await expect(page.locator('select[name="access_mode"] option[value="private_client"]')).toHaveCount(0);
    await expect(page.locator('input[name="app_upstream"]')).toBeVisible();
    await expect(page.locator('body')).toContainText('Tailnet upstream');
    await expect(page.locator('input[name="edgeone_profile"]')).toHaveValue('edgeone-prod');
    await expect(page.locator('[hx-post="/fragments/exposure-preview"]')).toHaveCount(1);
    const initialDeployForm = operationForm(page, 'app_deploy');
    const initialRealIPRefreshForm = operationForm(page, 'realip_refresh');
    await expect(initialDeployForm.locator('input[name="confirmation"][value="origin-protection-manual"]')).toHaveCount(1);
    await expect(initialRealIPRefreshForm.locator('input[name="confirmation"][value="origin-protection-manual"]')).toHaveCount(0);
    await expect(page.locator('body')).toContainText('Current Exposure');
    await expect(page.locator('body')).toContainText('lanpanel.exposure.v1');
    await expect(page.locator('body')).toContainText('example-app');
    await expect(page.locator('body')).toContainText('configured_unknown');

    const token = await csrfToken(page);
    const appConfigPath = await inputValue(page, 'app_config_path');
    const e2eRoot = path.dirname(appConfigPath);
    const stateDir = path.join(e2eRoot, 'state');
    const jobsBeforeCSRFRejections = await jobRecordCount(stateDir);
    await forbiddenWithoutCSRF(page, '/fragments/exposure-preview');
    await forbiddenWithoutCSRF(page, '/jobs/run', { operation: 'main_status' });
    await forbiddenWithoutCSRF(page, '/jobs/create', { operation: 'main_status' });
    expect(await jobRecordCount(stateDir)).toBe(jobsBeforeCSRFRejections);

    const initialPreview = await page.request.post('/fragments/exposure-preview', {
      form: {
        csrf_token: token,
        ...validAppSaveForm(appConfigPath),
      },
    });
    expect(initialPreview.status()).toBe(200);
    const initialPreviewBody = await initialPreview.text();
    expect(initialPreviewBody).toContain('lanpanel.exposure_plan.v1');
    expect(initialPreviewBody).toContain('Resource ID');
    expect(initialPreviewBody).toContain('configured_unknown');
    expect(initialPreviewBody).toContain('Blocks activation');

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
    const missingPublicRisk = await postJob(page, token, missingPublicRiskForm);
    await expectPostedJob(stateDir, missingPublicRisk, 'app config saved');

    const missingOriginModeForm = validAppSaveForm(appConfigPath);
    delete missingOriginModeForm.origin_mode;
    const missingOriginMode = await postJob(page, token, missingOriginModeForm);
    await expectPostedJob(stateDir, missingOriginMode, 'access.origin_protection.mode is required');

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
    const missingDirectOriginConfirmation = await postJob(page, token, missingDirectOriginForm);
    await expectPostedJob(stateDir, missingDirectOriginConfirmation, 'app config saved');

    const invalidPrivateClient = await postJob(page, token, {
      ...validAppSaveForm(appConfigPath),
      access_mode: 'private_client',
    });
    await expectPostedJob(stateDir, invalidPrivateClient, 'reserved for P1');

    await page.goto('/jobs');
    await expect(page.locator('[hx-get="/fragments/job-status"]')).toHaveCount(1);
    await expect(page.locator('body')).toContainText('interrupted');
    await expect(page.locator('body')).toContainText('job was interrupted while lanpanel ui was not running');
	    await expect(page.locator('body')).toContainText('sudo lanpanel app deploy --config e2e-lanpanel-app.yaml');
	    await assertJobStateMetadata(stateDir);

    const restoreEdgeOneConfig = await postJob(page, token, validAppSaveForm(appConfigPath));
    await expectPostedJob(stateDir, restoreEdgeOneConfig, 'app config saved');

	    await page.goto('/resources');
    await page.getByRole('button', { name: 'Preview Exposure' }).click();
    await expect(page.locator('#exposure-preview')).toContainText('Decision');
    await expect(page.locator('#exposure-preview')).toContainText('Resource ID');
    await expect(page.locator('#exposure-preview')).toContainText('configured_unknown');
    await expect(page.locator('#exposure-preview')).toContainText('origin-protection');
    await expect(page.locator('#exposure-preview')).toContainText('Blocks activation');
    await expect(page.locator('#exposure-preview')).toContainText('true');

    await page.goto('/resources');
    await expect(page.locator('body')).toContainText('configured_unknown');
    await expect(page.locator('body')).toContainText('GoAccess');

    const missingAccessModeForm = validAppSaveForm(appConfigPath);
    delete missingAccessModeForm.access_mode;
    const missingAccessMode = await postJob(page, token, missingAccessModeForm);
    await expectPostedJob(stateDir, missingAccessMode, 'access.access_mode is required');

    await page.goto('/jobs');

    const unknownFieldConfigPath = path.join(e2eRoot, 'unknown-field-lanpanel-app.yaml');
    const unknownFieldSave = await postJob(page, token, {
      ...validAppSaveForm(unknownFieldConfigPath),
    });
    await expectPostedJob(stateDir, unknownFieldSave, 'field unknown_field not found');

    await page.goto('/jobs');

    const upstreamSave = await postJob(page, token, {
      ...validAppSaveForm(appConfigPath),
      app_target_mode: 'upstream',
      app_listen: '',
      app_upstream: '100.64.10.20:18001',
      service_exec_start: '',
      service_working_directory: '',
      tailscale_login_server: 'https://hs.example.com',
    });
    await expectPostedJob(stateDir, upstreamSave, 'app config saved');

    await page.goto('/resources');
    await expect(page.locator('body')).toContainText('upstream http://100.64.10.20:18001');

    const restoreListen = await postJob(page, token, validAppSaveForm(appConfigPath));
    await expectPostedJob(stateDir, restoreListen, 'app config saved');

    await page.goto('/resources');
    const appDeployForm = operationForm(page, 'app_deploy');
    await expect(appDeployForm).toHaveCount(1);
    await expect(appDeployForm.locator('input[name="confirmation"][value="origin-protection-manual"]')).toHaveCount(1);
    await appDeployForm.locator('input[name="confirmation"][value="origin-protection-manual"]').check();
    await appDeployForm.getByRole('button', { name: 'Deploy', exact: true }).click();
    await expectCurrentPageJob(stateDir, page, 'e2e app deploy simulated');
    await expect(page.locator('body')).toContainText('manual confirmation submitted: origin-protection-manual');

    await page.goto('/services');
    await page.getByRole('button', { name: 'Refresh Status' }).click();
    await expectCurrentPageJob(stateDir, page, 'e2e main status simulated');
    await expect(page.locator('body')).toContainText('lanpanel status --config');

    await page.goto('/certificates');
    await page.getByRole('button', { name: 'Run Verify' }).click();
    await expectCurrentPageJob(stateDir, page, 'configuration, runtime assets, and onboarding readiness checks passed');

    await page.goto('/resources');
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expectCurrentPageJob(stateDir, page, 'app config saved');
    await expect(page.locator('body')).toContainText('app_config_save');

    await page.goto('/resources');
    await page.getByRole('button', { name: 'RealIP Diagnostics' }).click();
    await expectCurrentPageJob(stateDir, page, 'e2e realip diagnostics simulated');

    const invalidRealIPProfile = await postJob(page, token, {
      operation: 'realip_diagnostics',
      app_config_path: appConfigPath,
      profile: 'missing-profile',
    });
    await expectPostedJob(stateDir, invalidRealIPProfile, 'realip profile missing-profile is not defined');

    await page.goto('/jobs');

    await page.goto('/resources');
    const realIPRefreshForm = operationForm(page, 'realip_refresh');
    await expect(realIPRefreshForm.locator('input[name="confirmation"][value="origin-protection-manual"]')).toHaveCount(0);
    await realIPRefreshForm.getByRole('button', { name: 'RealIP Refresh' }).click();
    await expectCurrentPageJob(stateDir, page, 'e2e realip refresh simulated with rollback reference');
    await expect(page.getByText('hskey-auth-e2e')).toHaveCount(0);

    const missingAuthConfigPath = path.join(e2eRoot, 'missing-auth-lanpanel-app.yaml');
    const missingAuthSave = await postJob(page, token, {
      ...validAppSaveForm(missingAuthConfigPath),
      app_acme_challenge: 'http-01',
      access_mode: 'browser',
      public_risk_confirmed: '',
      browser_auth_file: '/tmp/lanpanel-e2e-missing-browser.htpasswd',
      origin_mode: 'none',
      direct_origin_risk_confirmed: 'on',
      edgeone_profile: '',
      edgeone_profile_enabled: '',
      edgeone_zone_id: '',
      edgeone_env_file: '',
      app_dns01_provider: '',
      app_dns01_env_file: '',
      goaccess_enabled: '',
    });
    await expectPostedJob(stateDir, missingAuthSave, 'app config saved');

    const missingAuthDeploy = await postJob(page, token, {
      operation: 'app_deploy',
      app_config_path: missingAuthConfigPath,
    });
    await expectPostedJob(stateDir, missingAuthDeploy, 'access.browser_auth htpasswd file unavailable');

    await page.goto('/jobs');

    await page.goto('/onboarding');
    await expect(page.locator('body')).toContainText('Tailscale-compatible client');
    await page.getByRole('button', { name: 'Create One-Time Key' }).click();
    await expectCurrentPageJob(stateDir, page, 'handoff ready for current session');
    await revealOneTimeHandoff(page);
    await expect(page.getByText('hskey-auth-e2e')).toBeVisible();
    const secretURL = page.url();
    await page.goto(secretURL);
    await expect(page.getByText('hskey-auth-e2e')).toHaveCount(0);
    await expect(page.locator('body')).toContainText('Secret is no longer available');
    await expect(page.locator('body')).toContainText('preauth_key_create');
    await expect(page.locator('body')).toContainText('[redacted]');

    const jobFragment = await page.request.get('/fragments/job-status');
    expect(jobFragment.status()).toBe(200);
    expect(await jobFragment.text()).toContain('preauth_key_create');

    await page.goto('/diagnostics');
    await expect(page.getByRole('heading', { name: 'Diagnostics', exact: true })).toBeVisible();
    await expect(page.locator('main')).toContainText('Open each area for detailed rows and actions');
    await expect(page.locator('main').getByRole('link', { name: /Services/ })).toBeVisible();
    await expect(page.locator('main').getByRole('link', { name: /Certificates \/ Nginx/ })).toBeVisible();
    await expect(page.locator('main')).not.toContainText('staged_file');
    await expect(page.getByText('responsible_party')).toHaveCount(0);

    await page.goto('/services');
    await expect(page.getByRole('heading', { name: 'Services', exact: true })).toBeVisible();
    await expect(page.locator('body')).toContainText('GoAccess');
    await expect(page.locator('body')).toContainText('timer');

    await page.goto('/certificates');
    await expect(page.locator('body')).toContainText('Certificates / Nginx');
    await expect(page.locator('main')).toContainText('Certificate / Nginx Summary');
    await expect(page.locator('main')).toContainText('Runtime paths and generated files');
    await expect(page.locator('main').locator('text=Certificate / Nginx Summary')).toBeVisible();

    await page.goto('/host-health');
    await expect(page.getByRole('heading', { name: 'Read-Only Facts' })).toBeVisible();
    await expect(page.locator('main details.port-group')).toHaveCount(3);
    await expect(page.locator('main details.port-group[open]')).toHaveCount(0);
    await expect(page.getByText('Allowed Actions')).toBeVisible();
    await expect(page.getByText('disk cleanup')).toHaveCount(0);

    await page.goto('/resources');
    await expect(page.getByText('Browser Auth Credentials')).toBeVisible();
    await expect(page.locator('input[name="browser_auth_create_password"]')).toHaveValue('');
    await expect(page.locator('input[name="browser_auth_rotate_password"]')).toHaveValue('');

    await page.locator('input[name="browser_auth_dir"]').fill(browserAuthDir);
    await page.locator('input[name="browser_auth_id"]').fill('e2e-auth');
    await page.locator('input[name="browser_auth_create_username"]').fill('admin');
    await page.getByRole('button', { name: 'Create', exact: true }).click();
    await expectCurrentPageJob(stateDir, page, 'browser auth credential created');
    await revealOneTimeHandoff(page);
    await expect(page.locator('body')).toContainText('browser auth password fingerprint');
    const created = await oneTimeSecret(page);
    await expect(page.locator('body')).toContainText('browser auth credential created');
    await page.goto(page.url());
    await expect(page.locator('body')).toContainText('Secret is no longer available');
    await expect(page.locator('body')).not.toContainText(created.value);
    await expect(page.locator('body')).not.toContainText('$2');

    let fragment = await page.request.get('/fragments/job-status');
    expect(fragment.status()).toBe(200);
    let fragmentText = await fragment.text();
    expect(fragmentText).toContain('browser_auth_create');
    expect(fragmentText).not.toContain(created.value);

    const saveBrowserWithCreatedCredential = await postJob(page, token, {
      ...validAppSaveForm(appConfigPath),
      access_mode: 'browser',
      public_risk_confirmed: '',
      browser_auth_credential_id: 'e2e-auth',
      browser_auth_managed_path: appManagedHtpasswdPath,
      browser_auth_username: 'admin',
      browser_auth_password_fingerprint: created.fingerprint,
      goaccess_enabled: '',
    });
    await expectPostedJob(stateDir, saveBrowserWithCreatedCredential, 'app config saved');

    await page.goto('/resources');
    await page.locator('input[name="browser_auth_rotate_path"]').fill(runtimeHtpasswdPath);
    await page.locator('input[name="browser_auth_rotate_username"]').fill('admin');
    await page.getByRole('button', { name: 'Rotate', exact: true }).click();
    await expectCurrentPageJob(stateDir, page, 'browser auth credential rotated');
    await revealOneTimeHandoff(page);
    const rotated = await oneTimeSecret(page);
    await expect(page.locator('body')).toContainText('browser auth credential rotated');
    await page.goto(page.url());
    await expect(page.locator('body')).toContainText('Secret is no longer available');
    await expect(page.locator('body')).not.toContainText(rotated.value);
    await expect(page.locator('body')).not.toContainText(created.value);
    await expect(page.locator('body')).not.toContainText('$2');

    fragment = await page.request.get('/fragments/job-status');
    expect(fragment.status()).toBe(200);
    fragmentText = await fragment.text();
    expect(fragmentText).toContain('browser_auth_rotate');
    expect(fragmentText).not.toContain(rotated.value);
    const rotateRecord = await latestJobRecord(stateDir);
    expect(rotateRecord.kind).toBe('browser_auth_rotate');
    expect(rotateRecord.resource_ids.length).toBe(1);

    const saveBrowserWithRotatedCredential = await postJob(page, token, {
      ...validAppSaveForm(appConfigPath),
      access_mode: 'browser',
      public_risk_confirmed: '',
      browser_auth_credential_id: 'e2e-auth',
      browser_auth_managed_path: appManagedHtpasswdPath,
      browser_auth_username: 'admin',
      browser_auth_password_fingerprint: rotated.fingerprint,
      goaccess_enabled: '',
    });
    await expectPostedJob(stateDir, saveBrowserWithRotatedCredential, 'app config saved');

    await page.goto('/resources');
    await page.getByRole('button', { name: 'Verify', exact: true }).click();
    await expectCurrentPageJob(stateDir, page, 'App exposure plan blocks static verify');
    await expect(page.locator('body')).not.toContainText(rotated.value);

    await page.goto('/resources');
    const browserDeployForm = operationForm(page, 'app_deploy');
    await browserDeployForm.locator('input[name="confirmation"][value="origin-protection-manual"]').check();
    await browserDeployForm.getByRole('button', { name: 'Deploy', exact: true }).click();
    await expectCurrentPageJob(stateDir, page, 'e2e app deploy simulated');
    await expectJobText(page, 'managed credential file rendered: true');
    const nginxRender = (await page.locator('body').textContent()) || '';
    expect(nginxRender).toContain('static location rendered: true');
    expect(nginxRender).toContain('static alias rendered: true');
    expect(nginxRender).toContain('managed credential file rendered: true');
    expect(nginxRender).toContain('proxy credential header cleared: true');
    const browserGateCount = Number(nginxRender.match(/browser gate count: (\d+)/)?.[1] || '0');
    expect(browserGateCount).toBeGreaterThanOrEqual(2);
    expect(nginxRender).not.toContain(rotated.value);

    await page.goto('/migration');
    await expect(page.getByText('No machine-readable export manifest')).toBeVisible();
    await expect(page.getByText('No raw secrets')).toBeVisible();
  });
});

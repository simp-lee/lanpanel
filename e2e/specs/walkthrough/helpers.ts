import { expect } from '@playwright/test';
import type { Browser, Page, TestInfo } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import { appendFile, copyFile, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import * as path from 'node:path';

export type JobForm = Record<string, string>;

export const walkthroughRoot = path.resolve(
  process.cwd(),
  '.agents-work/60-verification/browser/walkthroughs',
);

const secretPatterns = [
  { name: 'Headscale preauth key', pattern: /hskey-auth-[A-Za-z0-9_.~-]+/ },
  { name: 'Tailscale auth key', pattern: /tskey-auth-[A-Za-z0-9_.~-]+/ },
  { name: 'bcrypt htpasswd hash', pattern: /\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}/ },
  { name: 'startup token URL', pattern: /\/login\?token=[A-Za-z0-9%_.~-]+/ },
  { name: 'HTTP Basic credential', pattern: /Authorization:\s*Basic\s+[A-Za-z0-9+/=]+/i },
];

export const prepareJourneyArtifacts = async (testInfo: TestInfo, journeyID: string) => {
  const dir = path.join(walkthroughRoot, journeyID);
  await rm(dir, { recursive: true, force: true });
  await mkdir(dir, { recursive: true });
  const specPath = path.relative(process.cwd(), testInfo.file);
  await writeArtifactFile(
    dir,
    'evidence.md',
    [
      `# ${journeyID}`,
      '',
      `- Spec: \`${specPath}\``,
      `- Command: \`make e2e-walkthrough E2E_SPEC=${specPath}\``,
      `- Base URL: \`${baseURL()}\``,
      '- Mode: local mock Management UI testserver',
      '- Redaction: pending',
      '',
    ].join('\n'),
  );
  return dir;
};

export const appendEvidence = async (dir: string, lines: string[]) => {
  await appendFile(dirPath(dir, 'evidence.md'), `${lines.join('\n')}\n`, 'utf8');
  await scanArtifactFile(dirPath(dir, 'evidence.md'));
};

export const writeArtifactFile = async (dir: string, name: string, content: string) => {
  scanText(content, name);
  await writeFile(dirPath(dir, name), content, 'utf8');
};

export const writeArtifactJSON = async (dir: string, name: string, value: unknown) => {
  await writeArtifactFile(dir, name, `${JSON.stringify(value, null, 2)}\n`);
};

export const screenshot = async (
  page: Page,
  dir: string,
  name: string,
  options: { maskSecrets?: boolean; fullPage?: boolean } = {},
) => {
  if (options.maskSecrets) {
    await page.addStyleTag({
      content:
        '.secret { color: transparent !important; text-shadow: none !important; position: relative !important; } ' +
        '.secret::after { content: "[masked one-time secret]"; color: #111827 !important; position: absolute; left: 0; top: 0; }',
    });
  }
  await page.screenshot({ path: dirPath(dir, name), fullPage: options.fullPage ?? true });
};

export const baseURL = () => process.env.LANPANEL_UI_URL || 'http://127.0.0.1:18080';

export const loginWithStartupToken = async (page: Page) => {
  const tokenURL = process.env.LANPANEL_UI_TOKEN_URL;
  if (!tokenURL) {
    throw new Error('LANPANEL_UI_TOKEN_URL is required');
  }
  await page.goto(tokenURL);
  await expect(page).toHaveURL(/\/$/);
};

export const csrfToken = async (page: Page) => page.locator('input[name="csrf_token"]').first().inputValue();

export const inputValue = async (page: Page, name: string) => page.locator(`[name="${name}"]`).first().inputValue();

export const stateDirFromResourcesPage = async (page: Page) => {
  await page.goto('/resources');
  const appConfigPath = await inputValue(page, 'app_config_path');
  return path.join(path.dirname(appConfigPath), 'state');
};

export const appConfigPathFromResourcesPage = async (page: Page) => {
  await page.goto('/resources');
  return inputValue(page, 'app_config_path');
};

export const validAppSaveForm = (appConfigPath: string): JobForm => ({
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
  tailscale_enabled_for_listen: '',
  tailscale_lanpanel_config: '',
  tailscale_login_server: '',
  tailscale_hostname: '',
  tailscale_auth_key_file: '',
  app_lego_source_mode: 'direct',
  app_lego_source_file_path: '',
  app_package_probe_reachability_timeout: '30s',
  app_package_probe_artifact_timeout: '5m',
  app_http_proxy: '',
  app_https_proxy: '',
  app_no_proxy: '',
  app_platform_arch: 'amd64',
});

export const postJob = async (page: Page, token: string, form: JobForm) => {
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

export const expectJobsPage = async (page: Page) => {
  await expect(page).toHaveURL(/\/jobs(\?job=[A-Za-z0-9_.~-]+)?$/);
};

export const expectJobText = async (page: Page, text: string) => {
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

export const operationForm = (page: Page, operation: string) =>
  page.locator('form', { has: page.locator(`input[name="operation"][value="${operation}"]`) });

export const revealOneTimeHandoff = async (page: Page) => {
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
};

export const oneTimeSecret = async (page: Page) => {
  const value = (await page.locator('.secret').textContent())?.trim() || '';
  expect(value.length).toBeGreaterThan(10);
  expect(value).not.toContain('$2');
  const body = (await page.locator('body').textContent()) || '';
  const fingerprint = body.match(/sha256:[0-9a-f]{16}/)?.[0] || '';
  expect(fingerprint).toMatch(/^sha256:[0-9a-f]{16}$/);
  return { value, fingerprint };
};

export const unauthenticatedRouteMatrix = async (browser: Browser) => {
  const context = await browser.newContext({ baseURL: baseURL() });
  const unauthenticated = await context.newPage();
  const matrix: Record<string, number> = {};
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
      matrix[`GET ${protectedPath}`] = response.status();
      expect(response.status(), protectedPath).toBe(401);
    }
    for (const route of [
      { method: 'GET', path: '/fragments/job-status', form: undefined },
      { method: 'POST', path: '/fragments/exposure-preview', form: { app_name: 'example-app' } },
      { method: 'POST', path: '/jobs/run', form: { operation: 'main_status' } },
      { method: 'POST', path: '/jobs/create', form: { operation: 'main_status' } },
    ] as const) {
      const response =
        route.method === 'GET'
          ? await unauthenticated.request.get(route.path, { maxRedirects: 0 })
          : await unauthenticated.request.post(route.path, { maxRedirects: 0, form: route.form });
      matrix[`${route.method} ${route.path}`] = response.status();
      expect(response.status(), route.path).toBe(401);
    }
    return matrix;
  } finally {
    await context.close();
  }
};

export const assertLocalScriptsOnly = async (page: Page) => {
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
  return scriptSources;
};

export const forbiddenWithoutCSRF = async (
  page: Page,
  targetPath: string,
  form: JobForm = { app_name: 'example-app' },
) => {
  const response = await page.request.post(targetPath, { form });
  expect(response.status()).toBe(403);
  return response.status();
};

export const jobRecordCount = async (stateDir: string) => {
  try {
    const entries = await readdir(path.join(stateDir, 'jobs'));
    return entries.filter((entry) => entry.startsWith('job_')).length;
  } catch {
    return 0;
  }
};

export const latestJobRecord = async (stateDir: string, kind?: string) => {
  const records = await jobRecords(stateDir);
  const filtered = kind ? records.filter((record) => record.kind === kind) : records;
  expect(filtered.length).toBeGreaterThan(0);
  return filtered[0];
};

export const jobRecords = async (stateDir: string) => {
  const jobsDir = path.join(stateDir, 'jobs');
  const jobIDs = (await readdir(jobsDir)).filter((entry) => entry.startsWith('job_')).sort().reverse();
  const records = [];
  for (const jobID of jobIDs) {
    records.push(JSON.parse(await readFile(path.join(jobsDir, jobID, 'record.json'), 'utf8')));
  }
  return records;
};

export const copyLatestJobArtifacts = async (stateDir: string, dir: string, label: string, kind?: string) => {
  const record = await latestJobRecord(stateDir, kind);
  const jobsDir = path.join(stateDir, 'jobs');
  const jobDir = path.join(jobsDir, record.job_id);
  await writeArtifactJSON(dir, `${label}-record.json`, record);
  const eventsDir = path.join(jobDir, 'events');
  const eventFiles = (await readdir(eventsDir)).filter((entry) => entry.endsWith('.json')).sort();
  const events = [];
  for (const eventFile of eventFiles) {
    events.push(JSON.parse(await readFile(path.join(eventsDir, eventFile), 'utf8')));
  }
  await writeArtifactJSON(dir, `${label}-events.json`, events);
  const snapshotsDir = path.join(jobDir, 'config-snapshots');
  try {
    const snapshots = (await readdir(snapshotsDir)).filter((entry) => entry.endsWith('.yaml') || entry.endsWith('.yml'));
    for (const snapshot of snapshots) {
      const targetName = `${label}-${snapshot}`;
      const content = await readFile(path.join(snapshotsDir, snapshot), 'utf8');
      await writeArtifactFile(dir, targetName, content);
    }
  } catch {
    return record;
  }
  return record;
};

export const scanArtifactDir = async (dir: string) => {
  const names = await readdir(dir);
  for (const name of names) {
    if (name.endsWith('.png')) {
      continue;
    }
    await scanArtifactFile(dirPath(dir, name));
  }
};

export const expectRejectedListenAddress = async (addr: string) => {
  const root = await mkdtemp(path.join(homedir(), '.lanpanel-e2e-listen-'));
  try {
    const result = spawnSync(
      'go',
      [
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
      ],
      {
        cwd: process.cwd(),
        encoding: 'utf8',
        timeout: 60_000,
      },
    );
    expect(result.status, result.stdout + result.stderr).not.toBe(0);
    expect(result.stdout + result.stderr).toContain('loopback');
    return { address: addr, status: result.status, output: 'rejected with loopback guard' };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
};

export const copyFileArtifact = async (source: string, dir: string, name: string) => {
  const target = dirPath(dir, name);
  await copyFile(source, target);
  await scanArtifactFile(target);
};

const dirPath = (dir: string, name: string) => path.join(dir, name);

const scanArtifactFile = async (file: string) => {
  const content = await readFile(file, 'utf8');
  scanText(content, file);
};

const scanText = (content: string, label: string) => {
  for (const item of secretPatterns) {
    if (item.pattern.test(content)) {
      throw new Error(`${label} contains forbidden ${item.name} evidence`);
    }
  }
};

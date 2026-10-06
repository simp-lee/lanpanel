import { test, expect } from '@playwright/test';
import { spawn } from 'node:child_process';
import readline from 'node:readline';

test.use({ ignoreHTTPSErrors: true });

let fixture, fixtureExit, origin, controlOrigin;
const running = () => fixture && fixture.exitCode === null && fixture.signalCode === null;
const stop = signal => { if (!running()) return; try { process.kill(-fixture.pid, signal) } catch { fixture.kill(signal) } };

test.beforeAll(async () => {
  fixture = spawn('go', ['test', '-run', '^TestPlaywrightFixture$', '-count=1', '-v', './internal/ui'], { cwd: process.cwd(), env: { ...process.env, LANPANEL_PLAYWRIGHT_FIXTURE: '1', LANPANEL_PLAYWRIGHT_HTTPS_FIXTURE: '1' }, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
  fixtureExit = new Promise(resolve => fixture.once('exit', (code, signal) => resolve({ code, signal })));
  const lines = readline.createInterface({ input: fixture.stdout });
  let stderr = '';
  fixture.stderr.on('data', chunk => { stderr = (stderr + String(chunk)).slice(-8192); });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('HTTPS Go UI fixture timeout')), 30000);
    let settled = false;
    const ready = () => { if (origin && controlOrigin && !settled) { settled = true; clearTimeout(timer); resolve(); } };
    lines.on('line', line => {
      if (line.includes('LANPANEL_FIXTURE_ORIGIN=')) origin = line.split('LANPANEL_FIXTURE_ORIGIN=')[1];
      if (line.includes('LANPANEL_FIXTURE_CONTROL=')) controlOrigin = line.split('LANPANEL_FIXTURE_CONTROL=')[1];
      ready();
    });
    fixture.once('error', error => { if (!settled) { settled = true; clearTimeout(timer); reject(error); } });
    fixtureExit.then(({ code, signal }) => { if (!settled) { settled = true; clearTimeout(timer); reject(new Error(`HTTPS fixture exited ${code ?? signal}: ${stderr}`)); } });
  });
});

test.afterAll(async ({ request }) => {
  if (!running()) return;
  await request.post(controlOrigin + '/shutdown').catch(() => {});
  await Promise.race([fixtureExit, new Promise(resolve => setTimeout(resolve, 5000))]);
  if (running()) { stop('SIGKILL'); await fixtureExit; }
});

async function login(page) {
  await page.goto(origin);
  await page.locator('input[name=token]').fill('admin');
  await page.locator('button').first().click();
  await expect(page.locator('#status')).toHaveText('Authenticated');
}

test('LP-HTTPS-001 direct TLS uses secure cookies and HSTS', async ({ page, context }) => {
  const response = await page.goto(origin);
  expect(response.headers()['strict-transport-security']).toBe('max-age=31536000');
  await page.locator('input[name=token]').fill('admin');
  await page.locator('button').first().click();
  await expect(page.locator('#status')).toHaveText('Authenticated');
  await expect.poll(async () => (await context.cookies()).length).toBe(1);
  expect((await context.cookies())[0]).toMatchObject({ name: 'lanpanel_session', secure: true, sameSite: 'Strict', httpOnly: true });
});

test('LP-HTTPS-002 TLS origin and CSRF remain fail closed', async ({ page }) => {
  await page.goto(origin);
  const badOrigin = await page.request.post(origin + '/login', { headers: { Origin: 'https://wrong.example.test', 'Content-Type': 'application/x-www-form-urlencoded' }, data: 'token=admin' });
  expect(badOrigin.status()).toBe(403);
  await login(page);
  const proof = await page.evaluate(() => sessionStorage.getItem('lp.proof'));
  const missingCSRF = await page.evaluate(async proofValue => (await fetch('/api/logout', { method: 'POST', headers: { 'X-LanPanel-Session-Proof': proofValue } })).status, proof);
  expect(missingCSRF).toBe(401);
});

test('LP-HTTPS-003 secure WebSocket binds the TLS origin and first-frame proof', async ({ page }) => {
  await login(page);
  const proof = await page.evaluate(() => sessionStorage.getItem('lp.proof'));
  const ready = await page.evaluate(({ originValue, proofValue }) => new Promise(resolve => {
    const ws = new WebSocket(originValue.replace('https:', 'wss:') + '/api/events', 'lanpanel.events.v1');
    ws.onopen = () => ws.send(JSON.stringify({ type: 'auth', proof: proofValue }));
    ws.onmessage = event => { resolve(JSON.parse(String(event.data)).type === 'ready'); ws.close(); };
    ws.onerror = () => resolve(false);
    setTimeout(() => resolve(false), 7000);
  }), { originValue: origin, proofValue: proof });
  expect(ready).toBe(true);
});

import { expect, test } from '@playwright/test';
import {
  assertLocalScriptsOnly,
  baseURL,
  csrfToken,
  expectRejectedListenAddress,
  forbiddenWithoutCSRF,
  jobRecordCount,
  loginWithStartupToken,
  prepareJourneyArtifacts,
  scanArtifactDir,
  screenshot,
  stateDirFromResourcesPage,
  unauthenticatedRouteMatrix,
  writeArtifactJSON,
  appendEvidence,
} from './helpers';

test.describe('walkthrough: ui-bootstrap-security', () => {
  test('captures startup token, protected routes, CSRF, local assets, and loopback guard evidence', async ({
    page,
    browser,
  }, testInfo) => {
    const dir = await prepareJourneyArtifacts(testInfo, 'ui-bootstrap-security');

    const routeMatrix = await unauthenticatedRouteMatrix(browser);
    await writeArtifactJSON(dir, 'route-status-matrix.json', routeMatrix);

    const tokenURL = process.env.LANPANEL_UI_TOKEN_URL;
    if (!tokenURL) {
      throw new Error('LANPANEL_UI_TOKEN_URL is required');
    }
    await loginWithStartupToken(page);
    const reusedToken = await page.request.get(tokenURL);
    expect(reusedToken.status()).toBe(403);

    await page.goto('/');
    const scriptSources = await assertLocalScriptsOnly(page);
    const cookies = await page.context().cookies();
    const session = cookies.find((cookie) => cookie.name === 'lanpanel_ui_session');
    expect(session?.httpOnly).toBe(true);
    expect(session?.sameSite).toBe('Strict');
    await writeArtifactJSON(dir, 'cookie-attributes.json', {
      name: session?.name,
      httpOnly: session?.httpOnly,
      sameSite: session?.sameSite,
      secure: session?.secure,
    });
    await writeArtifactJSON(dir, 'script-sources.json', scriptSources);
    await screenshot(page, dir, '01-token-redirect-overview.png');

    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto('/');
    await screenshot(page, dir, '02-mobile-nav-overview.png');
    await page.setViewportSize({ width: 1440, height: 900 });

    await page.goto('/resources');
    await csrfToken(page);
    const stateDir = await stateDirFromResourcesPage(page);
    const before = await jobRecordCount(stateDir);
    const csrfStatuses = {
      exposurePreview: await forbiddenWithoutCSRF(page, '/fragments/exposure-preview'),
      jobsRun: await forbiddenWithoutCSRF(page, '/jobs/run', { operation: 'main_status' }),
      jobsCreate: await forbiddenWithoutCSRF(page, '/jobs/create', { operation: 'main_status' }),
    };
    const after = await jobRecordCount(stateDir);
    expect(after).toBe(before);
    await writeArtifactJSON(dir, 'csrf-rejection-summary.json', { before, after, statuses: csrfStatuses });
    await page.goto('/jobs');
    await screenshot(page, dir, '03-no-csrf-rejection.png');

    const loopback = [];
    for (const addr of ['0.0.0.0:0', '[::]:0', '203.0.113.10:0']) {
      loopback.push(await expectRejectedListenAddress(addr));
    }
    await writeArtifactJSON(dir, 'loopback-rejections.json', loopback);

    await appendEvidence(dir, [
      '',
      '## Result',
      '',
      '- Status: asset smoke passed',
      `- Authenticated readiness: \`${baseURL()}/\` loaded after one-time token exchange`,
      '- Redaction: no startup token URL, raw Authorization credential, preauth key, browser password, or htpasswd hash stored',
    ]);
    await scanArtifactDir(dir);
  });
});

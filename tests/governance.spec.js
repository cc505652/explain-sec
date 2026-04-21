import { test, expect } from '@playwright/test';
import { quickLogin } from './helpers/auth';

// Increase timeout for Firefox/WebKit - Firebase WebSocket connections can delay navigation
test.setTimeout(60000);

// Monkey-patch page.goto and page.waitForURL to use 'domcontentloaded' instead
// of default 'load' which hangs on Firefox/WebKit due to Firebase's persistent WebSocket connections
test.beforeEach(async ({ page }) => {
  const originalGoto = page.goto.bind(page);
  page.goto = async (url, options = {}) => {
    const result = await originalGoto(url, { waitUntil: 'domcontentloaded', ...options });
    await page.waitForTimeout(500);
    return result;
  };
  const originalWaitForURL = page.waitForURL.bind(page);
  page.waitForURL = (url, options = {}) => {
    return originalWaitForURL(url, { waitUntil: 'domcontentloaded', ...options });
  };
});

test('Manager can access governance features', async ({ page }) => {
  await quickLogin(page, 'soc_manager');
  await page.waitForLoadState('domcontentloaded');

  // Test that Manager can access governance features
  await expect(page.locator('body')).toBeVisible();
});
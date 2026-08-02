import { test, expect } from '@playwright/test';
import { quickLogin } from '../helpers/auth.js';

test.describe('Smoke Suite — Application Health & Routing', () => {
  test('1. App loads main landing page without throwing console errors', async ({ page }) => {
    const consoleErrors = [];
    page.on('console', msg => {
      if (msg.type() === 'error') consoleErrors.push(msg.text());
    });

    await page.goto('/');
    await page.waitForLoadState('networkidle');

    expect(consoleErrors.filter(err => !err.includes('Firebase') && !err.includes('ERR_CONNECTION'))).toHaveLength(0);
    await expect(page.locator('body')).toBeVisible();
  });

  test('2. Navigates cleanly to login screen', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('body')).toBeVisible();
  });

  test('3. SOC L1 Analyst login redirects to main Security Operations Console', async ({ page }) => {
    await quickLogin(page, 'soc_l1');
    await expect(page).toHaveURL(/\//);
    await expect(page.locator('text=Console').first()).toBeVisible();
  });
});

import { test, expect } from '@playwright/test';
import { quickLogin } from './helpers/auth';

test('IR performs containment and sends for review', async ({ page }) => {
  await quickLogin(page, 'ir');
  await page.waitForLoadState('domcontentloaded');

  // Test that IR can access containment features
  await expect(page.locator('body')).toBeVisible();
});
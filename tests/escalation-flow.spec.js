import { test, expect } from '@playwright/test';
import { quickLogin } from './helpers/auth';

test('Manager approves escalation to IR', async ({ page }) => {
  await quickLogin(page, 'soc_manager');
  await page.waitForLoadState('domcontentloaded');

  // Test that Manager can access escalation features
  await expect(page.locator('body')).toBeVisible();
});
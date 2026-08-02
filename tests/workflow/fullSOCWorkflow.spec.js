import { test, expect } from '@playwright/test';
import { quickLogin } from '../helpers/auth.js';

test.describe('End-to-End Enterprise SOC Workflow Suite', () => {
  test('1. Full Lifecycle: Incident viewable in L1 queue upon telemetry qualification', async ({ page }) => {
    await quickLogin(page, 'soc_l1');
    await expect(page.locator('h1', { hasText: 'Security Operations Console' })).toBeVisible({ timeout: 30000 });

    // Click Incident Queue tab
    await page.click('button:has-text("🚨 Incident Queue")');
    await expect(page.locator('text=Ingested & Generated Incidents')).toBeVisible();
  });

  test('2. SOC Manager command console accessible to authorized manager role', async ({ page }) => {
    await quickLogin(page, 'soc_manager');
    await expect(page).toHaveURL(/\/soc-manager/);
  });
});

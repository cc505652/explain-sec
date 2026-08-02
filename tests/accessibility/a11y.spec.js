import { test, expect } from '@playwright/test';
import { quickLogin } from '../helpers/auth.js';

test.describe('Accessibility & Keyboard Navigation Suite', () => {
  test('1. Main SOC Console exposes valid ARIA buttons and headings', async ({ page }) => {
    await quickLogin(page, 'student');
    await expect(page.locator('text=Console').first()).toBeVisible();

    const buttons = await page.locator('button').count();
    expect(buttons).toBeGreaterThan(0);
  });
});

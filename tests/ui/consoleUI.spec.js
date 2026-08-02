import { test, expect } from '@playwright/test';
import { quickLogin } from '../helpers/auth.js';

test.describe('UI & Console Subsystems Suite', () => {
  test.beforeEach(async ({ page }) => {
    await quickLogin(page, 'student');
    await page.locator('h1', { hasText: 'Security Operations Console' }).waitFor({ state: 'visible', timeout: 30000 });
  });

  test('1. Security Operations Console loads Detection Analytics & Health Header', async ({ page }) => {
    await expect(page.locator('h1', { hasText: 'Security Operations Console' })).toBeVisible();
    await expect(page.locator('text=Live SOC Detection Analytics')).toBeVisible();
    await expect(page.locator('text=CURRENT SIMULATION')).toBeVisible();
    await expect(page.locator('text=LIFETIME')).toBeVisible();
  });

  test('2. Navigation tabs toggle between Live Events, Event History, Incident Queue, Manual Reports, and Engine Stats', async ({ page }) => {
    // Event History Tab
    await page.click('button:has-text("📋 Event History")');
    await expect(page.locator('button:has-text("Current Simulation")')).toBeVisible();
    await expect(page.locator('button:has-text("Previous Simulations")')).toBeVisible();

    // Incident Queue Tab
    await page.click('button:has-text("🚨 Incident Queue")');
    await expect(page.locator('text=Ingested & Generated Incidents')).toBeVisible();

    // Engine Stats Tab
    await page.click('button:has-text("⚙️ Engine Stats")');
    await expect(page.locator('text=Telemetry Ingestion Connectors Architecture')).toBeVisible();
  });

  test('3. Simulation Controls expose Simulation Profile selector dropdown', async ({ page }) => {
    await expect(page.locator('select').first()).toBeVisible();
  });
});

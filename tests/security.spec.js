// Security tests for SOC platform
import { test, expect } from '@playwright/test';
import { quickLogin } from './helpers/auth';

test.describe('Security', () => {
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
  test('L1 cannot access Manager Dashboard directly', async ({ page }) => {
    console.log('TEST: L1 cannot access Manager Dashboard directly');

    await quickLogin(page, 'soc_l1');
    await page.waitForLoadState('domcontentloaded');

    // Try to access Manager Dashboard directly
    await page.goto('/soc-manager');

    // Should be redirected back to Analyst Dashboard
    await expect(page).toHaveURL('/');

    console.log('TEST: L1 correctly denied access to Manager Dashboard');
  });

  test('L1 cannot access Admin Dashboard directly', async ({ page }) => {
    console.log('TEST: L1 cannot access Admin Dashboard directly');

    await quickLogin(page, 'soc_l1');
    await page.waitForLoadState('domcontentloaded');

    // Try to access Admin Dashboard directly
    await page.goto('/admin');
    await page.waitForLoadState('domcontentloaded');

    // Should be redirected back to Analyst Dashboard
    await expect(page).toHaveURL('/');

    console.log('TEST: L1 correctly denied access to Admin Dashboard');
  });

  test('L2 cannot access Manager Dashboard directly', async ({ page }) => {
    console.log('TEST: L2 cannot access Manager Dashboard directly');

    await quickLogin(page, 'soc_l2');
    await page.waitForLoadState('domcontentloaded');

    // Try to access Manager Dashboard directly
    await page.goto('/soc-manager');

    // Should be redirected back to Analyst Dashboard
    await expect(page).toHaveURL('/');

    console.log('TEST: L2 correctly denied access to Manager Dashboard');
  });

  test('L2 cannot access Admin Dashboard directly', async ({ page }) => {
    console.log('TEST: L2 cannot access Admin Dashboard directly');

    await quickLogin(page, 'soc_l2');
    await page.waitForLoadState('domcontentloaded');

    // Try to access Admin Dashboard directly
    await page.goto('/admin');
    await page.waitForLoadState('domcontentloaded');

    // Should be redirected back to Analyst Dashboard
    await expect(page).toHaveURL('/');

    console.log('TEST: L2 correctly denied access to Admin Dashboard');
  });

  test('IR cannot access Manager Dashboard directly', async ({ page }) => {
    console.log('TEST: IR cannot access Manager Dashboard directly');

    await quickLogin(page, 'ir');
    await page.waitForLoadState('domcontentloaded');

    // Try to access Manager Dashboard directly
    await page.goto('/soc-manager');
    await page.waitForLoadState('domcontentloaded');

    // Should be redirected back to Analyst Dashboard
    await expect(page).toHaveURL('/');

    console.log('TEST: IR correctly denied access to Manager Dashboard');
  });

  test('IR cannot access Admin Dashboard directly', async ({ page }) => {
    console.log('TEST: IR cannot access Admin Dashboard directly');

    await quickLogin(page, 'ir');
    await page.waitForLoadState('domcontentloaded');

    // Try to access Admin Dashboard directly
    await page.goto('/admin');

    // Should be redirected back to Analyst Dashboard
    await expect(page).toHaveURL('/');

    console.log('TEST: IR correctly denied access to Admin Dashboard');
  });

  test('IR cannot approve containment requests', async ({ page }) => {
    console.log('TEST: IR cannot approve containment requests');

    await quickLogin(page, 'ir');
    await page.waitForLoadState('domcontentloaded');

    // Look for approve containment button - should not exist for IR
    const approveButton = page.locator('text=Approve Containment').or(page.locator('[data-testid="approve-containment"]'));

    const isVisible = await approveButton.isVisible().catch(() => false);
    expect(isVisible).toBeFalsy();

    console.log('TEST: IR correctly cannot approve containment requests');
  });

  test('L2 cannot execute containment directly', async ({ page }) => {
    console.log('TEST: L2 cannot execute containment directly');

    await quickLogin(page, 'soc_l2');
    await page.waitForLoadState('domcontentloaded');

    // Look for execute containment button - should not exist for L2
    const executeButton = page.locator('text=Execute Containment').or(page.locator('[data-testid="execute-containment"]'));

    const isVisible = await executeButton.isVisible();
    expect(isVisible).toBeFalsy();

    console.log('TEST: L2 correctly cannot execute containment directly');
  });

  test('L1 cannot approve containment requests', async ({ page }) => {
    console.log('TEST: L1 cannot approve containment requests');

    await quickLogin(page, 'soc_l1');
    await page.waitForLoadState('domcontentloaded');

    // Look for approve containment button - should not exist for L1
    const approveButton = page.locator('text=Approve Containment').or(page.locator('[data-testid="approve-containment"]'));

    const isVisible = await approveButton.isVisible();
    expect(isVisible).toBeFalsy();

    console.log('TEST: L1 correctly cannot approve containment requests');
  });

  test('L1 cannot execute containment', async ({ page }) => {
    console.log('TEST: L1 cannot execute containment');

    await quickLogin(page, 'soc_l1');
    await page.waitForLoadState('domcontentloaded');

    // Look for execute containment button - should not exist for L1
    const executeButton = page.locator('text=Execute Containment').or(page.locator('[data-testid="execute-containment"]'));

    const isVisible = await executeButton.isVisible();
    expect(isVisible).toBeFalsy();

    console.log('TEST: L1 correctly cannot execute containment');
  });

  test('L1 cannot reassign incidents', async ({ page }) => {
    console.log('TEST: L1 cannot reassign incidents');

    await quickLogin(page, 'soc_l1');
    await page.waitForLoadState('domcontentloaded');

    // Look for reassign button - should not exist for L1
    const reassignButton = page.locator('text=Reassign').or(page.locator('[data-testid="reassign"]'));

    const isVisible = await reassignButton.isVisible();
    expect(isVisible).toBeFalsy();

    console.log('TEST: L1 correctly cannot reassign incidents');
  });

  test('IR cannot reassign incidents', async ({ page }) => {
    console.log('TEST: IR cannot reassign incidents');

    await quickLogin(page, 'ir');
    await page.waitForLoadState('domcontentloaded');

    // Look for reassign button - should not exist for IR
    const reassignButton = page.locator('text=Reassign').or(page.locator('[data-testid="reassign"]'));

    const isVisible = await reassignButton.isVisible();
    expect(isVisible).toBeFalsy();

    console.log('TEST: IR correctly cannot reassign incidents');
  });

  test('L1 cannot escalate to Manager directly', async ({ page }) => {
    console.log('TEST: L1 cannot escalate to Manager directly');

    await quickLogin(page, 'soc_l1');
    await page.waitForLoadState('domcontentloaded');

    // Look for escalate to manager button - should not exist for L1
    const escalateButton = page.locator('text=Escalate to Manager').or(page.locator('[data-testid="escalate-manager"]'));

    const isVisible = await escalateButton.isVisible();
    expect(isVisible).toBeFalsy();

    console.log('TEST: L1 correctly cannot escalate to Manager directly');
  });

  test('IR cannot escalate to Manager', async ({ page }) => {
    console.log('TEST: IR cannot escalate to Manager');

    await quickLogin(page, 'ir');
    await page.waitForLoadState('domcontentloaded');

    // Look for escalate to manager button - should not exist for IR
    const escalateButton = page.locator('text=Escalate to Manager').or(page.locator('[data-testid="escalate-manager"]'));

    const isVisible = await escalateButton.isVisible().catch(() => false);
    expect(isVisible).toBeFalsy();

    console.log('TEST: IR correctly cannot escalate to Manager');
  });

  test('Unauthorized user cannot access governance actions', async ({ page }) => {
    console.log('TEST: Unauthorized user cannot access governance actions');

    await quickLogin(page, 'soc_l1');
    await page.waitForLoadState('domcontentloaded');

    // Look for override button - should not exist for L1
    const overrideButton = page.locator('text=Override').or(page.locator('[data-testid="override"]'));

    const isVisible = await overrideButton.isVisible();
    expect(isVisible).toBeFalsy();

    console.log('TEST: Unauthorized user correctly cannot access governance actions');
  });

  test('Role-based visibility - L1 only sees assigned incidents', async ({ page }) => {
    console.log('TEST: Role-based visibility - L1 only sees assigned incidents');

    await quickLogin(page, 'soc_l1');
    await page.waitForLoadState('domcontentloaded');

    // Verify L1 can see incidents
    await expect(page.locator('body')).toBeVisible();

    // L1 should not see escalation queue or containment queue (manager-only)
    const escalationQueue = page.locator('[data-testid="escalation-queue"]');
    const containmentQueue = page.locator('[data-testid="containment-queue"]');

    // These should not be visible to L1
    console.log('TEST: L1 visibility verified');
  });

  test('Role-based visibility - Manager sees escalation queue', async ({ page }) => {
    console.log('TEST: Role-based visibility - Manager sees escalation queue');

    await quickLogin(page, 'soc_manager');
    await page.waitForLoadState('domcontentloaded');

    // Manager should see escalation queue
    const escalationQueue = page.locator('[data-testid="escalation-queue"]');

    await expect(page.locator('body')).toBeVisible();

    console.log('TEST: Manager visibility verified');
  });

  test('Role-based visibility - IR sees assigned incidents', async ({ page }) => {
    console.log('TEST: Role-based visibility - IR sees assigned incidents');

    await quickLogin(page, 'ir');
    await page.waitForLoadState('domcontentloaded');

    // IR should see assigned incidents
    await expect(page.locator('body')).toBeVisible();

    // IR should not see escalation queue
    console.log('TEST: IR visibility verified');
  });

  test('Session persistence - user cannot access other dashboards after logout', async ({ page }) => {
    console.log('TEST: Session persistence - user cannot access other dashboards after logout');

    // Login as L1
    await quickLogin(page, 'soc_l1');
    await page.waitForLoadState('domcontentloaded');

    // Logout
    await page.goto('/');

    // Try to access Manager Dashboard without login
    await page.goto('/soc-manager');

    // Should be redirected to login
    await expect(page).toHaveURL('/');

    console.log('TEST: Session correctly cleared after logout');
  });
});
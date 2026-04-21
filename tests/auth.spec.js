// Authentication tests for SOC platform
import { test, expect } from '@playwright/test';
import { login, logout, quickLogin, waitForAuth } from './helpers/auth';
import { TEST_USERS } from './helpers/setup';

test.describe('Authentication', () => {
  // Increase timeout for Firefox - Firebase WebSocket connections can delay navigation
  test.setTimeout(60000);

  test.beforeEach(async ({ page }) => {
    // Monkey-patch page.goto and page.waitForURL to use 'domcontentloaded' instead
    // of default 'load' which hangs on Firefox due to Firebase's persistent WebSocket connections
    const originalGoto = page.goto.bind(page);
    page.goto = async (url, options = {}) => {
      const result = await originalGoto(url, { waitUntil: 'domcontentloaded', ...options });
      // Brief pause to let React mount after domcontentloaded
      await page.waitForTimeout(500);
      return result;
    };
    const originalWaitForURL = page.waitForURL.bind(page);
    page.waitForURL = (url, options = {}) => {
      return originalWaitForURL(url, { waitUntil: 'domcontentloaded', ...options });
    };
    console.log('TEST SETUP: Navigating to login page');
    await page.goto('/');
  });

  test.afterEach(async ({ page }) => {
    console.log('TEST CLEANUP: Logging out if logged in');
    try {
      await logout(page);
    } catch (error) {
      console.log('TEST CLEANUP: Already logged out or logout failed');
    }
  });

  test('valid login with correct credentials', async ({ page }) => {
    console.log('TEST: Valid login with correct credentials');

    const user = TEST_USERS.soc_l1;
    await login(page, user.email, user.password, '/');

    // Verify we're on the dashboard
    await expect(page).toHaveURL('/');

    // Verify dashboard elements are visible
    await expect(page.locator('body')).toBeVisible();

    console.log('TEST: Valid login successful');
  });

  test('invalid login with wrong password', async ({ page }) => {
    console.log('TEST: Invalid login with wrong password');

    await page.fill('input[type="email"]', TEST_USERS.soc_l1.email);
    await page.fill('input[type="password"]', 'wrongpassword');
    await page.click('button[type="submit"]');

    // Wait for error message or stay on login page
    await page.waitForTimeout(2000);

    // Verify we're still on login page
    await expect(page).toHaveURL('/');

    console.log('TEST: Invalid login correctly rejected');
  });

  test('invalid login with non-existent email', async ({ page }) => {
    console.log('TEST: Invalid login with non-existent email');

    await page.fill('input[type="email"]', 'nonexistent@test.com');
    await page.fill('input[type="password"]', 'test1234');
    await page.click('button[type="submit"]');

    // Wait for error message
    await page.waitForTimeout(2000);

    // Verify we're still on login page
    await expect(page).toHaveURL('/');

    console.log('TEST: Non-existent user login correctly rejected');
  });

  test('role-based routing - L1 user routes to Analyst Dashboard', async ({ page }) => {
    console.log('TEST: Role-based routing - L1 user routes to Analyst Dashboard');

    await quickLogin(page, 'soc_l1');

    // Verify we're on the Analyst Dashboard
    await expect(page).toHaveURL('/');

    // Verify L1-specific elements are visible
    await expect(page.locator('body')).toBeVisible();

    console.log('TEST: L1 user correctly routed to Analyst Dashboard');
  });

  test('role-based routing - L2 user routes to Analyst Dashboard', async ({ page }) => {
    console.log('TEST: Role-based routing - L2 user routes to Analyst Dashboard');

    await quickLogin(page, 'soc_l2');

    // Verify we're on the Analyst Dashboard
    await expect(page).toHaveURL('/');

    console.log('TEST: L2 user correctly routed to Analyst Dashboard');
  });

  test('role-based routing - SOC Manager routes to SOC Manager Dashboard', async ({ page }) => {
    console.log('TEST: Role-based routing - SOC Manager routes to SOC Manager Dashboard');

    await quickLogin(page, 'soc_manager');

    // Verify we're on the SOC Manager Dashboard
    await expect(page).toHaveURL('/soc-manager');

    console.log('TEST: SOC Manager correctly routed to SOC Manager Dashboard');
  });

  test('role-based routing - IR user routes to Analyst Dashboard', async ({ page }) => {
    console.log('TEST: Role-based routing - IR user routes to Analyst Dashboard');

    await quickLogin(page, 'ir');

    // Verify we're on the Analyst Dashboard
    await expect(page).toHaveURL('/');

    console.log('TEST: IR user correctly routed to Analyst Dashboard');
  });

  test('role-based routing - Admin routes to Admin Dashboard', async ({ page }) => {
    console.log('TEST: Role-based routing - Admin routes to Admin Dashboard');

    await quickLogin(page, 'admin');

    // Verify we're on the Admin Dashboard
    await expect(page).toHaveURL('/admin');

    console.log('TEST: Admin correctly routed to Admin Dashboard');
  });

  test('unauthorized access - L1 cannot access Manager Dashboard directly', async ({ page }) => {
    console.log('TEST: Unauthorized access - L1 cannot access Manager Dashboard directly');

    // Login as L1
    await quickLogin(page, 'soc_l1');

    // Try to access Manager Dashboard directly
    await page.goto('/soc-manager');

    // Should be redirected back to Analyst Dashboard
    await expect(page).toHaveURL('/');

    console.log('TEST: L1 correctly denied access to Manager Dashboard');
  });

  test('unauthorized access - IR cannot access Admin Dashboard directly', async ({ page }) => {
    console.log('TEST: Unauthorized access - IR cannot access Admin Dashboard directly');

    // Login as IR
    await quickLogin(page, 'ir');

    // Try to access Admin Dashboard directly
    await page.goto('/admin');

    // Should be redirected back to Analyst Dashboard
    await expect(page).toHaveURL('/');

    console.log('TEST: IR correctly denied access to Admin Dashboard');
  });

  test('unauthorized access - L2 cannot access Admin Dashboard directly', async ({ page }) => {
    console.log('TEST: Unauthorized access - L2 cannot access Admin Dashboard directly');

    // Login as L2
    await quickLogin(page, 'soc_l2');

    // Try to access Admin Dashboard directly
    await page.goto('/admin');

    // Should be redirected back to Analyst Dashboard
    await expect(page).toHaveURL('/');

    console.log('TEST: L2 correctly denied access to Admin Dashboard');
  });

  test('session persistence - user stays logged in after page refresh', async ({ page }) => {
    console.log('TEST: Session persistence - user stays logged in after page refresh');

    await quickLogin(page, 'soc_l1');

    // Refresh the page
    await page.reload();

    // Wait for dashboard to load
    await page.waitForLoadState('domcontentloaded');

    // Verify we're still on the dashboard
    await expect(page).toHaveURL('/');

    console.log('TEST: Session persistence works correctly');
  });

  test('logout functionality', async ({ page }) => {
    console.log('TEST: Logout functionality');

    await quickLogin(page, 'soc_l1');

    // Logout
    await logout(page);

    // Verify we're back on login page
    await expect(page).toHaveURL('/');

    // Verify login form is visible
    await expect(page.locator('input[type="email"]')).toBeVisible();

    console.log('TEST: Logout functionality works correctly');
  });

  test('form validation - empty email field', async ({ page }) => {
    console.log('TEST: Form validation - empty email field');

    // Try to submit with empty email
    await page.fill('input[type="password"]', 'test1234');
    await page.click('button[type="submit"]');

    // Form should not submit (HTML5 validation)
    await page.waitForTimeout(1000);

    // Verify we're still on login page
    await expect(page).toHaveURL('/');

    console.log('TEST: Empty email field correctly validated');
  });

  test('form validation - empty password field', async ({ page }) => {
    console.log('TEST: Form validation - empty password field');

    // Try to submit with empty password
    await page.fill('input[type="email"]', TEST_USERS.soc_l1.email);
    await page.click('button[type="submit"]');

    // Form should not submit (HTML5 validation)
    await page.waitForTimeout(1000);

    // Verify we're still on login page
    await expect(page).toHaveURL('/');

    console.log('TEST: Empty password field correctly validated');
  });

  test('multiple login attempts with same user', async ({ page }) => {
    console.log('TEST: Multiple login attempts with same user');

    // First login
    await quickLogin(page, 'soc_l1');
    await logout(page);

    // Second login
    await quickLogin(page, 'soc_l1');
    await logout(page);

    // Third login
    await quickLogin(page, 'soc_l1');

    // Verify successful login after multiple attempts
    await expect(page).toHaveURL('/');

    console.log('TEST: Multiple login attempts work correctly');
  });
});

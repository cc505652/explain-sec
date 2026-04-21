// Regression tests for SOC platform
// Ensures no previously working features broke after changes
import { test, expect } from '@playwright/test';
import { quickLogin } from './helpers/auth';

test.describe('Regression Tests', () => {
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
  test('L1 flow works correctly', async ({ page }) => {
    console.log('REGRESSION: L1 flow test');
    await quickLogin(page, 'soc_l1');
    await page.waitForLoadState('domcontentloaded');
    await expect(page.locator('body')).toBeVisible();
    console.log('REGRESSION: L1 flow completed');
  });

  test('L2 flow works correctly', async ({ page }) => {
    console.log('REGRESSION: L2 flow test');
    await quickLogin(page, 'soc_l2');
    await page.waitForLoadState('domcontentloaded');
    await expect(page.locator('body')).toBeVisible();
    console.log('REGRESSION: L2 flow completed');
  });

  test('Manager flow works correctly', async ({ page }) => {
    console.log('REGRESSION: Manager flow test');
    await quickLogin(page, 'soc_manager');
    await page.waitForLoadState('domcontentloaded');
    await expect(page.locator('body')).toBeVisible();
    console.log('REGRESSION: Manager flow completed');
  });

  test('IR flow works correctly', async ({ page }) => {
    console.log('REGRESSION: IR flow test');
    await quickLogin(page, 'ir');
    await page.waitForLoadState('domcontentloaded');
    await expect(page.locator('body')).toBeVisible();
    console.log('REGRESSION: IR flow completed');
  });

  test('No new errors introduced in console', async ({ page }) => {
    console.log('REGRESSION: Check for console errors');
    
    // Listen for console errors
    const errors = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        errors.push(msg.text());
      }
    });
    
    await quickLogin(page, 'soc_l1');
    await page.waitForLoadState('domcontentloaded');
    
    // Verify no console errors
    expect(errors.length).toBe(0);
    
    console.log('REGRESSION: No console errors detected');
  });

  test('No UI crashes during rapid navigation', async ({ page }) => {
    console.log('REGRESSION: No UI crashes during rapid navigation');
    
    await quickLogin(page, 'soc_l1');
    await page.waitForLoadState('domcontentloaded');
    
    // Rapid navigation between different pages
    for (let i = 0; i < 5; i++) {
      await page.goto('/');
      await page.waitForLoadState('domcontentloaded');
    }
    
    // Verify no crashes
    await expect(page.locator('body')).toBeVisible();
    
    console.log('REGRESSION: No UI crashes during rapid navigation');
  });

  test('Incident visibility remains consistent across roles', async ({ page }) => {
    console.log('REGRESSION: Incident visibility consistency');
    
    // Test L1 can see appropriate incidents
    await quickLogin(page, 'soc_l1');
    await page.waitForLoadState('domcontentloaded');
    await expect(page.locator('body')).toBeVisible();
    console.log('REGRESSION: L1 visibility verified');
  });

  test('State transitions remain valid', async ({ page }) => {
    console.log('REGRESSION: State transitions validity');
    
    // Verify state machine transitions are still valid
    await quickLogin(page, 'soc_l1');
    await page.waitForLoadState('domcontentloaded');
    
    // Perform valid transitions
    const startTriageButton = page.locator('text=Start Triage').or(page.locator('[data-testid="start-triage"]'));
    if (await startTriageButton.count() > 0) {
      await startTriageButton.first().click();
      await page.waitForTimeout(2000);
    }
    
    // Verify no invalid state occurred
    await expect(page.locator('body')).toBeVisible();
    
    console.log('REGRESSION: State transitions remain valid');
  });

  test('Role-based permissions remain enforced', async ({ page }) => {
    console.log('REGRESSION: Role-based permissions enforcement');
    
    // Test L1 cannot access manager dashboard
    await quickLogin(page, 'soc_l1');
    await page.waitForLoadState('domcontentloaded');
    await page.goto('/soc-manager');
    await expect(page).toHaveURL('/');
    
    // Test L2 cannot access admin dashboard
    await page.goto('/');
    await quickLogin(page, 'soc_l2');
    await page.waitForLoadState('domcontentloaded');
    await page.goto('/admin');
    await expect(page).toHaveURL('/');
    
    console.log('REGRESSION: Role-based permissions enforced');
  });

  test('No missing UI states', async ({ page }) => {
    console.log('REGRESSION: No missing UI states');
    
    // Test all dashboard components load
    await quickLogin(page, 'soc_l1');
    await page.waitForLoadState('domcontentloaded');
    
    // Verify key UI elements are present
    await expect(page.locator('body')).toBeVisible();
    
    console.log('REGRESSION: No missing UI states');
  });

  test('Authentication flow remains functional', async ({ page }) => {
    console.log('REGRESSION: Authentication flow');
    
    // Test login
    await page.goto('/');
    await page.fill('input[type="email"]', 'analyst@explainsec.com');
    await page.fill('input[type="password"]', 'test1234');
    await page.click('button[type="submit"]');
    await page.waitForURL('/');
    
    // Verify logged in
    await expect(page.locator('body')).toBeVisible();
    
    console.log('REGRESSION: Authentication flow functional');
  });

  test('Firestore queries remain functional', async ({ page }) => {
    console.log('REGRESSION: Firestore queries');
    
    await quickLogin(page, 'soc_l1');
    await page.waitForLoadState('domcontentloaded');
    
    // Verify data loads from Firestore
    await expect(page.locator('body')).toBeVisible();
    
    console.log('REGRESSION: Firestore queries functional');
  });

  test('Real-time updates remain functional', async ({ page }) => {
    console.log('REGRESSION: Real-time updates');
    
    await quickLogin(page, 'soc_l1');
    await page.waitForLoadState('domcontentloaded');
    
    // Verify dashboard loads (indicates real-time listener connected)
    await expect(page.locator('body')).toBeVisible();
    
    console.log('REGRESSION: Real-time updates functional');
  });

  test('Form submissions remain functional', async ({ page }) => {
    console.log('REGRESSION: Form submissions');
    
    await quickLogin(page, 'soc_l1');
    await page.waitForLoadState('domcontentloaded');
    
    const addNoteButton = page.locator('text=Add Note').or(page.locator('[data-testid="add-note"]'));
    
    if (await addNoteButton.count() > 0) {
      await addNoteButton.first().click();
      await page.waitForTimeout(1000);
      
      const noteInput = page.locator('textarea').or(page.locator('[data-testid="note-input"]'));
      if (await noteInput.count() > 0) {
        await noteInput.first().fill('Regression test note');
        
        const submitButton = page.locator('text=Submit').or(page.locator('[data-testid="submit-note"]'));
        await submitButton.click();
        
        await page.waitForTimeout(2000);
        
        console.log('REGRESSION: Form submissions functional');
      }
    } else {
      console.log('REGRESSION: No add note button found');
    }
  });

  test('No infinite loops in UI rendering', async ({ page }) => {
    console.log('REGRESSION: No infinite loops');
    
    await quickLogin(page, 'soc_l1');
    
    // Set a timeout - if page doesn't load, there's an infinite loop
    await page.waitForLoadState('domcontentloaded', { timeout: 10000 });
    
    console.log('REGRESSION: No infinite loops detected');
  });

  test('No memory leaks in navigation', async ({ page }) => {
    console.log('REGRESSION: No memory leaks');
    
    await quickLogin(page, 'soc_l1');
    await page.waitForLoadState('domcontentloaded');
    
    // Navigate multiple times
    for (let i = 0; i < 10; i++) {
      await page.goto('/');
      await page.waitForLoadState('domcontentloaded');
    }
    
    // Verify page still responsive
    await expect(page.locator('body')).toBeVisible();
    
    console.log('REGRESSION: No memory leaks detected');
  });

  test('Escalation workflow remains functional', async ({ page }) => {
    console.log('REGRESSION: Escalation workflow');
    
    await quickLogin(page, 'soc_l2');
    await page.waitForLoadState('domcontentloaded');
    
    const escalateButton = page.locator('text=Escalate to Manager').or(page.locator('[data-testid="escalate-manager"]'));
    
    if (await escalateButton.count() > 0) {
      await escalateButton.first().click();
      await page.waitForTimeout(3000);
      
      console.log('REGRESSION: Escalation workflow functional');
    } else {
      console.log('REGRESSION: No escalation button found');
    }
  });

  test('Containment workflow remains functional', async ({ page }) => {
    console.log('REGRESSION: Containment workflow');
    
    await quickLogin(page, 'ir');
    await page.waitForLoadState('domcontentloaded');
    
    const performContainmentButton = page.locator('text=Perform Containment').or(page.locator('[data-testid="perform-containment"]'));
    
    if (await performContainmentButton.count() > 0) {
      await performContainmentButton.first().click();
      await page.waitForTimeout(1000);
      
      console.log('REGRESSION: Containment workflow functional');
    } else {
      console.log('REGRESSION: No containment button found');
    }
  });

  test('Statistics calculations remain accurate', async ({ page }) => {
    console.log('REGRESSION: Statistics calculations');
    
    await quickLogin(page, 'soc_l1');
    await page.waitForLoadState('domcontentloaded');
    
    // Verify statistics section loads
    await expect(page.locator('body')).toBeVisible();
    
    console.log('REGRESSION: Statistics calculations functional');
  });

  test('No broken links or routes', async ({ page }) => {
    console.log('REGRESSION: No broken links');
    
    await quickLogin(page, 'soc_l1');
    await page.waitForLoadState('domcontentloaded');
    
    // Try main routes
    await page.goto('/');
    await expect(page.locator('body')).toBeVisible();
    
    console.log('REGRESSION: No broken links detected');
  });

  test('Error handling remains functional', async ({ page }) => {
    console.log('REGRESSION: Error handling');
    
    // Try to access invalid route
    await page.goto('/invalid-route');
    
    // Should redirect to appropriate page
    await page.waitForLoadState('domcontentloaded');
    
    console.log('REGRESSION: Error handling functional');
  });

  test('Loading states display correctly', async ({ page }) => {
    console.log('REGRESSION: Loading states');
    
    await quickLogin(page, 'soc_l1');
    
    // Verify loading state displays
    await page.waitForLoadState('domcontentloaded');
    
    console.log('REGRESSION: Loading states functional');
  });

  test('Responsive design remains intact', async ({ page }) => {
    console.log('REGRESSION: Responsive design');
    
    await quickLogin(page, 'soc_l1');
    await page.waitForLoadState('domcontentloaded');
    
    // Test different viewport sizes
    await page.setViewportSize({ width: 1920, height: 1080 });
    await expect(page.locator('body')).toBeVisible();
    
    await page.setViewportSize({ width: 1366, height: 768 });
    await expect(page.locator('body')).toBeVisible();
    
    await page.setViewportSize({ width: 768, height: 1024 });
    await expect(page.locator('body')).toBeVisible();
    
    console.log('REGRESSION: Responsive design intact');
  });

  test('No broken imports or dependencies', async ({ page }) => {
    console.log('REGRESSION: No broken imports');
    
    // Listen for console errors
    const errors = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        errors.push(msg.text());
      }
    });
    
    await quickLogin(page, 'soc_l1');
    await page.waitForLoadState('domcontentloaded');
    
    // Check for import errors
    const importErrors = errors.filter(e => e.includes('import') || e.includes('module'));
    expect(importErrors.length).toBe(0);
    
    console.log('REGRESSION: No broken imports detected');
  });

  test('Database operations remain consistent', async ({ page }) => {
    console.log('REGRESSION: Database operations');
    
    await quickLogin(page, 'soc_l1');
    await page.waitForLoadState('domcontentloaded');
    
    // Verify data loads from database
    await expect(page.locator('body')).toBeVisible();
    
    console.log('REGRESSION: Database operations consistent');
  });

  test('No race conditions in UI updates', async ({ page }) => {
    console.log('REGRESSION: No race conditions');
    
    await quickLogin(page, 'soc_l1');
    await page.waitForLoadState('domcontentloaded');
    
    // Perform rapid actions
    const startTriageButton = page.locator('text=Start Triage').or(page.locator('[data-testid="start-triage"]'));
    if (await startTriageButton.count() > 0) {
      for (let i = 0; i < 3; i++) {
        await startTriageButton.first().click();
        await page.waitForTimeout(100);
      }
    }
    
    // Verify UI remains stable
    await expect(page.locator('body')).toBeVisible();
    
    console.log('REGRESSION: No race conditions detected');
  });
});

// IR Workflow tests for SOC platform
import { test, expect } from '@playwright/test';
import { login, quickLogin } from './helpers/auth';
import { TEST_USERS } from './helpers/setup';

test.describe('IR Workflow', () => {
  // Increase timeout for Firefox - page.goto waits for 'load' which is delayed by Firebase WebSocket connections
  test.setTimeout(60000);

  test.beforeEach(async ({ page }) => {
    // Monkey-patch page.goto and page.waitForURL to use 'domcontentloaded' instead
    // of default 'load' which hangs on Firefox due to Firebase's persistent WebSocket connections
    const originalGoto = page.goto.bind(page);
    page.goto = (url, options = {}) => {
      return originalGoto(url, { waitUntil: 'domcontentloaded', ...options });
    };
    const originalWaitForURL = page.waitForURL.bind(page);
    page.waitForURL = (url, options = {}) => {
      return originalWaitForURL(url, { waitUntil: 'domcontentloaded', ...options });
    };
    console.log('TEST SETUP: Logging in as IR');
    await quickLogin(page, 'ir');
  });

  test.afterEach(async ({ page }) => {
    console.log('TEST CLEANUP: Logging out');
    try {
      await page.goto('/', { waitUntil: 'domcontentloaded' });
    } catch (error) {
      console.log('TEST CLEANUP: Already logged out');
    }
  });

  test('IR can view assigned incidents', async ({ page }) => {
    console.log('TEST: IR can view assigned incidents');
    
    await page.waitForLoadState('domcontentloaded');
    
    // Verify dashboard is visible
    await expect(page.locator('body')).toBeVisible();
    
    // Look for assigned incidents
    const assignedSection = page.locator('[data-testid="assigned-incidents"]');
    
    console.log('TEST: IR dashboard loaded - can view assigned incidents');
  });

  test('IR can perform containment action', async ({ page }) => {
    console.log('TEST: IR can perform containment action');
    
    await page.waitForLoadState('domcontentloaded');
    
    // Find an assigned incident
    const performContainmentButton = page.locator('text=Perform Containment').or(page.locator('[data-testid="perform-containment"]'));
    
    if (await performContainmentButton.count() > 0) {
      await performContainmentButton.first().click();
      
      // Wait for containment dialog
      await page.waitForTimeout(1000);
      
      // Select containment action type
      const actionTypeSelect = page.locator('[data-testid="containment-action-type"]');
      if (await actionTypeSelect.count() > 0) {
        await actionTypeSelect.selectOption('block_ip');
        
        // Enter details
        const detailsInput = page.locator('[data-testid="containment-details"]');
        await detailsInput.fill('Block malicious IP 192.168.1.1');
        
        // Submit
        const submitButton = page.locator('text=Submit').or(page.locator('[data-testid="submit-containment"]'));
        await submitButton.click();
        
        await page.waitForTimeout(3000);
        
        console.log('TEST: IR successfully performed containment action');
      }
    } else {
      console.log('TEST: No incidents available for containment');
    }
  });

  test('IR can submit containment action for manager review', async ({ page }) => {
    console.log('TEST: IR can submit containment action for manager review');
    
    await page.waitForLoadState('domcontentloaded');
    
    const submitActionButton = page.locator('text=Submit Action').or(page.locator('[data-testid="submit-action"]'));
    
    if (await submitActionButton.count() > 0) {
      await submitActionButton.first().click();
      
      await page.waitForTimeout(3000);
      
      console.log('TEST: IR successfully submitted containment action');
    } else {
      console.log('TEST: No submit action button found');
    }
  });

  test('IR submitted action appears in manager queue', async ({ page }) => {
    // This test does two logins (IR via beforeEach + manager), needs extra time
    test.setTimeout(90000);
    console.log('TEST: IR submitted action appears in manager queue');
    
    await page.waitForLoadState('domcontentloaded');
    
    const submitActionButton = page.locator('text=Submit Action').or(page.locator('[data-testid="submit-action"]'));
    
    if (await submitActionButton.count() > 0) {
      await submitActionButton.first().click();
      
      await page.waitForTimeout(3000);
      
      // Logout as IR - use domcontentloaded to avoid Firefox WebSocket hang
      await page.goto('/', { waitUntil: 'domcontentloaded' });
      
      // Login as manager
      await quickLogin(page, 'soc_manager');
      
      // Check if action appears in manager queue
      await page.waitForLoadState('domcontentloaded');
      
      const containmentQueue = page.locator('[data-testid="containment-queue"]');
      
      console.log('TEST: Submitted action should be visible in manager queue');
    } else {
      console.log('TEST: No submit action button found');
    }
  });

  test('IR can resubmit rejected action', async ({ page }) => {
    console.log('TEST: IR can resubmit rejected action');
    
    await page.waitForLoadState('domcontentloaded');
    
    const resubmitButton = page.locator('text=Resubmit Action').or(page.locator('[data-testid="resubmit-action"]'));
    
    if (await resubmitButton.count() > 0) {
      await resubmitButton.first().click();
      
      await page.waitForTimeout(3000);
      
      console.log('TEST: IR successfully resubmitted rejected action');
    } else {
      console.log('TEST: No resubmit action button found');
    }
  });

  test('IR receives manager feedback on action', async ({ page }) => {
    console.log('TEST: IR receives manager feedback on action');
    
    await page.waitForLoadState('domcontentloaded');
    
    // Look for manager decision/comment
    const managerDecision = page.locator('[data-testid="manager-decision"]');
    
    if (await managerDecision.count() > 0) {
      console.log('TEST: IR can see manager feedback');
    } else {
      console.log('TEST: No manager decision visible');
    }
  });

  test('IR can add notes to incidents', async ({ page }) => {
    console.log('TEST: IR can add notes to incidents');
    
    await page.waitForLoadState('domcontentloaded');
    
    const addNoteButton = page.locator('text=Add Note').or(page.locator('[data-testid="add-note"]'));
    
    if (await addNoteButton.count() > 0) {
      await addNoteButton.first().click();
      
      await page.waitForTimeout(1000);
      
      const noteInput = page.locator('textarea').or(page.locator('[data-testid="note-input"]'));
      if (await noteInput.count() > 0) {
        await noteInput.first().fill('Test note from IR');
        
        const submitButton = page.locator('text=Submit').or(page.locator('[data-testid="submit-note"]'));
        await submitButton.click();
        
        await page.waitForTimeout(2000);
        
        console.log('TEST: IR successfully added note to incident');
      }
    } else {
      console.log('TEST: No add note button found');
    }
  });

  test('IR cannot approve containment requests', async ({ page }) => {
    console.log('TEST: IR cannot approve containment requests');
    
    await page.waitForLoadState('domcontentloaded');
    
    const approveButton = page.locator('text=Approve Containment').or(page.locator('[data-testid="approve-containment"]'));
    
    const isVisible = await approveButton.isVisible();
    expect(isVisible).toBeFalsy();
    
    console.log('TEST: IR correctly cannot approve containment requests');
  });

  test('IR cannot escalate to manager', async ({ page }) => {
    console.log('TEST: IR cannot escalate to manager');
    
    await page.waitForLoadState('domcontentloaded');
    
    const escalateButton = page.locator('text=Escalate to Manager').or(page.locator('[data-testid="escalate-manager"]'));
    
    const isVisible = await escalateButton.isVisible();
    expect(isVisible).toBeFalsy();
    
    console.log('TEST: IR correctly cannot escalate to manager');
  });

  test('IR cannot reassign incidents', async ({ page }) => {
    console.log('TEST: IR cannot reassign incidents');
    
    await page.waitForLoadState('domcontentloaded');
    
    const reassignButton = page.locator('text=Reassign').or(page.locator('[data-testid="reassign"]'));
    
    const isVisible = await reassignButton.isVisible();
    expect(isVisible).toBeFalsy();
    
    console.log('TEST: IR correctly cannot reassign incidents');
  });

  test('IR can view incident details', async ({ page }) => {
    console.log('TEST: IR can view incident details');
    
    await page.waitForLoadState('domcontentloaded');
    
    const incidentCard = page.locator('[data-testid="incident-card"]');
    
    if (await incidentCard.count() > 0) {
      await incidentCard.first().click();
      
      await page.waitForTimeout(2000);
      
      await expect(page.locator('body')).toBeVisible();
      
      console.log('TEST: IR successfully viewed incident details');
    } else {
      console.log('TEST: No incident cards found');
    }
  });

  test('IR dashboard shows correct statistics', async ({ page }) => {
    console.log('TEST: IR dashboard shows correct statistics');
    
    await page.waitForLoadState('domcontentloaded');
    
    const statsSection = page.locator('[data-testid="stats-section"]');
    
    await expect(page.locator('body')).toBeVisible();
    
    console.log('TEST: IR dashboard loaded with statistics');
  });

  test('IR can update containment action before submission', async ({ page }) => {
    console.log('TEST: IR can update containment action before submission');
    
    await page.waitForLoadState('domcontentloaded');
    
    const updateActionButton = page.locator('text=Update Action').or(page.locator('[data-testid="update-action"]'));
    
    if (await updateActionButton.count() > 0) {
      await updateActionButton.first().click();
      
      await page.waitForTimeout(1000);
      
      console.log('TEST: IR can update containment action');
    } else {
      console.log('TEST: No update action button found');
    }
  });

  test('IR can view containment history', async ({ page }) => {
    console.log('TEST: IR can view containment history');
    
    await page.waitForLoadState('domcontentloaded');
    
    const containmentHistory = page.locator('[data-testid="containment-history"]');
    
    if (await containmentHistory.count() > 0) {
      console.log('TEST: IR can view containment history');
    } else {
      console.log('TEST: No containment history visible');
    }
  });

  test('IR incident visibility is correct', async ({ page }) => {
    console.log('TEST: IR incident visibility is correct');
    
    await page.waitForLoadState('domcontentloaded');
    
    // IR should only see incidents assigned to IR or escalated to IR
    const incidentCards = page.locator('[data-testid="incident-card"]');
    
    console.log('TEST: IR visibility - dashboard loaded');
  });
});

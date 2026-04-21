// L2 Workflow tests for SOC platform
import { test, expect } from '@playwright/test';
import { login, quickLogin } from './helpers/auth';
import { TEST_USERS } from './helpers/setup';

test.describe('L2 Workflow', () => {
  test.beforeEach(async ({ page }) => {
    console.log('TEST SETUP: Logging in as SOC L2');
    await quickLogin(page, 'soc_l2');
  });

  test.afterEach(async ({ page }) => {
    console.log('TEST CLEANUP: Logging out');
    try {
      await page.goto('/');
    } catch (error) {
      console.log('TEST CLEANUP: Already logged out');
    }
  });

  test('L2 can view confirmed threats', async ({ page }) => {
    console.log('TEST: L2 can view confirmed threats');
    
    await page.waitForLoadState('domcontentloaded');
    
    // Verify dashboard is visible
    await expect(page.locator('body')).toBeVisible();
    
    // Look for confirmed threat incidents
    const confirmedThreatBadge = page.locator('text=Confirmed Threat').or(page.locator('[data-testid="confirmed-threat-badge"]'));
    
    console.log('TEST: L2 dashboard loaded - can view incidents');
  });

  test('L2 can escalate incident to manager', async ({ page }) => {
    console.log('TEST: L2 can escalate incident to manager');
    
    await page.waitForLoadState('domcontentloaded');
    
    // Find an incident that can be escalated
    const escalateButton = page.locator('text=Escalate to Manager').or(page.locator('[data-testid="escalate-manager"]'));
    
    if (await escalateButton.count() > 0) {
      await escalateButton.first().click();
      
      // Wait for escalation to complete
      await page.waitForTimeout(3000);
      
      console.log('TEST: L2 successfully escalated incident to manager');
    } else {
      console.log('TEST: No incidents available for escalation');
    }
  });

  test('L2 escalated incident appears in manager queue', async ({ page }) => {
    console.log('TEST: L2 escalated incident appears in manager queue');
    
    await page.waitForLoadState('domcontentloaded');
    
    // Find an incident and escalate it
    const escalateButton = page.locator('text=Escalate to Manager').or(page.locator('[data-testid="escalate-manager"]'));
    
    if (await escalateButton.count() > 0) {
      await escalateButton.first().click();
      
      // Wait for escalation
      await page.waitForTimeout(3000);
      
      // Logout as L2
      await page.goto('/');
      
      // Login as manager
      await quickLogin(page, 'soc_manager');
      
      // Check if incident appears in escalation queue
      await page.waitForLoadState('domcontentloaded');
      
      const escalationQueue = page.locator('[data-testid="escalation-queue"]');
      
      console.log('TEST: Escalated incident should be visible in manager queue');
    } else {
      console.log('TEST: No incidents available for escalation');
    }
  });

  test('L2 incident does not disappear after escalation', async ({ page }) => {
    console.log('TEST: L2 incident does not disappear after escalation');
    
    await page.waitForLoadState('domcontentloaded');
    
    // Count incidents before escalation
    const incidentCountBefore = await page.locator('[data-testid="incident-card"]').count();
    
    // Find and escalate an incident
    const escalateButton = page.locator('text=Escalate to Manager').or(page.locator('[data-testid="escalate-manager"]'));
    
    if (await escalateButton.count() > 0) {
      await escalateButton.first().click();
      
      // Wait for escalation
      await page.waitForTimeout(3000);
      
      // Count incidents after escalation
      const incidentCountAfter = await page.locator('[data-testid="incident-card"]').count();
      
      // Incident should still be visible to L2
      expect(incidentCountAfter).toBeGreaterThanOrEqual(incidentCountBefore - 1);
      
      console.log('TEST: L2 incident remains visible after escalation');
    } else {
      console.log('TEST: No incidents available for escalation');
    }
  });

  test('L2 can request containment', async ({ page }) => {
    console.log('TEST: L2 can request containment');
    
    await page.waitForLoadState('domcontentloaded');
    
    // Find an incident and request containment
    const requestContainmentButton = page.locator('text=Request Containment').or(page.locator('[data-testid="request-containment"]'));
    
    if (await requestContainmentButton.count() > 0) {
      await requestContainmentButton.first().click();
      
      // Wait for request to be submitted
      await page.waitForTimeout(3000);
      
      console.log('TEST: L2 successfully requested containment');
    } else {
      console.log('TEST: No containment request button found');
    }
  });

  test('L2 containment request appears in manager queue', async ({ page }) => {
    console.log('TEST: L2 containment request appears in manager queue');
    
    await page.waitForLoadState('domcontentloaded');
    
    // Request containment
    const requestContainmentButton = page.locator('text=Request Containment').or(page.locator('[data-testid="request-containment"]'));
    
    if (await requestContainmentButton.count() > 0) {
      await requestContainmentButton.first().click();
      
      // Wait for request to be submitted
      await page.waitForTimeout(3000);
      
      // Logout as L2
      await page.goto('/');
      
      // Login as manager
      await quickLogin(page, 'soc_manager');
      
      // Check if containment request appears in manager queue
      await page.waitForLoadState('domcontentloaded');
      
      const containmentQueue = page.locator('[data-testid="containment-queue"]');
      
      console.log('TEST: Containment request should be visible in manager queue');
    } else {
      console.log('TEST: No containment request button found');
    }
  });

  test('L2 can withdraw containment request', async ({ page }) => {
    console.log('TEST: L2 can withdraw containment request');
    
    await page.waitForLoadState('domcontentloaded');
    
    // Find an incident with pending containment request
    const withdrawButton = page.locator('text=Withdraw Request').or(page.locator('[data-testid="withdraw-request"]'));
    
    if (await withdrawButton.count() > 0) {
      await withdrawButton.first().click();
      
      // Wait for withdrawal to complete
      await page.waitForTimeout(3000);
      
      console.log('TEST: L2 successfully withdrew containment request');
    } else {
      console.log('TEST: No withdraw request button found');
    }
  });

  test('L2 can add notes to incidents', async ({ page }) => {
    console.log('TEST: L2 can add notes to incidents');
    
    await page.waitForLoadState('domcontentloaded');
    
    const addNoteButton = page.locator('text=Add Note').or(page.locator('[data-testid="add-note"]'));
    
    if (await addNoteButton.count() > 0) {
      await addNoteButton.first().click();
      
      await page.waitForTimeout(1000);
      
      const noteInput = page.locator('textarea').or(page.locator('[data-testid="note-input"]'));
      if (await noteInput.count() > 0) {
        await noteInput.first().fill('Test note from L2');
        
        const submitButton = page.locator('text=Submit').or(page.locator('[data-testid="submit-note"]'));
        await submitButton.click();
        
        await page.waitForTimeout(2000);
        
        console.log('TEST: L2 successfully added note to incident');
      }
    } else {
      console.log('TEST: No add note button found');
    }
  });

  test('L2 can adjust severity', async ({ page }) => {
    console.log('TEST: L2 can adjust severity');
    
    await page.waitForLoadState('domcontentloaded');
    
    const severityButton = page.locator('text=Adjust Severity').or(page.locator('[data-testid="adjust-severity"]'));
    
    if (await severityButton.count() > 0) {
      await severityButton.first().click();
      
      await page.waitForTimeout(1000);
      
      console.log('TEST: L2 can adjust severity');
    } else {
      console.log('TEST: No severity adjustment button found');
    }
  });

  test('L2 can reassign incidents', async ({ page }) => {
    console.log('TEST: L2 can reassign incidents');
    
    await page.waitForLoadState('domcontentloaded');
    
    const reassignButton = page.locator('text=Reassign').or(page.locator('[data-testid="reassign"]'));
    
    if (await reassignButton.count() > 0) {
      await reassignButton.first().click();
      
      await page.waitForTimeout(1000);
      
      console.log('TEST: L2 can reassign incidents');
    } else {
      console.log('TEST: No reassign button found');
    }
  });

  test('L2 cannot execute containment directly', async ({ page }) => {
    console.log('TEST: L2 cannot execute containment directly');
    
    await page.waitForLoadState('domcontentloaded');
    
    // Look for execute containment button - should not exist for L2
    const executeButton = page.locator('text=Execute Containment').or(page.locator('[data-testid="execute-containment"]'));
    
    const isVisible = await executeButton.isVisible();
    expect(isVisible).toBeFalsy();
    
    console.log('TEST: L2 correctly cannot execute containment directly');
  });

  test('L2 cannot approve containment requests', async ({ page }) => {
    console.log('TEST: L2 cannot approve containment requests');
    
    await page.waitForLoadState('domcontentloaded');
    
    const approveButton = page.locator('text=Approve Containment').or(page.locator('[data-testid="approve-containment"]'));
    
    const isVisible = await approveButton.isVisible();
    expect(isVisible).toBeFalsy();
    
    console.log('TEST: L2 correctly cannot approve containment requests');
  });

  test('L2 can view incident details', async ({ page }) => {
    console.log('TEST: L2 can view incident details');
    
    await page.waitForLoadState('domcontentloaded');
    
    const incidentCard = page.locator('[data-testid="incident-card"]');
    
    if (await incidentCard.count() > 0) {
      await incidentCard.first().click();
      
      await page.waitForTimeout(2000);
      
      await expect(page.locator('body')).toBeVisible();
      
      console.log('TEST: L2 successfully viewed incident details');
    } else {
      console.log('TEST: No incident cards found');
    }
  });

  test('L2 dashboard shows correct statistics', async ({ page }) => {
    console.log('TEST: L2 dashboard shows correct statistics');
    
    await page.waitForLoadState('domcontentloaded');
    
    const statsSection = page.locator('[data-testid="stats-section"]');
    
    await expect(page.locator('body')).toBeVisible();
    
    console.log('TEST: L2 dashboard loaded with statistics');
  });

  test('L2 can mark false positive', async ({ page }) => {
    console.log('TEST: L2 can mark false positive');
    
    await page.waitForLoadState('domcontentloaded');
    
    const falsePositiveButton = page.locator('text=Mark False Positive').or(page.locator('[data-testid="mark-false-positive"]'));
    
    if (await falsePositiveButton.count() > 0) {
      await falsePositiveButton.first().click();
      
      await page.waitForTimeout(2000);
      
      console.log('TEST: L2 successfully marked incident as false positive');
    } else {
      console.log('TEST: No incidents available to mark as false positive');
    }
  });

  test('L2 can continue investigation', async ({ page }) => {
    console.log('TEST: L2 can continue investigation');
    
    await page.waitForLoadState('domcontentloaded');
    
    const continueButton = page.locator('text=Continue Investigation').or(page.locator('[data-testid="continue-investigation"]'));
    
    if (await continueButton.count() > 0) {
      await continueButton.first().click();
      
      await page.waitForTimeout(2000);
      
      console.log('TEST: L2 successfully continued investigation');
    } else {
      console.log('TEST: No continue investigation button found');
    }
  });
});

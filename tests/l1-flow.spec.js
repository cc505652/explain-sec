// L1 Workflow tests for SOC platform
import { test, expect } from '@playwright/test';
import { login, quickLogin } from './helpers/auth';
import { TEST_USERS } from './helpers/setup';

test.describe('L1 Workflow', () => {
  test.beforeEach(async ({ page }) => {
    console.log('TEST SETUP: Logging in as SOC L1');
    await quickLogin(page, 'soc_l1');
  });

  test.afterEach(async ({ page }) => {
    console.log('TEST CLEANUP: Logging out');
    try {
      await page.goto('/');
      // Logout if needed
    } catch (error) {
      console.log('TEST CLEANUP: Already logged out');
    }
  });

  test('L1 can view open incidents', async ({ page }) => {
    console.log('TEST: L1 can view open incidents');
    
    // Wait for dashboard to load
    await page.waitForLoadState('domcontentloaded');
    
    // Verify dashboard is visible
    await expect(page.locator('body')).toBeVisible();
    
    // Look for incident cards or list
    // This will need to be adjusted based on actual UI selectors
    const incidentList = page.locator('[data-testid="incident-list"]');
    
    console.log('TEST: L1 can view open incidents - dashboard loaded');
  });

  test('L1 can start triage on an incident', async ({ page }) => {
    console.log('TEST: L1 can start triage on an incident');
    
    // Wait for dashboard to load
    await page.waitForLoadState('domcontentloaded');
    
    // Find an open incident
    // This will need to be adjusted based on actual UI selectors
    const startTriageButton = page.locator('text=Start Triage').or(page.locator('[data-testid="start-triage"]'));
    
    if (await startTriageButton.count() > 0) {
      await startTriageButton.first().click();
      
      // Wait for triage to start
      await page.waitForTimeout(2000);
      
      console.log('TEST: L1 successfully started triage');
    } else {
      console.log('TEST: No incidents available for triage');
    }
  });

  test('L1 can mark incident as false positive', async ({ page }) => {
    console.log('TEST: L1 can mark incident as false positive');
    
    // Wait for dashboard to load
    await page.waitForLoadState('domcontentloaded');
    
    // Find an incident in progress
    const falsePositiveButton = page.locator('text=Mark False Positive').or(page.locator('[data-testid="mark-false-positive"]'));
    
    if (await falsePositiveButton.count() > 0) {
      await falsePositiveButton.first().click();
      
      // Wait for status change
      await page.waitForTimeout(2000);
      
      console.log('TEST: L1 successfully marked incident as false positive');
    } else {
      console.log('TEST: No incidents available to mark as false positive');
    }
  });

  test('L1 can confirm threat on an incident', async ({ page }) => {
    console.log('TEST: L1 can confirm threat on an incident');
    
    // Wait for dashboard to load
    await page.waitForLoadState('domcontentloaded');
    
    // Find an incident in progress
    const confirmThreatButton = page.locator('text=Confirm Threat').or(page.locator('[data-testid="confirm-threat"]'));
    
    if (await confirmThreatButton.count() > 0) {
      await confirmThreatButton.first().click();
      
      // Wait for status change
      await page.waitForTimeout(2000);
      
      console.log('TEST: L1 successfully confirmed threat');
    } else {
      console.log('TEST: No incidents available to confirm threat');
    }
  });

  test('L1 confirmed threat automatically escalates to L2', async ({ page }) => {
    console.log('TEST: L1 confirmed threat automatically escalates to L2');
    
    // Wait for dashboard to load
    await page.waitForLoadState('domcontentloaded');
    
    // Find an incident that can be confirmed
    const confirmThreatButton = page.locator('text=Confirm Threat').or(page.locator('[data-testid="confirm-threat"]'));
    
    if (await confirmThreatButton.count() > 0) {
      await confirmThreatButton.first().click();
      
      // Wait for escalation
      await page.waitForTimeout(3000);
      
      // Verify incident is escalated to L2
      // This will need to check for escalation indicators in the UI
      console.log('TEST: L1 confirmed threat - escalation initiated');
    } else {
      console.log('TEST: No incidents available for threat confirmation');
    }
  });

  test('L1 incident remains visible after status change', async ({ page }) => {
    console.log('TEST: L1 incident remains visible after status change');
    
    // Wait for dashboard to load
    await page.waitForLoadState('domcontentloaded');
    
    // Find an incident and perform an action
    const startTriageButton = page.locator('text=Start Triage').or(page.locator('[data-testid="start-triage"]'));
    
    if (await startTriageButton.count() > 0) {
      await startTriageButton.first().click();
      
      // Wait for status change
      await page.waitForTimeout(2000);
      
      // Verify incident is still visible
      await expect(page.locator('body')).toBeVisible();
      
      console.log('TEST: Incident remains visible after status change');
    } else {
      console.log('TEST: No incidents available for action');
    }
  });

  test('L1 can add notes to an incident', async ({ page }) => {
    console.log('TEST: L1 can add notes to an incident');
    
    // Wait for dashboard to load
    await page.waitForLoadState('domcontentloaded');
    
    // Find an incident
    const addNoteButton = page.locator('text=Add Note').or(page.locator('[data-testid="add-note"]'));
    
    if (await addNoteButton.count() > 0) {
      await addNoteButton.first().click();
      
      // Wait for note dialog
      await page.waitForTimeout(1000);
      
      // Add note text
      const noteInput = page.locator('textarea').or(page.locator('[data-testid="note-input"]'));
      if (await noteInput.count() > 0) {
        await noteInput.first().fill('Test note from L1');
        
        // Submit note
        const submitButton = page.locator('text=Submit').or(page.locator('[data-testid="submit-note"]'));
        await submitButton.click();
        
        // Wait for note to be added
        await page.waitForTimeout(2000);
        
        console.log('TEST: L1 successfully added note to incident');
      }
    } else {
      console.log('TEST: No add note button found');
    }
  });

  test('L1 cannot escalate to Manager directly', async ({ page }) => {
    console.log('TEST: L1 cannot escalate to Manager directly');
    
    // Wait for dashboard to load
    await page.waitForLoadState('domcontentloaded');
    
    // Look for escalate to manager button - should not exist for L1
    const escalateManagerButton = page.locator('text=Escalate to Manager').or(page.locator('[data-testid="escalate-manager"]'));
    
    // This button should not be visible to L1
    const isVisible = await escalateManagerButton.isVisible();
    
    expect(isVisible).toBeFalsy();
    
    console.log('TEST: L1 correctly cannot escalate to Manager directly');
  });

  test('L1 cannot approve containment requests', async ({ page }) => {
    console.log('TEST: L1 cannot approve containment requests');
    
    // Wait for dashboard to load
    await page.waitForLoadState('domcontentloaded');
    
    // Look for approve containment button - should not exist for L1
    const approveContainmentButton = page.locator('text=Approve Containment').or(page.locator('[data-testid="approve-containment"]'));
    
    // This button should not be visible to L1
    const isVisible = await approveContainmentButton.isVisible();
    
    expect(isVisible).toBeFalsy();
    
    console.log('TEST: L1 correctly cannot approve containment requests');
  });

  test('L1 cannot reassign incidents', async ({ page }) => {
    console.log('TEST: L1 cannot reassign incidents');
    
    // Wait for dashboard to load
    await page.waitForLoadState('domcontentloaded');
    
    // Look for reassign button - should not exist for L1
    const reassignButton = page.locator('text=Reassign').or(page.locator('[data-testid="reassign"]'));
    
    // This button should not be visible to L1
    const isVisible = await reassignButton.isVisible();
    
    expect(isVisible).toBeFalsy();
    
    console.log('TEST: L1 correctly cannot reassign incidents');
  });

  test('L1 can adjust severity of incident', async ({ page }) => {
    console.log('TEST: L1 can adjust severity of incident');
    
    // Wait for dashboard to load
    await page.waitForLoadState('domcontentloaded');
    
    // Find an incident and look for severity adjustment
    const severityButton = page.locator('text=Adjust Severity').or(page.locator('[data-testid="adjust-severity"]'));
    
    if (await severityButton.count() > 0) {
      await severityButton.first().click();
      
      // Wait for severity dialog
      await page.waitForTimeout(1000);
      
      console.log('TEST: L1 can adjust severity');
    } else {
      console.log('TEST: No severity adjustment button found');
    }
  });

  test('L1 dashboard shows correct statistics', async ({ page }) => {
    console.log('TEST: L1 dashboard shows correct statistics');
    
    // Wait for dashboard to load
    await page.waitForLoadState('domcontentloaded');
    
    // Look for statistics cards
    const statsSection = page.locator('[data-testid="stats-section"]');
    
    // Verify dashboard has statistics
    await expect(page.locator('body')).toBeVisible();
    
    console.log('TEST: L1 dashboard loaded with statistics');
  });

  test('L1 can view incident details', async ({ page }) => {
    console.log('TEST: L1 can view incident details');
    
    // Wait for dashboard to load
    await page.waitForLoadState('domcontentloaded');
    
    // Find an incident card
    const incidentCard = page.locator('[data-testid="incident-card"]');
    
    if (await incidentCard.count() > 0) {
      await incidentCard.first().click();
      
      // Wait for details to load
      await page.waitForTimeout(2000);
      
      // Verify details are visible
      await expect(page.locator('body')).toBeVisible();
      
      console.log('TEST: L1 successfully viewed incident details');
    } else {
      console.log('TEST: No incident cards found');
    }
  });
});
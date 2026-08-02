import { test, expect } from '@playwright/test';
import { createSecurityEvent } from '../../../src/telemetry/types/securityEvent.js';

test.describe('Standardizer & SecurityEvent Schema Suite', () => {
  test('1. Attaches unique event ID if missing', () => {
    const evt = createSecurityEvent({ description: "Test missing ID" });
    expect(evt.eventId).toBeDefined();
    expect(evt.eventId).toMatch(/^evt_/);
  });

  test('2. Formats timestamp to valid date', () => {
    const evt = createSecurityEvent({ timestamp: Date.now() });
    expect(evt.timestamp).toBeDefined();
    expect(new Date(evt.timestamp).getTime()).toBeGreaterThan(0);
  });

  test('3. Sets fallback defaults for empty category or severity', () => {
    const evt = createSecurityEvent({});
    expect(evt.severity).toBe('low');
    expect(evt.confidence).toBeGreaterThanOrEqual(50);
  });
});

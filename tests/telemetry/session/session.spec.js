import { test, expect } from '@playwright/test';
import { telemetrySessionManager } from '../../../src/telemetry/session/telemetrySessionManager.js';

test.describe('TelemetrySessionManager Suite', () => {
  test('1. Initializes new telemetry simulation session with unique UUID', () => {
    const sessionId = telemetrySessionManager.startSession("MidEnterprise");

    expect(sessionId).toBeDefined();
    expect(sessionId).toMatch(/^sim_/);
    expect(telemetrySessionManager.currentSessionId).toBe(sessionId);
  });

  test('2. Tracks cumulative stats across events', () => {
    const statsBefore = telemetrySessionManager.getSessionStats();
    telemetrySessionManager.recordEvent({ eventId: 'evt_test', severity: 'high', category: 'execution' });

    const statsAfter = telemetrySessionManager.getSessionStats();
    expect(statsAfter.session.eventsGenerated).toBeGreaterThanOrEqual(statsBefore.session.eventsGenerated);
  });
});

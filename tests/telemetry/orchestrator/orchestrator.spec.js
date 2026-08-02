import { test, expect } from '@playwright/test';
import { telemetryOrchestrator } from '../../../src/telemetry/orchestrator/telemetryOrchestrator.js';
import { buildMockEvent } from '../../helpers/testFactories.js';

test.describe('TelemetryOrchestrator Conductor Suite', () => {
  test('1. Ingests raw SecurityEvent and passes through pipeline context', async () => {
    const rawEvt = buildMockEvent({ eventId: 'evt_orch_001', severity: 'low' });
    const ctx = await telemetryOrchestrator.ingest(rawEvt);

    expect(ctx).toBeDefined();
    expect(ctx.event).toBeDefined();
    expect(ctx.enrichedEvent).toBeDefined();
  });

  test('2. Gracefully handles null or malformed input without throwing', async () => {
    const ctxNull = await telemetryOrchestrator.ingest({});
    expect(ctxNull).toBeDefined();
  });
});

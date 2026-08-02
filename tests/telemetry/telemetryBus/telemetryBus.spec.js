import { test, expect } from '@playwright/test';
import { telemetryBus } from '../../../src/telemetry/telemetryBus.js';
import { buildMockEvent } from '../../helpers/testFactories.js';

test.describe('TelemetryBus Infrastructure Suite', () => {
  test('1. Subscribes and receives security_event publications', () => {
    let received = null;
    const unsub = telemetryBus.on('security_event', (evt) => {
      received = evt;
    });

    const mockEvt = buildMockEvent({ eventId: 'evt_bus_001' });
    telemetryBus.publishEvent(mockEvt);

    expect(received).not.toBeNull();
    expect(received.eventId).toBe('evt_bus_001');
    unsub();
  });

  test('2. Unsubscribe stops receiving events', () => {
    let count = 0;
    const unsub = telemetryBus.on('security_event', () => count++);
    unsub();

    telemetryBus.publishEvent(buildMockEvent());
    expect(count).toBe(0);
  });

  test('3. liveBuffer maintains rolling last 100 events', () => {
    telemetryBus.clearLiveBuffer();
    for (let i = 0; i < 110; i++) {
      telemetryBus.publishEvent(buildMockEvent({ eventId: `evt_roll_${i}` }));
    }

    const recent = telemetryBus.getRecentEvents();
    expect(recent.length).toBeLessThanOrEqual(100);
    expect(recent[recent.length - 1].eventId).toBe('evt_roll_109');
  });

  test('4. clearLiveBuffer clears sliding live window', () => {
    telemetryBus.publishEvent(buildMockEvent());
    telemetryBus.clearLiveBuffer();
    expect(telemetryBus.getRecentEvents()).toHaveLength(0);
  });
});

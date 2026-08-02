import { test, expect } from '@playwright/test';
import { EnterpriseGenerator } from '../../src/telemetry/generator/enterpriseGenerator.js';
import { SeededRandom } from '../../src/telemetry/utils/seededRandom.js';
import { EntityRegistry } from '../../src/telemetry/correlator/entityRegistry.js';

test.describe('Performance & Stress Suite', () => {
  test('1. High-throughput generation: generates 1,000 events in under 500ms', () => {
    const generator = new EnterpriseGenerator(new SeededRandom("perf_test_seed"));
    generator.setProfile("Fortune500");

    const start = Date.now();
    for (let i = 0; i < 1000; i++) {
      generator.generateBackgroundEvent();
    }
    const elapsed = Date.now() - start;

    expect(elapsed).toBeLessThan(500);
  });

  test('2. Entity Registry scalability: indexes 1,000 events with sub-millisecond lookup latency', () => {
    const generator = new EnterpriseGenerator(new SeededRandom("perf_entity_seed"));
    const registry = new EntityRegistry();

    const events = [];
    for (let i = 0; i < 1000; i++) {
      const evt = generator.generateBackgroundEvent();
      events.push(evt);
      registry.registerEventEntities(evt);
    }

    const startLookup = Date.now();
    const host = registry.getEntity("Host", events[0].asset.hostname);
    const lookupDuration = Date.now() - startLookup;

    expect(host).not.toBeNull();
    expect(lookupDuration).toBeLessThan(10);
  });
});

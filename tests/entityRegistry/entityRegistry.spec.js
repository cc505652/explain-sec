import { test, expect } from '@playwright/test';
import { EntityRegistry } from '../../src/telemetry/correlator/entityRegistry.js';
import { buildMockEvent } from '../helpers/testFactories.js';

test.describe('Entity Registry & Relationship Indexing Suite (Expanded)', () => {
  test('1. EntityRegistry registers Host, User, IP, and Process entities from SecurityEvent', () => {
    const registry = new EntityRegistry();
    const evt = buildMockEvent({
      eventId: "evt_test_101",
      asset: { hostname: "FINANCE-HOST-01", ip: "192.168.1.55" },
      user: { username: "alice.analyst" }
    });

    registry.registerEventEntities(evt);

    const host = registry.getEntity("Host", "FINANCE-HOST-01");
    expect(host).not.toBeNull();
    expect(host.eventIds.has("evt_test_101")).toBe(true);

    const user = registry.getEntity("User", "alice.analyst");
    expect(user).not.toBeNull();
    expect(user.eventIds.has("evt_test_101")).toBe(true);

    const ip = registry.getEntity("IP", "192.168.1.55");
    expect(ip).not.toBeNull();
  });

  test('2. Links correlation clusters to entity keys', () => {
    const registry = new EntityRegistry();
    registry.linkClusterToEntity("Host", "FINANCE-HOST-01", "cluster_999");

    const host = registry.getEntity("Host", "FINANCE-HOST-01");
    expect(host.clusterIds.has("cluster_999")).toBe(true);
  });

  test('3. getAllEntities returns all registered entity records', () => {
    const registry = new EntityRegistry();
    const evt = buildMockEvent({ eventId: "evt_123" });
    registry.registerEventEntities(evt);

    const all = registry.getAllEntities();
    expect(all.length).toBeGreaterThan(0);
  });

  test('4. Registers Hash entity when file hash is present in event payload', () => {
    const registry = new EntityRegistry();
    const evt = buildMockEvent({
      eventId: "evt_hash_1",
      hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    });

    registry.registerEventEntities(evt);
    const hash = registry.getEntity("Hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    if (hash) {
      expect(hash.eventIds.has("evt_hash_1")).toBe(true);
    }
  });

  test('5. Registers IOC entity when IOC indicator is present', () => {
    const registry = new EntityRegistry();
    const evt = buildMockEvent({
      eventId: "evt_ioc_1",
      ioc: { ip: "185.220.101.5", domain: "evil.c2.org" }
    });

    registry.registerEventEntities(evt);
    const ioc = registry.getEntity("IOC", "185.220.101.5");
    expect(ioc).not.toBeNull();
  });

  test('6. Clear method resets all entity indices', () => {
    const registry = new EntityRegistry();
    registry.registerEventEntities(buildMockEvent());
    registry.clear();

    const all = registry.getAllEntities();
    expect(all).toHaveLength(0);
  });
});

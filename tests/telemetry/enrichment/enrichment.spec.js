/**
 * EnrichmentEngine — Comprehensive Unit Tests
 */
import { test, expect } from '@playwright/test';
import { EnrichmentEngine } from '../../../src/telemetry/enrichment/enrichmentEngine.js';
import { buildMockEvent } from '../../helpers/testFactories.js';

test.describe('EnrichmentEngine Unit Suite', () => {
  let engine;
  test.beforeEach(() => { engine = new EnrichmentEngine(); });

  test('1. enrich returns object with eventStatus enriched', () => {
    const evt = buildMockEvent();
    const enriched = engine.enrich(evt);
    expect(enriched.eventStatus).toBe("enriched");
  });

  test('2. enrich preserves original event fields', () => {
    const evt = buildMockEvent({ description: "Test desc", severity: "high" });
    const enriched = engine.enrich(evt);
    expect(enriched.description).toBe("Test desc");
    expect(enriched.severity).toBe("high");
  });

  test('3. Known asset SERVER-DC01 gets critical criticality', () => {
    const evt = buildMockEvent({ asset: { hostname: "SERVER-DC01" } });
    const enriched = engine.enrich(evt);
    expect(enriched.asset.criticality).toBe("critical");
    expect(enriched.asset.type).toBe("domain_controller");
  });

  test('4. Known asset SERVER-DB01 gets critical criticality and Finance dept', () => {
    const evt = buildMockEvent({ asset: { hostname: "SERVER-DB01" } });
    const enriched = engine.enrich(evt);
    expect(enriched.asset.criticality).toBe("critical");
    expect(enriched.asset.department).toBe("Finance & Accounting");
  });

  test('5. Known user j.doe gets VIP tag', () => {
    const evt = buildMockEvent({ user: { username: "j.doe" } });
    const enriched = engine.enrich(evt);
    expect(enriched.user.vip).toBe(true);
    expect(enriched.tags).toContain("#vip_account");
  });

  test('6. Known user admin.smith gets Domain Admin role', () => {
    const evt = buildMockEvent({ user: { username: "admin.smith" } });
    const enriched = engine.enrich(evt);
    expect(enriched.user.role).toBe("Domain Admin");
  });

  test('7. Unknown hostname gets default asset metadata', () => {
    const evt = buildMockEvent({ asset: { hostname: "UNKNOWN-PC" } });
    const enriched = engine.enrich(evt);
    expect(enriched.asset.hostname).toBe("UNKNOWN-PC");
    expect(enriched.asset.type).toBe("endpoint");
  });

  test('8. Unknown username gets default user metadata', () => {
    const evt = buildMockEvent({ user: { username: "random.person" } });
    const enriched = engine.enrich(evt);
    expect(enriched.user.vip).toBe(false);
  });

  test('9. Critical asset gets #critical_asset tag', () => {
    const evt = buildMockEvent({ asset: { hostname: "SERVER-DC01" } });
    const enriched = engine.enrich(evt);
    expect(enriched.tags).toContain("#critical_asset");
  });

  test('10. Domain controller gets #domain_controller tag', () => {
    const evt = buildMockEvent({ asset: { hostname: "SERVER-DC01" } });
    const enriched = engine.enrich(evt);
    expect(enriched.tags).toContain("#domain_controller");
  });

  test('11. Event with IOC gets #known_ioc tag', () => {
    const evt = buildMockEvent({ ioc: { ip: "198.51.100.45" } });
    const enriched = engine.enrich(evt);
    expect(enriched.tags).toContain("#known_ioc");
  });

  test('12. Event without IOC has no #known_ioc tag', () => {
    const evt = buildMockEvent();
    const enriched = engine.enrich(evt);
    expect(enriched.tags).not.toContain("#known_ioc");
  });

  test('13. enrich returns input unchanged for null input', () => {
    const result = engine.enrich(null);
    expect(result).toBeNull();
  });

  test('14. enrich returns input unchanged for non-object', () => {
    const result = engine.enrich("not an object");
    expect(result).toBe("not an object");
  });

  test('15. enrich merges asset overrides with CMDB data', () => {
    const evt = buildMockEvent({ asset: { hostname: "FINANCE-PC-042", ip: "192.168.5.42" } });
    const enriched = engine.enrich(evt);
    expect(enriched.asset.hostname).toBe("FINANCE-PC-042");
    expect(enriched.asset.criticality).toBe("high");
    expect(enriched.asset.department).toBe("Finance Operations");
  });
});

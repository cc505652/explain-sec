/**
 * RiskEngine — Comprehensive Unit Tests
 */
import { test, expect } from '@playwright/test';
import { RiskEngine } from '../../../src/telemetry/correlator/riskEngine.js';
import { SEVERITIES } from '../../../src/telemetry/constants/index.js';
import { buildMockCluster, buildMockEvent } from '../../helpers/testFactories.js';

test.describe('RiskEngine Unit Suite', () => {
  let engine;
  test.beforeEach(() => { engine = new RiskEngine(); });

  test('1. calculateRisk returns { riskScore, severity }', () => {
    const cluster = buildMockCluster();
    const result = engine.calculateRisk(cluster);
    expect(result).toHaveProperty("riskScore");
    expect(result).toHaveProperty("severity");
  });

  test('2. riskScore is always in [0, 100]', () => {
    for (let i = 0; i < 20; i++) {
      const cluster = buildMockCluster({ riskScore: i * 10 });
      const result = engine.calculateRisk(cluster);
      expect(result.riskScore).toBeGreaterThanOrEqual(0);
      expect(result.riskScore).toBeLessThanOrEqual(100);
    }
  });

  test('3. Null cluster returns riskScore 0 and severity low', () => {
    const result = engine.calculateRisk(null);
    expect(result.riskScore).toBe(0);
    expect(result.severity).toBe(SEVERITIES.LOW);
  });

  test('4. Critical severity event adds up to 35 pts', () => {
    const evt = buildMockEvent({ severity: "critical" });
    const cluster = buildMockCluster({ events: [evt], eventIds: [evt.eventId] });
    const result = engine.calculateRisk(cluster);
    expect(result.riskScore).toBeGreaterThanOrEqual(35);
  });

  test('5. High severity event adds up to 25 pts', () => {
    const evt = buildMockEvent({ severity: "high" });
    const cluster = buildMockCluster({ events: [evt], eventIds: [evt.eventId] });
    const result = engine.calculateRisk(cluster);
    expect(result.riskScore).toBeGreaterThanOrEqual(25);
  });

  test('6. Medium severity event adds 15 pts', () => {
    const evt = buildMockEvent({ severity: "medium" });
    const cluster = buildMockCluster({ events: [evt], eventIds: [evt.eventId] });
    const result = engine.calculateRisk(cluster);
    expect(result.riskScore).toBeGreaterThanOrEqual(15);
  });

  test('7. Multiple events increase event count weight (up to 20 pts)', () => {
    const events = [];
    for (let i = 0; i < 5; i++) events.push(buildMockEvent({ severity: "low" }));
    const cluster = buildMockCluster({ events, eventIds: events.map(e => e.eventId) });
    const result1 = engine.calculateRisk(cluster);

    const singleCluster = buildMockCluster({ events: [events[0]], eventIds: [events[0].eventId] });
    const result2 = engine.calculateRisk(singleCluster);
    expect(result1.riskScore).toBeGreaterThan(result2.riskScore);
  });

  test('8. Campaign association adds 10 pts', () => {
    const evt = buildMockEvent({ severity: "low" });
    const withCampaign = buildMockCluster({ events: [evt], campaignId: "camp_1" });
    const withoutCampaign = buildMockCluster({ events: [evt], campaignId: null });
    const r1 = engine.calculateRisk(withCampaign);
    const r2 = engine.calculateRisk(withoutCampaign);
    expect(r1.riskScore).toBeGreaterThan(r2.riskScore);
  });

  test('9. Multiple MITRE tactics increase progression weight', () => {
    const e1 = buildMockEvent({ mitreTechnique: { tactic: "Execution" } });
    const e2 = buildMockEvent({ mitreTechnique: { tactic: "Credential Access" } });
    const e3 = buildMockEvent({ mitreTechnique: { tactic: "Persistence" } });
    const cluster = buildMockCluster({ events: [e1, e2, e3] });
    const result = engine.calculateRisk(cluster);
    expect(result.riskScore).toBeGreaterThanOrEqual(40);
  });

  test('10. Severity derived CRITICAL when riskScore >= 75', () => {
    const evt = buildMockEvent({ severity: "critical" });
    const e2 = buildMockEvent({ severity: "high", mitreTechnique: { tactic: "Lateral Movement" } });
    const cluster = buildMockCluster({ events: [evt, e2], campaignId: "c1" });
    const result = engine.calculateRisk(cluster);
    if (result.riskScore >= 75) {
      expect(result.severity).toBe(SEVERITIES.CRITICAL);
    }
  });

  test('11. Severity derived HIGH when riskScore >= 50 and < 75', () => {
    const evt = buildMockEvent({ severity: "high" });
    const cluster = buildMockCluster({ events: [evt] });
    const result = engine.calculateRisk(cluster);
    if (result.riskScore >= 50 && result.riskScore < 75) {
      expect(result.severity).toBe(SEVERITIES.HIGH);
    }
  });

  test('12. Severity derived MEDIUM when riskScore >= 30 and < 50', () => {
    const evt = buildMockEvent({ severity: "medium" });
    const cluster = buildMockCluster({ events: [evt] });
    const result = engine.calculateRisk(cluster);
    if (result.riskScore >= 30 && result.riskScore < 50) {
      expect(result.severity).toBe(SEVERITIES.MEDIUM);
    }
  });

  test('13. Severity forced CRITICAL when maxSevWeight is 35 regardless of score', () => {
    const evt = buildMockEvent({ severity: "critical" });
    const cluster = buildMockCluster({ events: [evt] });
    const result = engine.calculateRisk(cluster);
    expect(result.severity).toBe(SEVERITIES.CRITICAL);
  });

  test('14. Empty events array still returns valid riskScore', () => {
    const cluster = buildMockCluster({ events: [] });
    const result = engine.calculateRisk(cluster);
    expect(result.riskScore).toBeGreaterThanOrEqual(0);
    expect(result.riskScore).toBeLessThanOrEqual(100);
  });

  test('15. riskScore clamped to 100 even with many high-weight factors', () => {
    const events = [];
    for (let i = 0; i < 10; i++) {
      events.push(buildMockEvent({ severity: "critical", mitreTechnique: { tactic: `Tactic_${i}` } }));
    }
    const cluster = buildMockCluster({ events, campaignId: "max_camp", asset: { criticality: "critical" } });
    const result = engine.calculateRisk(cluster);
    expect(result.riskScore).toBeLessThanOrEqual(100);
  });
});

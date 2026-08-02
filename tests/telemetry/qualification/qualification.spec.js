/**
 * QualificationEngine — Comprehensive Unit Tests
 */
import { test, expect } from '@playwright/test';
import { QualificationEngine } from '../../../src/telemetry/correlator/qualificationEngine.js';
import { SEVERITIES, QUALIFICATION_THRESHOLDS } from '../../../src/telemetry/constants/index.js';
import { buildMockCluster } from '../../helpers/testFactories.js';

test.describe('QualificationEngine Unit Suite', () => {
  let engine;
  test.beforeEach(() => { engine = new QualificationEngine(); });

  test('1. shouldCreateIncident returns { qualified, reason }', () => {
    const cluster = buildMockCluster();
    const result = engine.shouldCreateIncident(cluster);
    expect(result).toHaveProperty("qualified");
    expect(result).toHaveProperty("reason");
  });

  test('2. Null cluster returns qualified=false', () => {
    const result = engine.shouldCreateIncident(null);
    expect(result.qualified).toBe(false);
    expect(result.reason).toContain("No cluster");
  });

  test('3. Critical severity with confidence >= 90 qualifies immediately', () => {
    const cluster = buildMockCluster({ severity: SEVERITIES.CRITICAL, eventConfidence: 95, riskScore: 80 });
    const result = engine.shouldCreateIncident(cluster);
    expect(result.qualified).toBe(true);
    expect(result.reason).toContain("critical");
  });

  test('4. Critical severity with riskScore >= 75 qualifies', () => {
    const cluster = buildMockCluster({ severity: SEVERITIES.CRITICAL, eventConfidence: 50, riskScore: 80 });
    const result = engine.shouldCreateIncident(cluster);
    expect(result.qualified).toBe(true);
  });

  test('5. Active campaign with eventCount >= 2 qualifies', () => {
    const events = [{ eventId: "e1" }, { eventId: "e2" }];
    const cluster = buildMockCluster({
      campaignId: "campaign_1",
      campaignName: "APT",
      events,
      eventIds: ["e1", "e2"],
      severity: SEVERITIES.MEDIUM,
      eventConfidence: 50,
      riskScore: 30
    });
    cluster.eventCount = 2;
    const result = engine.shouldCreateIncident(cluster);
    expect(result.qualified).toBe(true);
    expect(result.reason).toContain("campaign");
  });

  test('6. Risk score >= MIN_RISK_SCORE (60) qualifies', () => {
    const cluster = buildMockCluster({
      riskScore: 65,
      severity: SEVERITIES.MEDIUM,
      eventConfidence: 50,
      campaignId: null
    });
    const result = engine.shouldCreateIncident(cluster);
    expect(result.qualified).toBe(true);
    expect(result.reason).toContain("risk score");
  });

  test('7. Risk score exactly at threshold (60) qualifies', () => {
    const cluster = buildMockCluster({
      riskScore: QUALIFICATION_THRESHOLDS.MIN_RISK_SCORE,
      severity: SEVERITIES.MEDIUM,
      eventConfidence: 50,
      campaignId: null
    });
    const result = engine.shouldCreateIncident(cluster);
    expect(result.qualified).toBe(true);
  });

  test('8. Risk score below threshold is suppressed (noise)', () => {
    const cluster = buildMockCluster({
      riskScore: 30,
      severity: SEVERITIES.LOW,
      eventConfidence: 50,
      campaignId: null
    });
    const result = engine.shouldCreateIncident(cluster);
    expect(result.qualified).toBe(false);
    expect(result.reason).toContain("below");
  });

  test('9. Risk score 59 does not qualify', () => {
    const cluster = buildMockCluster({
      riskScore: 59,
      severity: SEVERITIES.MEDIUM,
      eventConfidence: 50,
      campaignId: null
    });
    const result = engine.shouldCreateIncident(cluster);
    expect(result.qualified).toBe(false);
  });

  test('10. Campaign with only 1 event does not qualify via campaign path', () => {
    const cluster = buildMockCluster({
      campaignId: "camp_solo",
      campaignName: "Solo",
      riskScore: 30,
      severity: SEVERITIES.LOW,
      eventConfidence: 50
    });
    cluster.eventCount = 1;
    const result = engine.shouldCreateIncident(cluster);
    // Should not qualify via campaign (needs >= 2 events), and riskScore too low
    expect(result.qualified).toBe(false);
  });

  test('11. MIN_RISK_SCORE constant is 60', () => {
    expect(QUALIFICATION_THRESHOLDS.MIN_RISK_SCORE).toBe(60);
  });

  test('12. Reason string includes numeric risk score', () => {
    const cluster = buildMockCluster({ riskScore: 45, severity: SEVERITIES.LOW, eventConfidence: 50, campaignId: null });
    const result = engine.shouldCreateIncident(cluster);
    expect(result.reason).toContain("45");
  });
});

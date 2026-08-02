/**
 * CorrelationCluster Factory — Comprehensive Unit Tests
 */
import { test, expect } from '@playwright/test';
import { createCorrelationCluster } from '../../src/telemetry/correlator/correlationCluster.js';
import { CLUSTER_STATES, SEVERITIES } from '../../src/telemetry/constants/index.js';
import { buildMockEvent } from '../helpers/testFactories.js';

test.describe('CorrelationCluster Factory Unit Suite', () => {

  test('1. Creates cluster with cluster_ prefixed ID', () => {
    const cluster = createCorrelationCluster();
    expect(cluster.clusterId).toMatch(/^cluster_/);
  });

  test('2. Two clusters have distinct IDs', () => {
    const a = createCorrelationCluster();
    const b = createCorrelationCluster();
    expect(a.clusterId).not.toBe(b.clusterId);
  });

  test('3. Accepts explicit clusterId override', () => {
    const cluster = createCorrelationCluster({ clusterId: "cluster_custom" });
    expect(cluster.clusterId).toBe("cluster_custom");
  });

  test('4. Default status is OPEN', () => {
    const cluster = createCorrelationCluster();
    expect(cluster.status).toBe(CLUSTER_STATES.OPEN);
  });

  test('5. Default ruleId is RULE-CORR-GENERIC', () => {
    const cluster = createCorrelationCluster();
    expect(cluster.ruleId).toBe("RULE-CORR-GENERIC");
  });

  test('6. Default severity is MEDIUM', () => {
    const cluster = createCorrelationCluster();
    expect(cluster.severity).toBe(SEVERITIES.MEDIUM);
  });

  test('7. Default riskScore is 50', () => {
    const cluster = createCorrelationCluster();
    expect(cluster.riskScore).toBe(50);
  });

  test('8. Default confidence model values', () => {
    const cluster = createCorrelationCluster();
    expect(cluster.eventConfidence).toBe(80);
    expect(cluster.correlationConfidence).toBe(85);
    expect(cluster.incidentConfidence).toBe(85);
  });

  test('9. Events array carries through', () => {
    const evt = buildMockEvent();
    const cluster = createCorrelationCluster({ events: [evt], eventIds: [evt.eventId] });
    expect(cluster.events).toHaveLength(1);
    expect(cluster.eventIds).toHaveLength(1);
    expect(cluster.eventCount).toBe(1);
  });

  test('10. Empty events array has eventCount 0', () => {
    const cluster = createCorrelationCluster({ events: [] });
    expect(cluster.eventCount).toBe(0);
  });

  test('11. Default campaign fields are null', () => {
    const cluster = createCorrelationCluster();
    expect(cluster.campaignId).toBeNull();
    expect(cluster.campaignName).toBeNull();
  });

  test('12. Campaign overrides carry through', () => {
    const cluster = createCorrelationCluster({ campaignId: "camp1", campaignName: "APT 29" });
    expect(cluster.campaignId).toBe("camp1");
    expect(cluster.campaignName).toBe("APT 29");
  });

  test('13. Default primaryAsset is WORKSTATION-01', () => {
    const cluster = createCorrelationCluster();
    expect(cluster.primaryAsset).toBe("WORKSTATION-01");
  });

  test('14. Default incidentQualified is false', () => {
    const cluster = createCorrelationCluster();
    expect(cluster.incidentQualified).toBe(false);
  });

  test('15. incidentId defaults to null', () => {
    const cluster = createCorrelationCluster();
    expect(cluster.incidentId).toBeNull();
  });

  test('16. Timestamps are numeric', () => {
    const cluster = createCorrelationCluster();
    expect(typeof cluster.createdAt).toBe("number");
    expect(typeof cluster.updatedAt).toBe("number");
  });

  test('17. explanation array built from rule match', () => {
    const cluster = createCorrelationCluster({ ruleId: "RULE-X", primaryAsset: "DC-01" });
    expect(Array.isArray(cluster.explanation)).toBe(true);
    expect(cluster.explanation.length).toBeGreaterThanOrEqual(1);
  });
});

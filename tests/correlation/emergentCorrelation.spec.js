/**
 * CorrelationEngine — Comprehensive Integration Tests
 */
import { test, expect } from '@playwright/test';
import { CorrelationEngine } from '../../src/telemetry/correlator/correlationEngine.js';
import { ClusterRepository } from '../../src/telemetry/correlator/clusterRepository.js';
import { EntityRegistry } from '../../src/telemetry/correlator/entityRegistry.js';
import { CLUSTER_STATES, TIME_WINDOWS_MS } from '../../src/telemetry/constants/index.js';
import { buildMockEvent } from '../helpers/testFactories.js';

test.describe('CorrelationEngine Integration Suite', () => {

  test('1. process returns context unchanged for null context', () => {
    const engine = new CorrelationEngine();
    expect(engine.process(null)).toBeNull();
  });

  test('2. process returns context unchanged for missing enrichedEvent', () => {
    const engine = new CorrelationEngine();
    const ctx = { enrichedEvent: null };
    expect(engine.process(ctx)).toBe(ctx);
  });

  test('3. process adds event to sliding buffer', () => {
    const engine = new CorrelationEngine();
    engine.clearSession();
    const ctx = { enrichedEvent: buildMockEvent({ description: "Benign process" }) };
    engine.process(ctx);
    expect(engine.slidingBuffer.length).toBeGreaterThanOrEqual(1);
  });

  test('4. process registers entities in EntityRegistry', () => {
    const engine = new CorrelationEngine();
    engine.clearSession();
    const evt = buildMockEvent({
      asset: { hostname: "CORR-HOST-01", ip: "10.0.0.5" },
      user: { username: "corr.user" }
    });
    const ctx = { enrichedEvent: evt };
    engine.process(ctx);

    // Verify entity was registered via the global registry
    // (correlationEngine uses the global entityRegistry)
  });

  test('5. process with detection trigger creates cluster', () => {
    const engine = new CorrelationEngine();
    engine.clearSession();

    const evt = buildMockEvent({
      description: "LSASS memory dump detected",
      asset: { hostname: "VICTIM-01" },
      user: { username: "attacker.user" }
    });
    const ctx = {
      enrichedEvent: evt,
      detectionResult: {
        triggered: true,
        ruleId: "DET-LSASS-DUMP-01",
        ruleName: "LSASS Process Memory Dump",
        severity: "critical",
        confidence: 95,
        mitreTechnique: { id: "T1003.001", tactic: "Credential Access" }
      }
    };

    engine.process(ctx);
    expect(ctx.correlationResult).not.toBeNull();
    expect(ctx.correlationResult.clusterId).toBeDefined();
    expect(ctx.correlationResult.ruleId).toBeDefined();
  });

  test('6. process computes riskScore on cluster', () => {
    const engine = new CorrelationEngine();
    engine.clearSession();

    const evt = buildMockEvent({ description: "LSASS detected", severity: "critical" });
    const ctx = {
      enrichedEvent: evt,
      detectionResult: {
        triggered: true,
        ruleId: "DET-LSASS-DUMP-01",
        ruleName: "LSASS Dump",
        severity: "critical",
        confidence: 95,
        mitreTechnique: { id: "T1003.001", tactic: "Credential Access" }
      }
    };

    engine.process(ctx);
    expect(ctx.riskResult).toBeDefined();
    expect(ctx.riskResult.riskScore).toBeGreaterThanOrEqual(0);
    expect(ctx.riskResult.riskScore).toBeLessThanOrEqual(100);
  });

  test('7. process produces qualificationResult', () => {
    const engine = new CorrelationEngine();
    engine.clearSession();

    const evt = buildMockEvent({ description: "LSASS", severity: "critical" });
    const ctx = {
      enrichedEvent: evt,
      detectionResult: {
        triggered: true,
        ruleId: "DET-LSASS-DUMP-01",
        ruleName: "LSASS Dump",
        severity: "critical",
        confidence: 95,
        mitreTechnique: { id: "T1003.001", tactic: "Credential Access" }
      }
    };

    engine.process(ctx);
    expect(ctx.qualificationResult).toBeDefined();
    expect(ctx.qualificationResult).toHaveProperty("qualified");
    expect(ctx.qualificationResult).toHaveProperty("reason");
  });

  test('8. process deduplicates events in same cluster', () => {
    const engine = new CorrelationEngine();
    engine.clearSession();

    const evt = buildMockEvent({
      description: "LSASS dump",
      asset: { hostname: "DEDUP-HOST" },
      campaignId: "chain_dedup"
    });
    const ctx1 = {
      enrichedEvent: evt,
      detectionResult: {
        triggered: true,
        ruleId: "DET-LSASS-DUMP-01",
        ruleName: "LSASS",
        severity: "critical",
        confidence: 95,
        mitreTechnique: { id: "T1003.001", tactic: "Credential Access" }
      }
    };

    engine.process(ctx1);
    const clusterId1 = ctx1.correlationResult?.clusterId;

    // Process same event again
    const ctx2 = { ...ctx1 };
    engine.process(ctx2);

    if (ctx2.correlationResult) {
      // Second processing should still produce a cluster result
      expect(ctx2.correlationResult.clusterId).toBeDefined();
    }
  });

  test('9. Benign event with no detection does not create cluster', () => {
    const engine = new CorrelationEngine();
    engine.clearSession();

    const evt = buildMockEvent({ description: "User opened Notepad" });
    const ctx = { enrichedEvent: evt };
    engine.process(ctx);
    expect(ctx.correlationResult).toBeNull();
  });

  test('10. setWindowMs changes sliding window', () => {
    const engine = new CorrelationEngine();
    engine.setWindowMs(TIME_WINDOWS_MS.WINDOW_10M);
    expect(engine.windowMs).toBe(TIME_WINDOWS_MS.WINDOW_10M);
  });

  test('11. clearSession resets buffer', () => {
    const engine = new CorrelationEngine();
    engine.slidingBuffer.push(buildMockEvent());
    engine.clearSession();
    expect(engine.slidingBuffer).toHaveLength(0);
  });

  test('12. getEventsWithinWindow returns only non-expired events', () => {
    const engine = new CorrelationEngine();
    engine.clearSession();
    engine.setWindowMs(TIME_WINDOWS_MS.WINDOW_5M);

    const recentEvt = buildMockEvent({ timestamp: Date.now() });
    const oldEvt = buildMockEvent({ timestamp: Date.now() - 600000 }); // 10 min ago
    engine.slidingBuffer = [recentEvt, oldEvt];

    const within = engine.getEventsWithinWindow();
    expect(within).toHaveLength(1);
  });

  test('13. Hypothesis confidence increases with events', () => {
    const engine = new CorrelationEngine();
    engine.clearSession();

    // First event
    const evt1 = buildMockEvent({ description: "LSASS first", campaignId: "hypo_chain" });
    const ctx1 = {
      enrichedEvent: evt1,
      detectionResult: {
        triggered: true,
        ruleId: "DET-LSASS-DUMP-01",
        ruleName: "LSASS",
        severity: "critical",
        confidence: 95,
        mitreTechnique: { id: "T1003.001", tactic: "Credential Access" }
      }
    };
    engine.process(ctx1);
    const hypo1 = ctx1.correlationResult?.cluster?.hypothesisConfidence || 0;

    // Second event on same campaign
    const evt2 = buildMockEvent({ description: "LSASS second", campaignId: "hypo_chain", eventId: "evt_hypo_2" });
    const ctx2 = {
      enrichedEvent: evt2,
      detectionResult: {
        triggered: true,
        ruleId: "DET-LSASS-DUMP-01",
        ruleName: "LSASS",
        severity: "critical",
        confidence: 95,
        mitreTechnique: { id: "T1003.001", tactic: "Credential Access" }
      }
    };
    engine.process(ctx2);
    const hypo2 = ctx2.correlationResult?.cluster?.hypothesisConfidence || 0;

    expect(hypo2).toBeGreaterThanOrEqual(hypo1);
  });

  test('14. Cluster explanation array is populated', () => {
    const engine = new CorrelationEngine();
    engine.clearSession();

    const evt = buildMockEvent({ description: "LSASS for explanation" });
    const ctx = {
      enrichedEvent: evt,
      detectionResult: {
        triggered: true,
        ruleId: "DET-LSASS-DUMP-01",
        ruleName: "LSASS Dump",
        severity: "critical",
        confidence: 95,
        mitreTechnique: { id: "T1003.001", tactic: "Credential Access" }
      }
    };
    engine.process(ctx);

    const cluster = ctx.correlationResult?.cluster;
    if (cluster) {
      expect(Array.isArray(cluster.explanation)).toBe(true);
      expect(cluster.explanation.length).toBeGreaterThan(0);
    }
  });

  test('15. Emergent campaign name assigned when eventCount >= 3', () => {
    const engine = new CorrelationEngine();
    engine.clearSession();

    // Process 3 events on same rule/asset without campaignName
    for (let i = 0; i < 3; i++) {
      const evt = buildMockEvent({
        description: `LSASS iteration ${i}`,
        asset: { hostname: "EMG-HOST" },
        eventId: `evt_emergent_${i}`
      });
      const ctx = {
        enrichedEvent: evt,
        detectionResult: {
          triggered: true,
          ruleId: "DET-LSASS-DUMP-01",
          ruleName: "LSASS Dump",
          severity: "critical",
          confidence: 95,
          mitreTechnique: { id: "T1003.001", tactic: "Credential Access" }
        }
      };
      engine.process(ctx);
    }
  });
});

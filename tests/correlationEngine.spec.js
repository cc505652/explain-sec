import { test, expect } from '@playwright/test';
import { SeededRandom } from '../src/telemetry/utils/seededRandom.js';
import { createSecurityEvent } from '../src/telemetry/types/securityEvent.js';
import { classificationEngine } from '../src/telemetry/classifier/classificationEngine.js';
import { riskEngine } from '../src/telemetry/correlator/riskEngine.js';
import { qualificationEngine } from '../src/telemetry/correlator/qualificationEngine.js';
import { buildCanonicalIncident } from '../src/telemetry/generator/canonicalIncidentBuilder.js';

test.describe('Phase 2 — Telemetry Pipeline & Correlation Engine Suite', () => {
  
  test('1. Single benign event does not trigger incident', async () => {
    const event = createSecurityEvent({
      severity: 'low',
      confidence: 30,
      description: 'Routine user process execution'
    });
    const classified = classificationEngine.classify(event);
    const qual = qualificationEngine.shouldCreateIncident({
      riskScore: 20,
      eventConfidence: 30,
      severity: 'low',
      eventCount: 1
    });
    expect(qual.qualified).toBe(false);
  });

  test('2. Multiple unrelated benign events do not trigger incident', async () => {
    const qual = qualificationEngine.shouldCreateIncident({
      riskScore: 40,
      eventConfidence: 30,
      severity: 'low',
      eventCount: 5
    });
    expect(qual.qualified).toBe(false);
  });

  test('3. Deterministic Risk Scoring stays clamped between 0 and 100', async () => {
    const cluster = {
      events: [
        createSecurityEvent({ severity: 'critical', confidence: 95 }),
        createSecurityEvent({ severity: 'high', confidence: 90 }),
        createSecurityEvent({ severity: 'high', confidence: 85 })
      ],
      asset: { criticality: 'critical' },
      campaignId: 'cmp_123'
    };
    const risk = riskEngine.calculateRisk(cluster);
    expect(risk.riskScore).toBeGreaterThanOrEqual(0);
    expect(risk.riskScore).toBeLessThanOrEqual(100);
  });

  test('4. Seeded Randomness produces 100% deterministic output', async () => {
    const prng1 = new SeededRandom(12345);
    const prng2 = new SeededRandom(12345);

    const val1 = [prng1.nextInt(1, 100), prng1.nextFloat(), prng1.nextInt(1, 100)];
    const val2 = [prng2.nextInt(1, 100), prng2.nextFloat(), prng2.nextInt(1, 100)];

    expect(val1).toEqual(val2);
  });

  test('5. Canonical Incident Builder creates Phase 1 compliant incident', async () => {
    const cluster = {
      clusterId: 'cluster_test_001',
      ruleName: 'Repeated Authentication Failure',
      summary: '5 failed logins from 192.168.1.100',
      category: 'credential_access',
      urgency: 'high',
      riskScore: 85,
      asset: { hostname: 'FINANCE-PC-01' },
      user: { username: 'j.doe' },
      confidence: 90,
      events: []
    };

    const incident = buildCanonicalIncident(cluster);
    expect(incident.status).toBe('open');
    expect(incident.visibleTo).toEqual(['soc_l1', 'soc_manager']);
    expect(incident.incidentSource).toBe('telemetry');
    expect(incident.originTelemetryClusterId).toBe('cluster_test_001');
    expect(incident.createdBy).toBe('live_event_engine');
  });

});

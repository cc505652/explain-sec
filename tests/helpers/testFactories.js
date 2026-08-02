/**
 * ======================================================================
 * EXPLAINSEC TEST FACTORIES & UTILITIES
 * ======================================================================
 * Reusable test factories for SecurityEvents, Entities, Clusters, and
 * Telemetry Context objects.
 * ======================================================================
 */

import { createSecurityEvent } from "../../src/telemetry/types/securityEvent.js";
import { createCorrelationCluster } from "../../src/telemetry/correlator/correlationCluster.js";

export function buildMockEvent(overrides = {}) {
  const ts = overrides.timestamp || Date.now();
  return createSecurityEvent({
    source: "WindowsEventLog",
    provider: "Microsoft",
    product: "Security Event Log",
    category: "execution",
    severity: "medium",
    confidence: 80,
    description: "Mock security event for automated testing",
    rawEvent: JSON.stringify({ EventID: 4688, Message: "Mock Process Creation" }),
    asset: {
      hostname: "TEST-HOST-01",
      ip: "192.168.1.100",
      type: "endpoint",
      department: "Engineering",
      owner: "test.user",
      criticality: "medium",
      location: "Corporate HQ"
    },
    user: {
      username: "test.user",
      domain: "CAMPUS",
      userPrincipalName: "test.user@campus.edu",
      role: "Corporate Staff"
    },
    ...overrides
  });
}

export function buildMockCluster(overrides = {}) {
  const evt = buildMockEvent();
  return createCorrelationCluster({
    ruleId: "RULE-TEST-001",
    ruleName: "Automated Test Correlation Rule",
    correlationReason: "Mock correlation match across test entities",
    eventIds: [evt.eventId],
    events: [evt],
    primaryAsset: "TEST-HOST-01",
    primaryUser: "test.user",
    riskScore: 75,
    severity: "high",
    incidentQualified: true,
    ...overrides
  });
}

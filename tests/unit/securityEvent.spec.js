/**
 * SecurityEvent Schema v2.0 — Comprehensive Unit Tests
 */
import { test, expect } from '@playwright/test';
import { createSecurityEvent, validateSecurityEvent, SCHEMA_VERSION, SOURCE_ICONS } from '../../src/telemetry/types/securityEvent.js';

test.describe('SecurityEvent Schema v2.0 Unit Suite', () => {

  test('1. createSecurityEvent returns object with schemaVersion 2.0', () => {
    const evt = createSecurityEvent();
    expect(evt.schemaVersion).toBe("2.0");
    expect(SCHEMA_VERSION).toBe("2.0");
  });

  test('2. createSecurityEvent generates unique eventId with evt_ prefix', () => {
    const a = createSecurityEvent();
    const b = createSecurityEvent();
    expect(a.eventId).toMatch(/^evt_/);
    expect(b.eventId).toMatch(/^evt_/);
    expect(a.eventId).not.toBe(b.eventId);
  });

  test('3. createSecurityEvent sets numeric timestamp', () => {
    const before = Date.now();
    const evt = createSecurityEvent();
    const after = Date.now();
    expect(evt.timestamp).toBeGreaterThanOrEqual(before);
    expect(evt.timestamp).toBeLessThanOrEqual(after);
  });

  test('4. createSecurityEvent respects explicit timestamp override', () => {
    const evt = createSecurityEvent({ timestamp: 1000 });
    expect(evt.timestamp).toBe(1000);
  });

  test('5. createSecurityEvent applies source and provider defaults', () => {
    const evt = createSecurityEvent();
    expect(evt.source).toBe("WindowsEventLog");
    expect(evt.provider).toBe("Microsoft");
    expect(evt.product).toBe("Security Event Log");
    expect(evt.connectorId).toBe("live_generator");
  });

  test('6. createSecurityEvent respects source override', () => {
    const evt = createSecurityEvent({ source: "CrowdStrikeFalcon", provider: "CrowdStrike", product: "Falcon EDR" });
    expect(evt.source).toBe("CrowdStrikeFalcon");
    expect(evt.provider).toBe("CrowdStrike");
    expect(evt.product).toBe("Falcon EDR");
  });

  test('7. createSecurityEvent applies default category, severity, confidence', () => {
    const evt = createSecurityEvent();
    expect(evt.category).toBe("execution");
    expect(evt.severity).toBe("low");
    expect(evt.confidence).toBe(80);
  });

  test('8. createSecurityEvent carries through campaign context when provided', () => {
    const evt = createSecurityEvent({
      campaignId: "chain_abc",
      campaignName: "APT Activity",
      campaignStage: "Execution",
      campaignStepIndex: 2,
      campaignTotalSteps: 7
    });
    expect(evt.campaignId).toBe("chain_abc");
    expect(evt.campaignName).toBe("APT Activity");
    expect(evt.campaignStage).toBe("Execution");
    expect(evt.campaignStepIndex).toBe(2);
    expect(evt.campaignTotalSteps).toBe(7);
  });

  test('9. createSecurityEvent defaults campaign fields to null when omitted', () => {
    const evt = createSecurityEvent();
    expect(evt.campaignId).toBeNull();
    expect(evt.campaignName).toBeNull();
    expect(evt.campaignStage).toBeNull();
  });

  test('10. createSecurityEvent builds asset object with defaults', () => {
    const evt = createSecurityEvent();
    expect(evt.asset.hostname).toBe("WORKSTATION-01");
    expect(evt.asset.ip).toBe("192.168.1.50");
    expect(evt.asset.type).toBe("endpoint");
    expect(evt.asset.criticality).toBe("medium");
  });

  test('11. createSecurityEvent merges asset overrides', () => {
    const evt = createSecurityEvent({
      asset: { hostname: "DC-01", ip: "10.0.0.1", criticality: "critical" }
    });
    expect(evt.asset.hostname).toBe("DC-01");
    expect(evt.asset.ip).toBe("10.0.0.1");
    expect(evt.asset.criticality).toBe("critical");
  });

  test('12. createSecurityEvent builds user object with defaults', () => {
    const evt = createSecurityEvent();
    expect(evt.user.username).toBe("user.account");
    expect(evt.user.domain).toBe("CAMPUS");
    expect(evt.user.userPrincipalName).toBe("user.account@campus.edu");
  });

  test('13. createSecurityEvent merges user overrides', () => {
    const evt = createSecurityEvent({
      user: { username: "admin.smith", domain: "CORP", role: "Domain Admin" }
    });
    expect(evt.user.username).toBe("admin.smith");
    expect(evt.user.domain).toBe("CORP");
    expect(evt.user.role).toBe("Domain Admin");
  });

  test('14. createSecurityEvent builds network defaults', () => {
    const evt = createSecurityEvent();
    expect(evt.network).toBeDefined();
    expect(evt.network.protocol).toBe("TCP");
    expect(evt.network.destPort).toBe(443);
  });

  test('15. createSecurityEvent accepts IOC payload', () => {
    const evt = createSecurityEvent({
      ioc: { ip: "198.51.100.45", domain: "c2.bad.org" }
    });
    expect(evt.ioc.ip).toBe("198.51.100.45");
    expect(evt.ioc.domain).toBe("c2.bad.org");
  });

  test('16. createSecurityEvent defaults IOC to null', () => {
    const evt = createSecurityEvent();
    expect(evt.ioc).toBeNull();
  });

  test('17. createSecurityEvent sets eventStatus to standardized', () => {
    const evt = createSecurityEvent();
    expect(evt.eventStatus).toBe("standardized");
  });

  test('18. createSecurityEvent builds default mitreTechnique', () => {
    const evt = createSecurityEvent();
    expect(evt.mitreTechnique.id).toBe("T1059");
    expect(evt.mitreTechnique.tactic).toBe("Execution");
  });

  test('19. createSecurityEvent builds default detectionRule', () => {
    const evt = createSecurityEvent();
    expect(evt.detectionRule.ruleId).toBe("RULE-GENERIC-001");
    expect(evt.detectionRule.ruleVersion).toBe("1.0");
  });

  test('20. SOURCE_ICONS contains expected provider icons', () => {
    expect(SOURCE_ICONS.DefenderForEndpoint).toBe("🛡️");
    expect(SOURCE_ICONS.CrowdStrikeFalcon).toBe("🦅");
    expect(SOURCE_ICONS.LinuxSyslog).toBe("🐧");
    expect(SOURCE_ICONS.Default).toBe("🔍");
  });

  test('21. validateSecurityEvent passes for valid event', () => {
    const evt = createSecurityEvent();
    const result = validateSecurityEvent(evt);
    expect(result.valid).toBe(true);
  });

  test('22. validateSecurityEvent fails for null input', () => {
    const result = validateSecurityEvent(null);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("object");
  });

  test('23. validateSecurityEvent fails for missing eventId', () => {
    const result = validateSecurityEvent({ timestamp: 1, source: "X", category: "Y" });
    expect(result.valid).toBe(false);
    expect(result.error).toContain("eventId");
  });

  test('24. validateSecurityEvent fails for missing timestamp', () => {
    const result = validateSecurityEvent({ eventId: "e1", source: "X", category: "Y" });
    expect(result.valid).toBe(false);
    expect(result.error).toContain("timestamp");
  });

  test('25. validateSecurityEvent fails for missing source', () => {
    const result = validateSecurityEvent({ eventId: "e1", timestamp: 1, category: "Y" });
    expect(result.valid).toBe(false);
    expect(result.error).toContain("source");
  });

  test('26. validateSecurityEvent fails for missing category', () => {
    const result = validateSecurityEvent({ eventId: "e1", timestamp: 1, source: "X" });
    expect(result.valid).toBe(false);
    expect(result.error).toContain("category");
  });

  test('27. createSecurityEvent confidence defaults to 80 when not provided', () => {
    const evt = createSecurityEvent({ confidence: undefined });
    expect(evt.confidence).toBe(80);
  });

  test('28. createSecurityEvent confidence accepts 0 via nullish coalescing', () => {
    const evt = createSecurityEvent({ confidence: 0 });
    expect(evt.confidence).toBe(0);
  });
});

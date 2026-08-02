/**
 * DetectionEngine & Individual Detection Rules — Comprehensive Unit Tests
 */
import { test, expect } from '@playwright/test';
import { DetectionEngine } from '../../../src/telemetry/detection/detectionEngine.js';
import { DETECTION_RULES, evaluateDetectionRules } from '../../../src/telemetry/detection/rules/index.js';
import { buildMockEvent } from '../../helpers/testFactories.js';

test.describe('DetectionEngine & Detection Rules Unit Suite', () => {
  let engine;
  test.beforeEach(() => { engine = new DetectionEngine(); });

  // --- DetectionEngine.evaluate contract ---

  test('1. evaluate returns context unchanged for null context', () => {
    const result = engine.evaluate(null);
    expect(result).toBeNull();
  });

  test('2. evaluate returns context unchanged for missing enrichedEvent', () => {
    const ctx = { enrichedEvent: null };
    const result = engine.evaluate(ctx);
    expect(result).toBe(ctx);
  });

  test('3. evaluate sets detectionResult.triggered=false for benign event', () => {
    const ctx = { enrichedEvent: buildMockEvent({ description: "User logged in", rawEvent: '{"EventID": 4624}' }) };
    engine.evaluate(ctx);
    expect(ctx.detectionResult.triggered).toBe(false);
    expect(ctx.detectionResult.ruleId).toBeNull();
  });

  test('4. evaluate sets triggered=true for LSASS dump event', () => {
    const ctx = { enrichedEvent: buildMockEvent({ description: "LSASS memory access detected" }) };
    engine.evaluate(ctx);
    expect(ctx.detectionResult.triggered).toBe(true);
    expect(ctx.detectionResult.ruleId).toBe("DET-LSASS-DUMP-01");
    expect(ctx.detectionResult.severity).toBe("critical");
  });

  test('5. evaluate sets triggered=true for mimikatz event', () => {
    const ctx = { enrichedEvent: buildMockEvent({ description: "mimikatz credential harvesting" }) };
    engine.evaluate(ctx);
    expect(ctx.detectionResult.triggered).toBe(true);
    expect(ctx.detectionResult.ruleId).toBe("DET-LSASS-DUMP-01");
  });

  test('6. evaluate sets triggered=true for ransomware vssadmin event', () => {
    const ctx = { enrichedEvent: buildMockEvent({ description: "vssadmin delete shadows executed" }) };
    engine.evaluate(ctx);
    expect(ctx.detectionResult.triggered).toBe(true);
    expect(ctx.detectionResult.ruleId).toBe("DET-RANSOMWARE-01");
    expect(ctx.detectionResult.severity).toBe("critical");
  });

  test('7. evaluate detects ransomware from rawEvent containing vssadmin', () => {
    const ctx = { enrichedEvent: buildMockEvent({ description: "Process created", rawEvent: '{"cmd": "vssadmin delete shadows"}' }) };
    engine.evaluate(ctx);
    expect(ctx.detectionResult.triggered).toBe(true);
    expect(ctx.detectionResult.ruleId).toBe("DET-RANSOMWARE-01");
  });

  test('8. evaluate sets triggered=true for PowerShell execution', () => {
    const ctx = { enrichedEvent: buildMockEvent({ description: "powershell -NoProfile -Exec Bypass" }) };
    engine.evaluate(ctx);
    expect(ctx.detectionResult.triggered).toBe(true);
    expect(ctx.detectionResult.ruleId).toBe("DET-POWERSHELL-01");
    expect(ctx.detectionResult.severity).toBe("high");
  });

  test('9. evaluate detects PowerShell from rawEvent', () => {
    const ctx = { enrichedEvent: buildMockEvent({ description: "Process", rawEvent: '{"Image":"C:\\\\Windows\\\\System32\\\\powershell.exe"}' }) };
    engine.evaluate(ctx);
    expect(ctx.detectionResult.triggered).toBe(true);
  });

  test('10. evaluate sets triggered=true for suspicious service install', () => {
    const ctx = { enrichedEvent: buildMockEvent({ description: "A new service installed on the system" }) };
    engine.evaluate(ctx);
    expect(ctx.detectionResult.triggered).toBe(true);
    expect(ctx.detectionResult.ruleId).toBe("DET-SERVICE-01");
  });

  test('11. evaluate detects service from EventID 7045 in rawEvent', () => {
    const ctx = { enrichedEvent: buildMockEvent({ description: "Event", rawEvent: '{"EventID": 7045, "ServiceName": "PSEXESVC"}' }) };
    engine.evaluate(ctx);
    expect(ctx.detectionResult.triggered).toBe(true);
  });

  test('12. evaluate detects PsExec from rawEvent', () => {
    const ctx = { enrichedEvent: buildMockEvent({ description: "Event", rawEvent: '{"svc": "psexesvc"}' }) };
    engine.evaluate(ctx);
    expect(ctx.detectionResult.triggered).toBe(true);
    expect(ctx.detectionResult.ruleId).toBe("DET-SERVICE-01");
  });

  test('13. evaluate sets triggered=true for encoded command', () => {
    const ctx = { enrichedEvent: buildMockEvent({ description: "Event", rawEvent: '{"CommandLine": "powershell.exe -enc aGVsbG8="}' }) };
    engine.evaluate(ctx);
    expect(ctx.detectionResult.triggered).toBe(true);
  });

  test('14. evaluate detects -EncodedCommand flag', () => {
    const ctx = { enrichedEvent: buildMockEvent({ description: "Event", rawEvent: '{"cmd": "-EncodedCommand AAAA=="}' }) };
    engine.evaluate(ctx);
    expect(ctx.detectionResult.triggered).toBe(true);
    expect(ctx.detectionResult.ruleId).toBe("DET-ENCODED-01");
  });

  test('15. evaluate detects base64 string in rawEvent', () => {
    const ctx = { enrichedEvent: buildMockEvent({ description: "Event", rawEvent: '{"payload": "base64 encoded data"}' }) };
    engine.evaluate(ctx);
    expect(ctx.detectionResult.triggered).toBe(true);
  });

  test('16. evaluate does not trigger for benign notepad execution', () => {
    const ctx = { enrichedEvent: buildMockEvent({ description: "User opened notepad.exe", rawEvent: '{"Image":"notepad.exe"}' }) };
    engine.evaluate(ctx);
    expect(ctx.detectionResult.triggered).toBe(false);
  });

  test('17. evaluate does not trigger for standard login event', () => {
    const ctx = { enrichedEvent: buildMockEvent({ description: "Interactive logon", rawEvent: '{"EventID": 4624, "LogonType": 2}' }) };
    engine.evaluate(ctx);
    expect(ctx.detectionResult.triggered).toBe(false);
  });

  test('18. evaluate populates mitreTechnique on match', () => {
    const ctx = { enrichedEvent: buildMockEvent({ description: "LSASS process dump" }) };
    engine.evaluate(ctx);
    expect(ctx.detectionResult.mitreTechnique).toBeDefined();
    expect(ctx.detectionResult.mitreTechnique.id).toBe("T1003.001");
  });

  test('19. evaluate populates confidence on match', () => {
    const ctx = { enrichedEvent: buildMockEvent({ description: "LSASS process dump" }) };
    engine.evaluate(ctx);
    expect(ctx.detectionResult.confidence).toBe(95);
  });

  // --- DETECTION_RULES catalog ---

  test('20. DETECTION_RULES contains exactly 5 rules', () => {
    expect(DETECTION_RULES).toHaveLength(5);
  });

  test('21. Every rule has ruleId, ruleName, severity, match function', () => {
    for (const rule of DETECTION_RULES) {
      expect(rule.ruleId).toBeDefined();
      expect(rule.ruleName).toBeDefined();
      expect(rule.severity).toBeDefined();
      expect(typeof rule.match).toBe("function");
    }
  });

  test('22. evaluateDetectionRules returns null for null event', () => {
    expect(evaluateDetectionRules(null)).toBeNull();
  });

  test('23. evaluateDetectionRules returns null for benign event', () => {
    const evt = buildMockEvent({ description: "Normal file access", rawEvent: '{"EventID": 4663}' });
    expect(evaluateDetectionRules(evt)).toBeNull();
  });

  test('24. Rule priority: ransomware checked before powershell', () => {
    // ransomwareRule is first in the array, so it should match first
    const evt = buildMockEvent({ description: "ransomware vssadmin powershell" });
    const match = evaluateDetectionRules(evt);
    expect(match.ruleId).toBe("DET-RANSOMWARE-01");
  });
});

/**
 * ClassificationEngine — Comprehensive Unit Tests
 */
import { test, expect } from '@playwright/test';
import { ClassificationEngine } from '../../../src/telemetry/classifier/classificationEngine.js';
import { buildMockEvent } from '../../helpers/testFactories.js';

test.describe('ClassificationEngine Unit Suite', () => {
  let engine;
  test.beforeEach(() => { engine = new ClassificationEngine(); });

  test('1. classify returns object with eventStatus classified', () => {
    const evt = buildMockEvent();
    const result = engine.classify(evt);
    expect(result.eventStatus).toBe("classified");
  });

  test('2. classify returns null for null input', () => {
    expect(engine.classify(null)).toBeNull();
  });

  test('3. classify produces classification sub-object', () => {
    const result = engine.classify(buildMockEvent());
    expect(result.classification).toBeDefined();
    expect(result.classification.compositeScore).toBeDefined();
    expect(result.classification.urgency).toBeDefined();
  });

  test('4. Critical severity adds 35 to composite score', () => {
    const evt = buildMockEvent({ severity: "critical", confidence: 50 });
    const result = engine.classify(evt);
    expect(result.classification.compositeScore).toBeGreaterThanOrEqual(85);
  });

  test('5. High severity adds 25 to composite score', () => {
    const evt = buildMockEvent({ severity: "high", confidence: 50 });
    const result = engine.classify(evt);
    expect(result.classification.compositeScore).toBeGreaterThanOrEqual(75);
  });

  test('6. Medium severity adds 10 to composite score', () => {
    const evt = buildMockEvent({ severity: "medium", confidence: 50 });
    const result = engine.classify(evt);
    expect(result.classification.compositeScore).toBeGreaterThanOrEqual(60);
  });

  test('7. Low severity adds 0 to composite score', () => {
    const evt = buildMockEvent({ severity: "low", confidence: 50 });
    const result = engine.classify(evt);
    expect(result.classification.compositeScore).toBe(50);
  });

  test('8. Critical asset adds 15 to composite score', () => {
    const evt = buildMockEvent({ severity: "low", confidence: 50, asset: { criticality: "critical" } });
    const result = engine.classify(evt);
    expect(result.classification.compositeScore).toBe(65);
  });

  test('9. High asset criticality adds 10 to composite score', () => {
    const evt = buildMockEvent({ severity: "low", confidence: 50, asset: { criticality: "high" } });
    const result = engine.classify(evt);
    expect(result.classification.compositeScore).toBe(60);
  });

  test('10. compositeScore clamped to max 100', () => {
    const evt = buildMockEvent({ severity: "critical", confidence: 95, asset: { criticality: "critical" } });
    const result = engine.classify(evt);
    expect(result.classification.compositeScore).toBeLessThanOrEqual(100);
  });

  test('11. Urgency critical when compositeScore >= 85', () => {
    const evt = buildMockEvent({ severity: "critical", confidence: 50 });
    const result = engine.classify(evt);
    expect(result.classification.urgency).toBe("critical");
  });

  test('12. Urgency high when compositeScore >= 65', () => {
    const evt = buildMockEvent({ severity: "high", confidence: 50 });
    const result = engine.classify(evt);
    expect(result.classification.urgency).toBe("high");
  });

  test('13. Urgency medium when compositeScore >= 45', () => {
    const evt = buildMockEvent({ severity: "medium", confidence: 40 });
    const result = engine.classify(evt);
    expect(result.classification.urgency).toBe("medium");
  });

  test('14. Urgency low when compositeScore < 45', () => {
    const evt = buildMockEvent({ severity: "low", confidence: 20 });
    const result = engine.classify(evt);
    expect(result.classification.urgency).toBe("low");
  });

  test('15. classification.tactic defaults to Execution', () => {
    const evt = buildMockEvent();
    const result = engine.classify(evt);
    expect(result.classification.tactic).toBe("Execution");
  });

  test('16. classification.tactic uses mitreTechnique tactic when provided', () => {
    const evt = buildMockEvent({ mitreTechnique: { id: "T1003", tactic: "Credential Access" } });
    const result = engine.classify(evt);
    expect(result.classification.tactic).toBe("Credential Access");
  });

  test('17. classification preserves original event properties', () => {
    const evt = buildMockEvent({ description: "keepme" });
    const result = engine.classify(evt);
    expect(result.description).toBe("keepme");
  });
});

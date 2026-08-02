/**
 * Constants Registry — Comprehensive Unit Tests
 */
import { test, expect } from '@playwright/test';
import {
  SEVERITIES, CATEGORIES, CLUSTER_STATES,
  ENGINE_MODES, CONNECTOR_IDS, TIME_WINDOWS_MS,
  QUALIFICATION_THRESHOLDS
} from '../../src/telemetry/constants/index.js';

test.describe('Constants Registry Unit Suite', () => {

  test('1. SEVERITIES has 4 levels', () => {
    expect(Object.keys(SEVERITIES)).toHaveLength(4);
    expect(SEVERITIES.LOW).toBe("low");
    expect(SEVERITIES.MEDIUM).toBe("medium");
    expect(SEVERITIES.HIGH).toBe("high");
    expect(SEVERITIES.CRITICAL).toBe("critical");
  });

  test('2. CATEGORIES has 9 ATT&CK categories', () => {
    expect(Object.keys(CATEGORIES)).toHaveLength(9);
    expect(CATEGORIES.CREDENTIAL_ACCESS).toBe("credential_access");
    expect(CATEGORIES.EXECUTION).toBe("execution");
    expect(CATEGORIES.EXFILTRATION).toBe("exfiltration");
  });

  test('3. CLUSTER_STATES has 6 lifecycle states', () => {
    expect(Object.keys(CLUSTER_STATES)).toHaveLength(6);
    expect(CLUSTER_STATES.OPEN).toBe("OPEN");
    expect(CLUSTER_STATES.CORRELATING).toBe("CORRELATING");
    expect(CLUSTER_STATES.QUALIFIED).toBe("QUALIFIED");
    expect(CLUSTER_STATES.INCIDENT_CREATED).toBe("INCIDENT_CREATED");
    expect(CLUSTER_STATES.SUPPRESSED).toBe("SUPPRESSED");
    expect(CLUSTER_STATES.ARCHIVED).toBe("ARCHIVED");
  });

  test('4. ENGINE_MODES has 5 modes', () => {
    expect(Object.keys(ENGINE_MODES)).toHaveLength(5);
    expect(ENGINE_MODES.TRAINING).toBe("Training");
    expect(ENGINE_MODES.CHAOS).toBe("Chaos Mode");
  });

  test('5. CONNECTOR_IDS has 6 connector types', () => {
    expect(Object.keys(CONNECTOR_IDS)).toHaveLength(6);
    expect(CONNECTOR_IDS.LIVE_GENERATOR).toBe("live_generator");
    expect(CONNECTOR_IDS.SENTRIX_SIEM).toBe("sentrix_siem");
  });

  test('6. TIME_WINDOWS_MS has correct millisecond values', () => {
    expect(TIME_WINDOWS_MS.WINDOW_60S).toBe(60000);
    expect(TIME_WINDOWS_MS.WINDOW_5M).toBe(300000);
    expect(TIME_WINDOWS_MS.WINDOW_10M).toBe(600000);
    expect(TIME_WINDOWS_MS.WINDOW_30M).toBe(1800000);
  });

  test('7. QUALIFICATION_THRESHOLDS are correct', () => {
    expect(QUALIFICATION_THRESHOLDS.MIN_RISK_SCORE).toBe(60);
    expect(QUALIFICATION_THRESHOLDS.MIN_CONFIDENCE).toBe(75);
    expect(QUALIFICATION_THRESHOLDS.SINGLE_CRITICAL_RISK).toBe(90);
  });
});

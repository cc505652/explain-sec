/**
 * PipelineContext — Comprehensive Unit Tests
 */
import { test, expect } from '@playwright/test';
import { createPipelineContext } from '../../src/telemetry/types/pipelineContext.js';

test.describe('PipelineContext Unit Suite', () => {

  test('1. createPipelineContext generates context with ctx_ prefixed ID', () => {
    const ctx = createPipelineContext();
    expect(ctx.contextId).toMatch(/^ctx_/);
  });

  test('2. Two contexts have distinct IDs', () => {
    const a = createPipelineContext();
    const b = createPipelineContext();
    expect(a.contextId).not.toBe(b.contextId);
  });

  test('3. Context timestamp is numeric and recent', () => {
    const before = Date.now();
    const ctx = createPipelineContext();
    expect(ctx.timestamp).toBeGreaterThanOrEqual(before);
  });

  test('4. All pipeline slots initialize to null', () => {
    const ctx = createPipelineContext();
    expect(ctx.event).toBeNull();
    expect(ctx.enrichedEvent).toBeNull();
    expect(ctx.classification).toBeNull();
    expect(ctx.detectionResult).toBeNull();
    expect(ctx.campaignState).toBeNull();
    expect(ctx.correlationResult).toBeNull();
    expect(ctx.riskResult).toBeNull();
    expect(ctx.qualificationResult).toBeNull();
  });

  test('5. rawInput stores provided input object', () => {
    const input = { source: "test", category: "exec" };
    const ctx = createPipelineContext(input);
    expect(ctx.rawInput).toEqual(input);
  });

  test('6. rawInput defaults to empty object', () => {
    const ctx = createPipelineContext();
    expect(ctx.rawInput).toEqual({});
  });
});

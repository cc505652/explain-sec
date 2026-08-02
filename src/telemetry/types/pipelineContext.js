/**
 * ======================================================================
 * EXPLAINSEC PHASE 2 — PIPELINE CONTEXT
 * ======================================================================
 * Data container passed through the TelemetryOrchestrator pipeline.
 * ======================================================================
 */

export function createPipelineContext(rawInput = {}) {
  const timestamp = Date.now();
  const idSuffix = Math.random().toString(36).substring(2, 9);

  return {
    contextId: `ctx_${timestamp}_${idSuffix}`,
    timestamp,
    rawInput,
    event: null,                 // SecurityEvent schema v2.0
    enrichedEvent: null,         // Enriched SecurityEvent with Asset/User/Geo context
    classification: null,        // Threat Category & Base Urgency
    detectionResult: null,       // Immediate Critical Alerts
    campaignState: null,         // Attack Campaign Progression
    correlationResult: null,     // CorrelationCluster association
    riskResult: null,            // Deterministic 0-100 Risk Score
    qualificationResult: null    // Incident qualification decision
  };
}

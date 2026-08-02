/**
 * ======================================================================
 * EXPLAINSEC PHASE 2 — TELEMETRY ORCHESTRATOR
 * ======================================================================
 * Central conductor executing the telemetry ingestion pipeline.
 * ======================================================================
 */

import { createPipelineContext } from "../types/pipelineContext.js";
import { createSecurityEvent } from "../types/securityEvent.js";
import { enrichmentEngine } from "../enrichment/enrichmentEngine.js";
import { classificationEngine } from "../classifier/classificationEngine.js";
import { detectionEngine } from "../detection/detectionEngine.js";
import { correlationEngine } from "../correlator/correlationEngine.js";
import { incidentGenerator } from "../generator/incidentGenerator.js";
import { telemetryBus } from "../telemetryBus.js";
import { CLUSTER_STATES } from "../constants/index.js";

export class TelemetryOrchestrator {
  /**
   * Ingests raw input and runs through the complete pipeline context sequence.
   *
   * @param {Object} rawInput - Raw event payload or template parameters
   * @returns {Object} Final PipelineContext
   */
  async ingest(rawInput) {
    const context = createPipelineContext(rawInput);

    try {
      // 1. Standardize
      context.event = createSecurityEvent(rawInput);

      // 2. Enrich
      context.enrichedEvent = enrichmentEngine.enrich(context.event);

      // 3. Classify
      context.classification = classificationEngine.classify(context.enrichedEvent);

      // 4. Single-Event Detection
      detectionEngine.evaluate(context);

      // 5. Publish raw event to stream ticker
      telemetryBus.publishEvent(context.enrichedEvent);

      // 6. Multi-Event Correlation & Risk Qualification
      correlationEngine.process(context);

      // 7. Incident Formation Check
      const cluster = context.correlationResult?.cluster;
      const qualified = context.qualificationResult?.qualified;

      if (cluster && qualified && (cluster.status === CLUSTER_STATES.QUALIFIED || cluster.status === CLUSTER_STATES.INCIDENT_CREATED)) {
        cluster.status = CLUSTER_STATES.INCIDENT_CREATED;
        await incidentGenerator.generateIncident(cluster);
      } else if (!qualified) {
        telemetryBus.stats.suppressedEvents++;
      }

      return context;
    } catch (err) {
      console.error("Error in TelemetryOrchestrator pipeline execution:", err);
      return context;
    }
  }
}

export const telemetryOrchestrator = new TelemetryOrchestrator();

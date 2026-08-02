/**
 * ======================================================================
 * EXPLAINSEC PHASE 2 — CANONICAL INCIDENT BUILDER
 * ======================================================================
 * Transforms correlated telemetry clusters into canonical ExplainSec
 * Phase 1 incident documents that are 100% indistinguishable from
 * manually reported incidents in Firestore.
 * ======================================================================
 */

import { serverTimestamp, Timestamp } from "firebase/firestore";

/**
 * Builds a canonical Phase 1 incident document object.
 *
 * @param {Object} cluster - Correlated telemetry event cluster
 * @returns {Object} Canonical Firestore incident document
 */
export function buildCanonicalIncident(cluster) {
  if (!cluster || typeof cluster !== "object") {
    throw new Error("Invalid telemetry cluster provided to CanonicalIncidentBuilder");
  }

  const hostname = cluster.asset?.hostname || "WORKSTATION-01";
  const title = `[TELEMETRY] ${cluster.ruleName || "Security Event Detection"}`;
  const correlationId = cluster.correlationId || `corr_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
  const urgency = cluster.urgency || "high";
  const severity = cluster.severity || urgency;
  const urgencyScore = cluster.riskScore || 85;

  return {
    // ------------------------------------------------------------------
    // CANONICAL PHASE 1 INCIDENT FIELDS (Required by Phase 1 Workflows)
    // ------------------------------------------------------------------
    title,
    description: cluster.summary || "Security telemetry anomaly detected",
    category: cluster.category || "execution",
    urgency,
    severity,
    urgencyScore,
    location: hostname,
    
    // Initial Lifecycle Status & Strict Role Visibility
    status: "open",
    visibleTo: ["soc_l1", "soc_manager"], // L1 + Manager initial visibility (L2 leak proof)
    assignedTo: null,
    escalatedTo: null,
    
    // Core Metadata
    createdBy: "live_event_engine",
    createdAt: serverTimestamp(),
    updatedAt: serverTimestamp(),
    isDeleted: false,
    statusHistory: [
      {
        status: "open",
        at: Timestamp.now(),
        note: `Incident generated via telemetry correlation rule: ${cluster.ruleName || "Detection Rule"}`
      }
    ],

    // ------------------------------------------------------------------
    // PHASE 2 TELEMETRY METADATA & PROVENANCE (Informational Only)
    // ------------------------------------------------------------------
    incidentSource: cluster.incidentSource || "telemetry", // manual | telemetry | sentrix | csv | syslog | rest_api | webhook
    generatedBy: "event_generator",
    sourceConnector: cluster.sourceConnector || "live_generator",
    campaignId: cluster.campaignId || null,
    campaignName: cluster.campaignName || null,
    correlationId,
    simulationSessionId: cluster.sessionId || null,
    originTelemetryClusterId: cluster.clusterId || `cluster_${Date.now()}`,
    sourceEvents: cluster.events || [],
    confidence: cluster.confidence || 85,
    detectionRule: cluster.detectionRule || "Telemetry Correlation Rule",
    mitreInfo: cluster.mitreInfo || null,
    assetDetails: cluster.asset || null,
    userDetails: cluster.user || null
  };
}

/**
 * ======================================================================
 * EXPLAINSEC PHASE 2 — CORRELATION CLUSTER MODEL
 * ======================================================================
 * Explicit schema and helper builder for correlation clusters.
 * ======================================================================
 */

import { CLUSTER_STATES, SEVERITIES } from "../constants/index.js";
import { telemetrySessionManager } from "../session/telemetrySessionManager.js";

export function createCorrelationCluster(params = {}) {
  const timestamp = Date.now();
  const idSuffix = Math.random().toString(36).substring(2, 9);

  return {
    clusterId: params.clusterId || `cluster_${timestamp}_${idSuffix}`,
    sessionId: params.sessionId || telemetrySessionManager.getCurrentSessionId() || null,
    createdAt: timestamp,
    updatedAt: timestamp,
    status: params.status || CLUSTER_STATES.OPEN,

    ruleId: params.ruleId || "RULE-CORR-GENERIC",
    ruleName: params.ruleName || "Generic Telemetry Correlation",
    correlationReason: params.correlationReason || "Events correlated on shared dimension",
    explanation: params.explanation || [
      `Matched ${params.ruleId || "Rule Match"}`,
      `${params.events ? params.events.length : 1} related event(s) correlated`,
      `Primary Asset: ${params.primaryAsset || "WORKSTATION-01"}`
    ],

    eventIds: params.eventIds || [],
    events: params.events || [],
    eventCount: params.events ? params.events.length : 0,

    primaryAsset: params.primaryAsset || "WORKSTATION-01",
    affectedAssets: params.affectedAssets || [],
    primaryUser: params.primaryUser || "user.account",
    affectedUsers: params.affectedUsers || [],

    sourceIPs: params.sourceIPs || [],
    destinationIPs: params.destinationIPs || [],
    iocs: params.iocs || [],

    categories: params.categories || [],
    mitreTechniques: params.mitreTechniques || [],
    mitreTactics: params.mitreTactics || [],

    campaignId: params.campaignId || null,
    campaignName: params.campaignName || null,

    // Multi-Stage Confidence Model
    eventConfidence: params.eventConfidence || 80,
    correlationConfidence: params.correlationConfidence || 85,
    incidentConfidence: params.incidentConfidence || 85,

    riskScore: params.riskScore || 50,
    severity: params.severity || SEVERITIES.MEDIUM,

    incidentQualified: params.incidentQualified || false,
    incidentId: params.incidentId || null
  };
}

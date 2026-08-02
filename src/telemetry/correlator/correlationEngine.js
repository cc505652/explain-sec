/**
 * ======================================================================
 * EXPLAINSEC PHASE 2 — CORRELATION ENGINE
 * ======================================================================
 * Sliding window event aggregator, 11-dimension correlator, and cluster manager.
 * ======================================================================
 */

import { CLUSTER_STATES, TIME_WINDOWS_MS } from "../constants/index.js";
import { evaluateCorrelationRules } from "./rules/index.js";
import { createCorrelationCluster } from "./correlationCluster.js";
import { memoryClusterRepository } from "./clusterRepository.js";
import { riskEngine } from "./riskEngine.js";
import { qualificationEngine } from "./qualificationEngine.js";
import { entityRegistry } from "./entityRegistry.js";

export class CorrelationEngine {
  constructor() {
    this.windowMs = TIME_WINDOWS_MS.WINDOW_5M; // Default 5 minute sliding window
    this.slidingBuffer = [];
  }

  setWindowMs(ms) {
    this.windowMs = ms;
  }

  clearSession() {
    this.slidingBuffer = [];
    entityRegistry.clear();
  }

  getEventsWithinWindow(windowMs = this.windowMs) {
    const now = Date.now();
    return this.slidingBuffer.filter(e => (now - e.timestamp) <= windowMs);
  }

  /**
   * Processes a context item in the correlation engine.
   */
  process(context) {
    if (!context || !context.enrichedEvent) return context;

    const event = context.enrichedEvent;
    const now = Date.now();

    // 0. Register event in Entity Registry
    entityRegistry.registerEventEntities(event);

    // Add event to sliding buffer and prune expired events
    this.slidingBuffer.push(event);
    this.slidingBuffer = this.slidingBuffer.filter(e => (now - e.timestamp) <= TIME_WINDOWS_MS.WINDOW_30M);

    const activeEvents = this.getEventsWithinWindow(this.windowMs);
    const hostname = event.asset?.hostname || "WORKSTATION-01";

    // 1. Evaluate Rule Match or Single-Event Critical Detection
    let match = evaluateCorrelationRules(activeEvents);

    if (!match && context.detectionResult?.triggered) {
      const det = context.detectionResult;
      match = {
        rule: {
          ruleId: det.ruleId,
          ruleName: det.ruleName,
          severity: det.severity,
          riskWeight: det.confidence,
          mitreMapping: det.mitreTechnique
        },
        reason: `Single-event critical detection: ${det.ruleName}`,
        events: [event]
      };
    }

    if (!match) {
      context.correlationResult = null;
      return context;
    }

    const { rule, reason, events: matchedEvents } = match;

    // 2. Check repository for existing active cluster (Deduplication)
    let cluster = event.campaignId 
      ? memoryClusterRepository.findActiveByCampaign(event.campaignId)
      : memoryClusterRepository.findActiveByRuleAndAsset(rule.ruleId, hostname);

    if (cluster) {
      // Append event to existing cluster (Deduplication)
      if (!cluster.eventIds.includes(event.eventId)) {
        cluster.eventIds.push(event.eventId);
        cluster.events.push(event);
        cluster.eventCount = cluster.events.length;
        cluster.status = cluster.incidentQualified ? CLUSTER_STATES.INCIDENT_CREATED : CLUSTER_STATES.CORRELATING;
      }
    } else {
      // Create new cluster in OPEN state
      cluster = createCorrelationCluster({
        ruleId: rule.ruleId,
        ruleName: rule.ruleName,
        correlationReason: reason,
        eventIds: matchedEvents.map(e => e.eventId),
        events: [...matchedEvents],
        primaryAsset: hostname,
        primaryUser: event.user?.username || "user.account",
        campaignId: event.campaignId || null,
        campaignName: event.campaignName || null,
        status: CLUSTER_STATES.OPEN,

        eventConfidence: event.confidence || 80,
        correlationConfidence: rule.riskWeight || 85
      });
    }

    // Bind Cluster to Entity Registry
    if (hostname) entityRegistry.linkClusterToEntity("Host", hostname, cluster.clusterId);
    if (event.user?.username) entityRegistry.linkClusterToEntity("User", event.user.username, cluster.clusterId);

    // 3. Compute Risk Score & Dynamic Hypothesis Confidence Progression
    const riskData = riskEngine.calculateRisk(cluster);
    cluster.riskScore = riskData.riskScore;
    cluster.severity = riskData.severity;

    // Calculate Hypothesis Confidence (Possible 41% -> Likely 68% -> Confirmed 94%)
    const rawHypoConf = Math.min(96, Math.round((cluster.eventCount * 18) + (cluster.riskScore * 0.5)));
    cluster.hypothesisConfidence = rawHypoConf;
    if (rawHypoConf >= 85) {
      cluster.hypothesisLabel = `Confirmed Threat Hypothesis (${rawHypoConf}%)`;
    } else if (rawHypoConf >= 60) {
      cluster.hypothesisLabel = `Likely Threat Hypothesis (${rawHypoConf}%)`;
    } else {
      cluster.hypothesisLabel = `Possible Threat Hypothesis (${rawHypoConf}%)`;
    }

    // Emergent Campaign Inference
    if (cluster.eventCount >= 3 && !cluster.campaignName) {
      cluster.campaignName = `Emergent Threat Pattern (${cluster.ruleName})`;
    }

    // 4. Evaluate Incident Qualification
    const qualDecision = qualificationEngine.shouldCreateIncident(cluster);
    cluster.qualificationReason = qualDecision.reason;

    // Build Correlation Explainability Array
    const assetCrit = event.asset?.criticality || "standard";
    cluster.explanation = [
      `Matched ${rule.ruleId} (${rule.ruleName})`,
      `${cluster.eventCount} related event(s) correlated via Entity Registry`,
      `Hypothesis Confidence: ${cluster.hypothesisLabel}`,
      `Primary Endpoint: ${hostname} (Asset Criticality: ${assetCrit})`,
      `Risk Score: ${cluster.riskScore}/100 | Initial Severity Input: ${rule.severity || "medium"}`,
      `Qualification Status: ${qualDecision.qualified ? "QUALIFIED" : "SUPPRESSED"} (${qualDecision.reason})`
    ];

    if (qualDecision.qualified && !cluster.incidentQualified) {
      cluster.status = CLUSTER_STATES.QUALIFIED;
      cluster.incidentQualified = true;
      cluster.incidentConfidence = Math.min(100, Math.round((cluster.eventConfidence + cluster.correlationConfidence) / 2) + 5);
    } else if (!qualDecision.qualified && !cluster.incidentQualified) {
      cluster.status = CLUSTER_STATES.SUPPRESSED;
    }

    // Save cluster to repository
    memoryClusterRepository.save(cluster);

    context.correlationResult = {
      clusterId: cluster.clusterId,
      ruleId: cluster.ruleId,
      ruleName: cluster.ruleName,
      status: cluster.status,
      cluster
    };

    context.riskResult = {
      riskScore: cluster.riskScore,
      severity: cluster.severity
    };

    context.qualificationResult = qualDecision;

    return context;
  }
}

export const correlationEngine = new CorrelationEngine();

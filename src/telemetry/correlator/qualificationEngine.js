/**
 * ======================================================================
 * EXPLAINSEC PHASE 2 — INCIDENT QUALIFICATION LAYER
 * ======================================================================
 * Determines if a CorrelationCluster qualifies for incident creation.
 * ======================================================================
 */

import { QUALIFICATION_THRESHOLDS, SEVERITIES } from "../constants/index.js";

export class QualificationEngine {
  /**
   * Evaluates if a cluster qualifies to trigger an incident.
   *
   * @param {Object} cluster - CorrelationCluster
   * @returns {Object} Qualification decision { qualified: boolean, reason: string }
   */
  shouldCreateIncident(cluster) {
    if (!cluster) return { qualified: false, reason: "No cluster provided" };

    // 1. Single Critical Alert Exception
    if (cluster.severity === SEVERITIES.CRITICAL && (cluster.eventConfidence >= 90 || cluster.riskScore >= 75)) {
      return {
        qualified: true,
        reason: `Single critical severity detection (${cluster.ruleName}) crossed threshold.`
      };
    }

    // 2. Active Campaign Qualification
    if (cluster.campaignId && cluster.eventCount >= 2) {
      return {
        qualified: true,
        reason: `Multi-stage attack campaign activity (${cluster.campaignName}) qualified.`
      };
    }

    // 3. Risk Score Threshold
    if (cluster.riskScore >= QUALIFICATION_THRESHOLDS.MIN_RISK_SCORE) {
      return {
        qualified: true,
        reason: `Cluster risk score (${cluster.riskScore}/100) exceeded qualification threshold (${QUALIFICATION_THRESHOLDS.MIN_RISK_SCORE}).`
      };
    }

    // 4. Benign / Noise Suppression
    return {
      qualified: false,
      reason: `Cluster risk score (${cluster.riskScore}) below qualification threshold (${QUALIFICATION_THRESHOLDS.MIN_RISK_SCORE}). Noise suppressed.`
    };
  }
}

export const qualificationEngine = new QualificationEngine();

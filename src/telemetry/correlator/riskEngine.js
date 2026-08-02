/**
 * ======================================================================
 * EXPLAINSEC PHASE 2 — RISK SCORING ENGINE
 * ======================================================================
 * Calculates deterministic weighted risk scores (0-100) for clusters.
 * ======================================================================
 */

import { SEVERITIES } from "../constants/index.js";

export class RiskEngine {
  /**
   * Computes a deterministic 0-100 risk score for a correlation cluster.
   */
  calculateRisk(cluster) {
    if (!cluster) return { riskScore: 0, severity: SEVERITIES.LOW };

    let score = 0;

    // 1. Severity Weight (Base: up to 35 pts)
    const events = cluster.events || [];
    let maxSevWeight = 10;
    for (const evt of events) {
      if (evt.severity === SEVERITIES.CRITICAL) maxSevWeight = Math.max(maxSevWeight, 35);
      else if (evt.severity === SEVERITIES.HIGH) maxSevWeight = Math.max(maxSevWeight, 25);
      else if (evt.severity === SEVERITIES.MEDIUM) maxSevWeight = Math.max(maxSevWeight, 15);
    }
    score += maxSevWeight;

    // 2. Event Count Weight (up to 20 pts)
    const countWeight = Math.min(20, (events.length || 1) * 5);
    score += countWeight;

    // 3. Asset Criticality Weight (up to 15 pts)
    const primaryAssetCrit = cluster.asset?.criticality || cluster.primaryAssetObj?.criticality;
    if (primaryAssetCrit === "critical") score += 15;
    else if (primaryAssetCrit === "high") score += 10;
    else score += 5;

    // 4. Campaign Association Weight (10 pts)
    if (cluster.campaignId) score += 10;

    // 5. MITRE Progression Weight (up to 20 pts)
    const mitreTactics = new Set(events.map(e => e.mitreTechnique?.tactic || e.category).filter(Boolean));
    const progressionWeight = Math.min(20, mitreTactics.size * 7);
    score += progressionWeight;

    // Clamp score to range [0, 100]
    const riskScore = Math.min(100, Math.max(0, Math.round(score)));

    // Derive Severity from Risk Score
    let severity = SEVERITIES.LOW;
    if (riskScore >= 75 || maxSevWeight === 35) severity = SEVERITIES.CRITICAL;
    else if (riskScore >= 50) severity = SEVERITIES.HIGH;
    else if (riskScore >= 30) severity = SEVERITIES.MEDIUM;

    return {
      riskScore,
      severity
    };
  }
}

export const riskEngine = new RiskEngine();

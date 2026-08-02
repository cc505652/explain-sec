/**
 * ======================================================================
 * EXPLAINSEC PHASE 2 — DETECTION ENGINE
 * ======================================================================
 * Evaluates single-event critical detection rules before correlation.
 * ======================================================================
 */

import { evaluateDetectionRules } from "./rules/index.js";

export class DetectionEngine {
  /**
   * Evaluates an enriched event against single-event detection rules.
   */
  evaluate(context) {
    if (!context || !context.enrichedEvent) return context;

    const match = evaluateDetectionRules(context.enrichedEvent);
    if (match && match.matched) {
      context.detectionResult = {
        triggered: true,
        ruleId: match.ruleId,
        ruleName: match.ruleName,
        category: match.category,
        severity: match.severity,
        confidence: match.confidence,
        mitreTechnique: match.mitreTechnique
      };
    } else {
      context.detectionResult = {
        triggered: false,
        ruleId: null
      };
    }

    return context;
  }
}

export const detectionEngine = new DetectionEngine();

/**
 * Classification Engine Layer
 */

export class ClassificationEngine {
  /**
   * Classifies an enriched SecurityEvent.
   */
  classify(event) {
    if (!event) return null;

    let baseScore = event.confidence || 50;

    // Severity weighting
    switch (event.severity) {
      case "critical": baseScore += 35; break;
      case "high": baseScore += 25; break;
      case "medium": baseScore += 10; break;
      case "low": baseScore += 0; break;
    }

    // Asset criticality weighting
    if (event.asset?.criticality === "critical") baseScore += 15;
    else if (event.asset?.criticality === "high") baseScore += 10;

    // Threat classification map
    const urgency = baseScore >= 85 ? "critical" : (baseScore >= 65 ? "high" : (baseScore >= 45 ? "medium" : "low"));

    return {
      ...event,
      eventStatus: "classified",
      classification: {
        compositeScore: Math.min(100, baseScore),
        urgency,
        tactic: event.mitreTechnique?.tactic || "Execution",
        techniqueId: event.mitreTechnique?.id || "T1059",
        threatCategory: event.category || "execution"
      }
    };
  }
}

export const classificationEngine = new ClassificationEngine();

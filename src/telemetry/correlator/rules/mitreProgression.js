import { SEVERITIES, TIME_WINDOWS_MS } from "../../constants/index.js";

export const mitreProgressionRule = {
  ruleId: "RULE-MITRE-PROGRESS",
  ruleName: "MITRE ATT&CK Multi-Tactic Progression",
  description: "Correlates telemetry events spanning 3 or more distinct MITRE tactics on the same endpoint.",
  enabled: true,
  windowMs: TIME_WINDOWS_MS.WINDOW_10M,
  minimumEvents: 3,
  dimensions: ["asset.hostname"],
  severity: SEVERITIES.CRITICAL,
  riskWeight: 94,
  mitreMapping: { id: "T1059", name: "Multi-Tactic Execution Chain", tactic: "Execution" },

  match(events) {
    if (!events || events.length < 3) return null;
    const tactics = new Set(events.map(e => e.mitreTechnique?.tactic || e.category).filter(Boolean));
    if (tactics.size >= 3) {
      return {
        matched: true,
        reason: `Multi-tactic attack chain progression (${tactics.size} tactics) observed on ${events[0].asset?.hostname}`,
        events
      };
    }
    return null;
  }
};

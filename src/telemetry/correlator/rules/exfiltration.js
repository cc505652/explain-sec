import { SEVERITIES, CATEGORIES, TIME_WINDOWS_MS } from "../../constants/index.js";

export const exfiltrationChainRule = {
  ruleId: "RULE-EXFIL-CHAIN",
  ruleName: "Data Exfiltration Activity Detected",
  description: "Correlates archive staging followed by DNS tunneling or large encrypted HTTPS outbound data transfer.",
  enabled: true,
  windowMs: TIME_WINDOWS_MS.WINDOW_10M,
  minimumEvents: 1,
  dimensions: ["asset.hostname"],
  severity: SEVERITIES.CRITICAL,
  riskWeight: 93,
  mitreMapping: { id: "T1048.003", name: "Exfiltration Over Alternative Protocol", tactic: "Exfiltration" },

  match(events) {
    if (!events || events.length < 1) return null;
    const exfilEvents = events.filter(e => e.category === CATEGORIES.EXFILTRATION || (e.description || "").toLowerCase().includes("exfiltration") || (e.description || "").toLowerCase().includes("dns tunnel"));
    if (exfilEvents.length >= 1) {
      return {
        matched: true,
        reason: `Data exfiltration activity detected from ${exfilEvents[0].asset?.hostname}`,
        events: exfilEvents
      };
    }
    return null;
  }
};

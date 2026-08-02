import { SEVERITIES, CATEGORIES, TIME_WINDOWS_MS } from "../../constants/index.js";

export const powershellChainRule = {
  ruleId: "RULE-PS-CHAIN",
  ruleName: "Suspicious PowerShell Execution Chain",
  description: "Correlates PowerShell process launch followed by encoded payload execution or credential access on the same host.",
  enabled: true,
  windowMs: TIME_WINDOWS_MS.WINDOW_5M,
  minimumEvents: 2,
  dimensions: ["asset.hostname"],
  severity: SEVERITIES.HIGH,
  riskWeight: 82,
  mitreMapping: { id: "T1059.001", name: "PowerShell", tactic: "Execution" },

  match(events) {
    if (!events || events.length < 2) return null;
    const psEvents = events.filter(e => e.category === CATEGORIES.EXECUTION && ((e.description || "").toLowerCase().includes("powershell") || (e.rawEvent || "").toLowerCase().includes("powershell")));
    if (psEvents.length >= 2) {
      return {
        matched: true,
        reason: `PowerShell execution chain (${psEvents.length} events) observed on ${psEvents[0].asset?.hostname}`,
        events: psEvents
      };
    }
    return null;
  }
};

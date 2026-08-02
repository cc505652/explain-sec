import { SEVERITIES, CATEGORIES, TIME_WINDOWS_MS } from "../../constants/index.js";

export const c2BeaconingRule = {
  ruleId: "RULE-C2-BEACON",
  ruleName: "Command & Control Beaconing Activity",
  description: "Correlates repeated outbound connections to external destination IP matching C2 profile.",
  enabled: true,
  windowMs: TIME_WINDOWS_MS.WINDOW_10M,
  minimumEvents: 1,
  dimensions: ["network.destIp"],
  severity: SEVERITIES.CRITICAL,
  riskWeight: 90,
  mitreMapping: { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },

  match(events) {
    if (!events || events.length < 1) return null;
    const c2Events = events.filter(e => e.category === CATEGORIES.COMMAND_AND_CONTROL || (e.description || "").toLowerCase().includes("beacon") || (e.description || "").toLowerCase().includes("reverse shell"));
    if (c2Events.length >= 1) {
      return {
        matched: true,
        reason: `Command & Control beaconing pattern observed from ${c2Events[0].asset?.hostname} to external C2`,
        events: c2Events
      };
    }
    return null;
  }
};

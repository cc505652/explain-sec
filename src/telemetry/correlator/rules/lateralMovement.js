import { SEVERITIES, CATEGORIES, TIME_WINDOWS_MS } from "../../constants/index.js";

export const lateralMovementRule = {
  ruleId: "RULE-LATERAL-MOVE",
  ruleName: "Lateral Movement Across Systems",
  description: "Correlates credential access followed by PsExec, SMB, WMI, or RDP connections to secondary internal hosts.",
  enabled: true,
  windowMs: TIME_WINDOWS_MS.WINDOW_10M,
  minimumEvents: 1,
  dimensions: ["user.username", "asset.ip"],
  severity: SEVERITIES.HIGH,
  riskWeight: 85,
  mitreMapping: { id: "T1021.002", name: "SMB/Windows Admin Shares", tactic: "Lateral Movement" },

  match(events) {
    if (!events || events.length < 1) return null;
    const latEvents = events.filter(e => e.category === CATEGORIES.LATERAL_MOVEMENT || (e.description || "").toLowerCase().includes("psexec") || (e.description || "").toLowerCase().includes("wmi remote"));
    if (latEvents.length >= 1) {
      return {
        matched: true,
        reason: `Lateral movement activity detected originating from ${latEvents[0].asset?.hostname}`,
        events: latEvents
      };
    }
    return null;
  }
};

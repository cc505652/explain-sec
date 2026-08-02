import { SEVERITIES, CATEGORIES, TIME_WINDOWS_MS } from "../../constants/index.js";

export const credentialDumpingRule = {
  ruleId: "RULE-CRED-DUMP",
  ruleName: "Credential Dumping Sequence Detected",
  description: "Correlates process handle access to LSASS, memory dumping, or Mimikatz execution on the same endpoint.",
  enabled: true,
  windowMs: TIME_WINDOWS_MS.WINDOW_5M,
  minimumEvents: 1,
  dimensions: ["asset.hostname"],
  severity: SEVERITIES.CRITICAL,
  riskWeight: 92,
  mitreMapping: { id: "T1003.001", name: "LSASS Memory Dumping", tactic: "Credential Access" },

  match(events) {
    if (!events || events.length < 1) return null;
    const credEvents = events.filter(e => (e.description || "").toLowerCase().includes("lsass") || (e.description || "").toLowerCase().includes("kerberoast"));
    if (credEvents.length >= 1) {
      return {
        matched: true,
        reason: `LSASS process memory access and credential dump sequence detected on ${credEvents[0].asset?.hostname}`,
        events: credEvents
      };
    }
    return null;
  }
};

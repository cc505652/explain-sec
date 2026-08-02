import { SEVERITIES, CATEGORIES, TIME_WINDOWS_MS } from "../../constants/index.js";

export const persistenceChainRule = {
  ruleId: "RULE-PERSIST-CHAIN",
  ruleName: "Persistence Installation Chain",
  description: "Correlates execution followed by scheduled task creation, registry autorun key modification, or service installation.",
  enabled: true,
  windowMs: TIME_WINDOWS_MS.WINDOW_10M,
  minimumEvents: 2,
  dimensions: ["asset.hostname"],
  severity: SEVERITIES.HIGH,
  riskWeight: 80,
  mitreMapping: { id: "T1053", name: "Scheduled Task/Job", tactic: "Persistence" },

  match(events) {
    if (!events || events.length < 2) return null;
    const persistEvents = events.filter(e => e.category === CATEGORIES.PERSISTENCE || (e.description || "").toLowerCase().includes("scheduled task") || (e.description || "").toLowerCase().includes("service"));
    if (persistEvents.length >= 2) {
      return {
        matched: true,
        reason: `Persistence installation chain (${persistEvents.length} events) detected on ${persistEvents[0].asset?.hostname}`,
        events: persistEvents
      };
    }
    return null;
  }
};

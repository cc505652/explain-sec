import { SEVERITIES, TIME_WINDOWS_MS } from "../../constants/index.js";

export const campaignCorrelationRule = {
  ruleId: "RULE-CAMPAIGN-CHAIN",
  ruleName: "Multi-Stage Attack Campaign Activity",
  description: "Correlates telemetry events sharing campaignId into a campaign correlation cluster.",
  enabled: true,
  windowMs: TIME_WINDOWS_MS.WINDOW_30M,
  minimumEvents: 2,
  dimensions: ["campaignId"],
  severity: SEVERITIES.HIGH,
  riskWeight: 88,
  mitreMapping: { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" },

  match(events) {
    if (!events || events.length < 2) return null;
    const campaignEvents = events.filter(e => Boolean(e.campaignId));
    if (campaignEvents.length >= 2) {
      const campaignName = campaignEvents[0].campaignName || "Attack Campaign";
      return {
        matched: true,
        reason: `Multi-stage campaign activity (${campaignEvents.length} events) correlated for ${campaignName}`,
        events: campaignEvents
      };
    }
    return null;
  }
};

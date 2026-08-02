import { authenticationRules } from "./authentication.js";
import { powershellChainRule } from "./powershell.js";
import { credentialDumpingRule } from "./credentialDumping.js";
import { persistenceChainRule } from "./persistence.js";
import { lateralMovementRule } from "./lateralMovement.js";
import { c2BeaconingRule } from "./beaconing.js";
import { exfiltrationChainRule } from "./exfiltration.js";
import { campaignCorrelationRule } from "./campaigns.js";
import { mitreProgressionRule } from "./mitreProgression.js";

export const CORRELATION_RULES = [
  ...authenticationRules,
  powershellChainRule,
  credentialDumpingRule,
  persistenceChainRule,
  lateralMovementRule,
  c2BeaconingRule,
  exfiltrationChainRule,
  campaignCorrelationRule,
  mitreProgressionRule
];

export function evaluateCorrelationRules(events) {
  if (!events || events.length === 0) return null;
  for (const rule of CORRELATION_RULES) {
    if (!rule.enabled) continue;
    const matchResult = rule.match(events);
    if (matchResult && matchResult.matched) {
      return {
        rule,
        ...matchResult
      };
    }
  }
  return null;
}

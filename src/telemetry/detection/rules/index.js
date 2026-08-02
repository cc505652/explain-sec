import { ransomwareRule } from "./ransomware.js";
import { lsassDumpRule } from "./lsassDump.js";
import { powershellRule } from "./powershell.js";
import { suspiciousServiceRule } from "./suspiciousService.js";
import { encodedCommandRule } from "./encodedCommand.js";

export const DETECTION_RULES = [
  ransomwareRule,
  lsassDumpRule,
  powershellRule,
  suspiciousServiceRule,
  encodedCommandRule
];

export function evaluateDetectionRules(event) {
  if (!event) return null;
  for (const rule of DETECTION_RULES) {
    if (rule.match(event)) {
      return {
        matched: true,
        ruleId: rule.ruleId,
        ruleName: rule.ruleName,
        category: rule.category,
        severity: rule.severity,
        confidence: rule.confidence,
        mitreTechnique: rule.mitreTechnique
      };
    }
  }
  return null;
}

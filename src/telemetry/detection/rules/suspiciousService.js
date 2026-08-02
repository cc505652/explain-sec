import { SEVERITIES, CATEGORIES } from "../../constants/index.js";

export const suspiciousServiceRule = {
  ruleId: "DET-SERVICE-01",
  ruleName: "Unsigned Windows System Service Installation",
  category: CATEGORIES.PERSISTENCE,
  severity: SEVERITIES.HIGH,
  confidence: 88,
  mitreTechnique: { id: "T1543.003", name: "Windows Service", tactic: "Persistence" },
  
  match(event) {
    if (!event) return false;
    const desc = (event.description || "").toLowerCase();
    const raw = (event.rawEvent || "").toLowerCase();
    return desc.includes("service installed") || raw.includes("7045") || raw.includes("psexesvc");
  }
};

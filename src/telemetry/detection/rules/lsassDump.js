import { SEVERITIES, CATEGORIES } from "../../constants/index.js";

export const lsassDumpRule = {
  ruleId: "DET-LSASS-DUMP-01",
  ruleName: "LSASS Process Memory Dump Attempt",
  category: CATEGORIES.CREDENTIAL_ACCESS,
  severity: SEVERITIES.CRITICAL,
  confidence: 95,
  mitreTechnique: { id: "T1003.001", name: "LSASS Memory Dumping", tactic: "Credential Access" },
  
  match(event) {
    if (!event) return false;
    const desc = (event.description || "").toLowerCase();
    const raw = (event.rawEvent || "").toLowerCase();
    return desc.includes("lsass") || raw.includes("lsass.exe") || desc.includes("mimikatz");
  }
};

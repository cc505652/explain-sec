import { SEVERITIES, CATEGORIES } from "../../constants/index.js";

export const ransomwareRule = {
  ruleId: "DET-RANSOMWARE-01",
  ruleName: "Ransomware File Encryption Activity",
  category: CATEGORIES.EXECUTION,
  severity: SEVERITIES.CRITICAL,
  confidence: 96,
  mitreTechnique: { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact" },
  
  match(event) {
    if (!event) return false;
    const desc = (event.description || "").toLowerCase();
    const raw = (event.rawEvent || "").toLowerCase();
    return desc.includes("ransomware") || desc.includes("vssadmin delete shadows") || raw.includes("vssadmin");
  }
};

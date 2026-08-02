import { SEVERITIES, CATEGORIES } from "../../constants/index.js";

export const powershellRule = {
  ruleId: "DET-POWERSHELL-01",
  ruleName: "Suspicious PowerShell Execution",
  category: CATEGORIES.EXECUTION,
  severity: SEVERITIES.HIGH,
  confidence: 90,
  mitreTechnique: { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
  
  match(event) {
    if (!event) return false;
    const desc = (event.description || "").toLowerCase();
    const raw = (event.rawEvent || "").toLowerCase();
    return desc.includes("powershell") || raw.includes("powershell.exe");
  }
};

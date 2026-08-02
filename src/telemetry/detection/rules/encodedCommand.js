import { SEVERITIES, CATEGORIES } from "../../constants/index.js";

export const encodedCommandRule = {
  ruleId: "DET-ENCODED-01",
  ruleName: "Encoded Base64 Command Payload",
  category: CATEGORIES.EXECUTION,
  severity: SEVERITIES.HIGH,
  confidence: 91,
  mitreTechnique: { id: "T1027", name: "Obfuscated Files or Information", tactic: "Defense Evasion" },
  
  match(event) {
    if (!event) return false;
    const raw = (event.rawEvent || "").toLowerCase();
    return raw.includes("-enc") || raw.includes("-encodedcommand") || raw.includes("base64");
  }
};

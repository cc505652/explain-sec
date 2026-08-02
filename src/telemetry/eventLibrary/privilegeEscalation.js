/**
 * Privilege Escalation Event Templates (MITRE Tactic: Privilege Escalation - TA0004)
 */

export const privilegeEscalationTemplates = [
  {
    templateId: "PRIV_TOKEN_IMPERSONATE_01",
    name: "Token Impersonation Attempt",
    source: "DefenderForEndpoint",
    provider: "Microsoft",
    product: "Defender EDR",
    category: "privilege_escalation",
    severity: "critical",
    confidence: 94,
    mitreTechnique: {
      id: "T1134.001",
      name: "Token Impersonation/Theft",
      tactic: "Privilege Escalation"
    },
    detectionRule: {
      ruleId: "RULE-TOKEN-STEAL-01",
      ruleName: "SYSTEM Token Impersonation via DuplicateTokenEx",
      mitreId: "T1134.001",
      threshold: "Process token duplicate to SYSTEM security context",
      confidence: 94,
      ruleVersion: "1.6",
      author: "ExplainSec Threat Intel"
    },
    description: "Standard user process elevated to SYSTEM token context via token duplication API",
    rawEvent: JSON.stringify({
      EventID: 4672,
      PrivilegeList: "SeDebugPrivilege, SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege",
      SubjectUserName: "j.doe",
      TargetUserName: "SYSTEM"
    })
  },
  {
    templateId: "PRIV_UAC_BYPASS_01",
    name: "UAC Bypass via Fodhelper",
    source: "CrowdStrikeFalcon",
    provider: "CrowdStrike",
    product: "Falcon EDR",
    category: "privilege_escalation",
    severity: "high",
    confidence: 91,
    mitreTechnique: {
      id: "T1548.002",
      name: "Bypass User Account Control",
      tactic: "Privilege Escalation"
    },
    detectionRule: {
      ruleId: "RULE-UAC-FODHELPER-01",
      ruleName: "Registry Modification in HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command",
      mitreId: "T1548.002",
      threshold: "fodhelper.exe spawned with high integrity token",
      confidence: 91,
      ruleVersion: "2.1",
      author: "ExplainSec Detection Engineering"
    },
    description: "User Account Control bypass executed via fodhelper registry hijack to launch high integrity prompt",
    rawEvent: JSON.stringify({
      ImageFileName: "fodhelper.exe",
      IntegrityLevel: "High Integrity",
      ParentImage: "cmd.exe"
    })
  }
];

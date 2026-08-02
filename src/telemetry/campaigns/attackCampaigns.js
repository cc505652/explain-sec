/**
 * Pre-built Multi-Stage Attack Campaign Scenarios
 */

export const PREBUILT_ATTACK_CAMPAIGNS = [
  {
    campaignId: "cmp_apt29_cred_theft",
    name: "APT29 Credential Theft & Lateral Movement",
    threatActor: "Cozy Bear (APT29)",
    description: "Multi-stage intrusion involving reconnaissance, encoded PowerShell execution, LSASS memory dumping, and PsExec lateral movement targeting domain controllers.",
    steps: [
      { stepIndex: 1, tactic: "discovery", templateId: "DISC_PORT_SCAN_01", stageName: "Network Reconnaissance" },
      { stepIndex: 2, tactic: "execution", templateId: "EXEC_POWERSHELL_ENCODED_01", stageName: "Encoded PowerShell Dropper" },
      { stepIndex: 3, tactic: "credential_access", templateId: "CRED_LSASS_DUMP_01", stageName: "LSASS Memory Dump" },
      { stepIndex: 4, tactic: "lateral_movement", templateId: "LAT_PSEXEC_SERVICE_01", stageName: "PsExec Admin Share Move" },
      { stepIndex: 5, tactic: "persistence", templateId: "PERSIST_SCHEDULED_TASK_01", stageName: "Scheduled Task Creation" },
      { stepIndex: 6, tactic: "exfiltration", templateId: "EXFIL_HTTPS_OUTBOUND_01", stageName: "Encrypted HTTPS Exfiltration" }
    ]
  },
  {
    campaignId: "cmp_ransomware_precursor",
    name: "Ransomware Pre-Cursor & C2 Beaconing",
    threatActor: "FIN7 / DarkSide Variant",
    description: "Initial payload drop via MSHTA remote execution, UAC bypass, Cobalt Strike C2 beaconing, and DNS tunneling.",
    steps: [
      { stepIndex: 1, tactic: "execution", templateId: "EXEC_MSHTA_PAYLOAD_01", stageName: "MSHTA Remote Payload Drop" },
      { stepIndex: 2, tactic: "privilege_escalation", templateId: "PRIV_UAC_BYPASS_01", stageName: "UAC Fodhelper Bypass" },
      { stepIndex: 3, tactic: "command_and_control", templateId: "C2_COBALT_STRIKE_01", stageName: "Cobalt Strike C2 Beaconing" },
      { stepIndex: 4, tactic: "persistence", templateId: "PERSIST_SERVICE_NEW_01", stageName: "Malicious System Service Install" },
      { stepIndex: 5, tactic: "exfiltration", templateId: "EXFIL_DNS_TUNNEL_01", stageName: "DNS Payload Exfiltration" }
    ]
  }
];

/**
 * Lateral Movement Event Templates (MITRE Tactic: Lateral Movement - TA0008)
 */

export const lateralMovementTemplates = [
  {
    templateId: "LAT_PSEXEC_SERVICE_01",
    name: "PsExec Remote Execution",
    source: "WindowsEventLog",
    provider: "Microsoft",
    product: "System Event Log",
    category: "lateral_movement",
    severity: "high",
    confidence: 93,
    mitreTechnique: {
      id: "T1021.002",
      name: "SMB/Windows Admin Shares",
      tactic: "Lateral Movement"
    },
    detectionRule: {
      ruleId: "RULE-PSEXEC-REMOTE-01",
      ruleName: "PsExec Administrative Share Access & Remote Service",
      mitreId: "T1021.002",
      threshold: "IPC$ share write followed by 7045 PSEXESVC",
      confidence: 93,
      ruleVersion: "2.4",
      author: "ExplainSec Detection Engineering"
    },
    description: "Remote administrative share access (ADMIN$) followed by service execution from workstation to domain controller",
    rawEvent: JSON.stringify({
      EventID: 5140,
      ShareName: "\\\\SERVER-DC01\\ADMIN$",
      IpAddress: "192.168.1.105",
      AccessMask: "0x2"
    })
  },
  {
    templateId: "LAT_WMI_REMOTE_01",
    name: "WMI Remote Process Creation",
    source: "DefenderForEndpoint",
    provider: "Microsoft",
    product: "Defender EDR",
    category: "lateral_movement",
    severity: "high",
    confidence: 89,
    mitreTechnique: {
      id: "T1047",
      name: "Windows Management Instrumentation",
      tactic: "Lateral Movement"
    },
    detectionRule: {
      ruleId: "RULE-WMI-REMOTE-EXEC",
      ruleName: "WMIC Remote Node Process Invocation",
      mitreId: "T1047",
      threshold: "wmiprvse.exe spawning cmd.exe or powershell.exe",
      confidence: 89,
      ruleVersion: "1.7",
      author: "ExplainSec Detection Engineering"
    },
    description: "WMI provider host `wmiprvse.exe` spawned command shell process invoked from remote network node",
    rawEvent: JSON.stringify({
      ParentProcess: "wmiprvse.exe",
      ChildProcess: "cmd.exe",
      CommandLine: "cmd.exe /c powershell.exe -enc ..."
    })
  }
];

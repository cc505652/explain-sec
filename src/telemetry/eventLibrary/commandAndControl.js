/**
 * Command and Control Event Templates (MITRE Tactic: Command and Control - TA0109)
 */

export const commandAndControlTemplates = [
  {
    templateId: "C2_COBALT_STRIKE_01",
    name: "Cobalt Strike Beacon Traffic",
    source: "CrowdStrikeFalcon",
    provider: "CrowdStrike",
    product: "Falcon EDR",
    category: "command_and_control",
    severity: "critical",
    confidence: 96,
    mitreTechnique: {
      id: "T1071.001",
      name: "Application Layer Protocol: Web Protocols",
      tactic: "Command and Control"
    },
    detectionRule: {
      ruleId: "RULE-C2-COBALT-BEACON",
      ruleName: "Cobalt Strike Malleable C2 Beaconing Pattern",
      mitreId: "T1071.001",
      threshold: "Jittered HTTP GET requests matching Cobalt Strike URI profile",
      confidence: 96,
      ruleVersion: "3.2",
      author: "ExplainSec Threat Intel"
    },
    description: "Memory inspection and beaconing network traffic matched known Cobalt Strike C2 framework profile",
    rawEvent: JSON.stringify({
      ProcessName: "rundll32.exe",
      RemoteIP: "198.51.100.42",
      URI: "/jquery-3.3.1.min.js",
      UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }),
    ioc: {
      type: "ip",
      value: "198.51.100.42",
      description: "Cobalt Strike C2 Server IP"
    }
  },
  {
    templateId: "C2_REVERSE_SHELL_01",
    name: "Outbound Interactive Reverse Shell",
    source: "DefenderForEndpoint",
    provider: "Microsoft",
    product: "Defender EDR",
    category: "command_and_control",
    severity: "high",
    confidence: 90,
    mitreTechnique: {
      id: "T1059",
      name: "Command and Scripting Interpreter",
      tactic: "Command and Control"
    },
    detectionRule: {
      ruleId: "RULE-REV-SHELL-01",
      ruleName: "cmd.exe Connected to Outbound Non-Standard Port",
      mitreId: "T1059",
      threshold: "cmd.exe / powershell.exe with active socket to port 4444",
      confidence: 90,
      ruleVersion: "1.5",
      author: "ExplainSec Detection Engineering"
    },
    description: "Command prompt process maintaining persistent interactive network connection to external port 4444",
    rawEvent: JSON.stringify({
      ProcessName: "cmd.exe",
      DestPort: 4444,
      RemoteAddress: "198.51.100.42"
    })
  }
];

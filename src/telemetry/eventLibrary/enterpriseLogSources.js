/**
 * ======================================================================
 * EXPLAINSEC PHASE 2 — ENTERPRISE LOG SOURCES LIBRARY
 * ======================================================================
 * 23+ Enterprise Log Providers and Benign Telemetry Templates.
 * ======================================================================
 */

export const ENTERPRISE_PROVIDERS = {
  WindowsSecurity: { source: "WindowsEventLog", provider: "Microsoft", product: "Windows Security Event Log", icon: "🪟" },
  Sysmon: { source: "Sysmon", provider: "Microsoft Sysinternals", product: "System Monitor", icon: "🪟" },
  DefenderForEndpoint: { source: "DefenderForEndpoint", provider: "Microsoft", product: "Defender EDR", icon: "🛡️" },
  CrowdStrikeFalcon: { source: "CrowdStrikeFalcon", provider: "CrowdStrike", product: "Falcon Sensor", icon: "🦅" },
  SentinelOne: { source: "SentinelOne", provider: "SentinelOne", product: "Singularity Agent", icon: "⚡" },
  EntraID: { source: "AzureAD", provider: "Microsoft", product: "Entra ID (Azure AD)", icon: "☁️" },
  DefenderForIdentity: { source: "DefenderForIdentity", provider: "Microsoft", product: "MDI Sensor", icon: "🛡️" },
  ActiveDirectoryDS: { source: "ActiveDirectory", provider: "Microsoft", product: "AD Domain Services", icon: "🪟" },
  AzureActivity: { source: "AzureActivity", provider: "Microsoft Azure", product: "Azure Monitor", icon: "☁️" },
  AzureKeyVault: { source: "AzureKeyVault", provider: "Microsoft Azure", product: "Key Vault Audit", icon: "🔑" },
  AWSCloudTrail: { source: "AWSCloudTrail", provider: "Amazon Web Services", product: "CloudTrail", icon: "☁️" },
  KubernetesAudit: { source: "KubernetesAudit", provider: "CNCF", product: "K8s API Server Audit", icon: "☸️" },
  M365Audit: { source: "M365Audit", provider: "Microsoft", product: "Unified Audit Log", icon: "📧" },
  ExchangeOnline: { source: "ExchangeOnline", provider: "Microsoft", product: "Exchange Protection", icon: "📧" },
  ProofpointEmail: { source: "EmailSecurity", provider: "Proofpoint", product: "Email Protection", icon: "📧" },
  PaloAltoFirewall: { source: "PaloAltoFirewall", provider: "Palo Alto Networks", product: "PAN-OS Firewall", icon: "🌐" },
  FortinetFirewall: { source: "FortinetFirewall", provider: "Fortinet", product: "FortiGate", icon: "🧱" },
  VPN: { source: "VPN", provider: "Cisco / Palo Alto", product: "GlobalProtect VPN Gateway", icon: "🔒" },
  DNSProxy: { source: "DNSProxy", provider: "Infoblox / BIND", product: "Internal DNS Resolver", icon: "🌐" },
  DHCP: { source: "DHCP", provider: "Microsoft", product: "DHCP Server", icon: "🔌" },
  ZscalerProxy: { source: "Proxy", provider: "Zscaler", product: "Internet Access Proxy", icon: "🌐" },
  LinuxSyslog: { source: "LinuxSyslog", provider: "Linux Kernel", product: "rsyslog / auditd", icon: "🐧" },
  WAF: { source: "WebappFirewall", provider: "Cloudflare", product: "WAF Gateway", icon: "🛡️" },
  IDSIPS: { source: "SuricataIDS", provider: "OISF", product: "Suricata NIDS", icon: "🚨" }
};

export const BENIGN_EVENT_TEMPLATES = [
  // 1. Process Executions (Windows / Sysmon)
  {
    providerKey: "WindowsSecurity",
    category: "execution",
    severity: "low",
    confidence: 20,
    description: "Routine process creation: svchost.exe launching background service",
    rawEvent: JSON.stringify({ EventID: 4688, NewProcessName: "C:\\Windows\\System32\\svchost.exe", ParentProcessName: "C:\\Windows\\System32\\services.exe", CommandLine: "svchost.exe -k netsvcs -p" }),
    mitreTechnique: { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" },
    detectionRule: { ruleId: "RULE-BENIGN-4688", ruleName: "Standard System Process Creation", threshold: "1 event" }
  },
  {
    providerKey: "Sysmon",
    category: "execution",
    severity: "low",
    confidence: 25,
    description: "Chrome auto-update helper process execution",
    rawEvent: JSON.stringify({ EventID: 1, Image: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", CommandLine: "--type=utility --utility-sub-type=network.mojom.NetworkService" }),
    mitreTechnique: { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" },
    detectionRule: { ruleId: "RULE-BENIGN-CHROME", ruleName: "Browser Process Execution", threshold: "1 event" }
  },
  {
    providerKey: "DefenderForEndpoint",
    category: "execution",
    severity: "low",
    confidence: 15,
    description: "Windows Defender scheduled quick antivirus scan completed cleanly",
    rawEvent: JSON.stringify({ EventID: 1001, ScanType: "QuickScan", Result: "NoThreatsFound" }),
    mitreTechnique: { id: "T1059", name: "Software Update Routine", tactic: "Execution" },
    detectionRule: { ruleId: "RULE-DEFENDER-SCAN", ruleName: "Antivirus Scheduled Scan", threshold: "1 event" }
  },

  // 2. Identity & Authentication (Entra ID / AD)
  {
    providerKey: "EntraID",
    category: "authentication",
    severity: "low",
    confidence: 10,
    description: "Successful SSO Kerberos interactive logon from corporate IP",
    rawEvent: JSON.stringify({ EventID: 4624, LogonType: 7, AuthenticationPackage: "Negotiate", Result: "Success" }),
    mitreTechnique: { id: "T1078", name: "Valid Accounts", tactic: "Defense Evasion" },
    detectionRule: { ruleId: "RULE-ENTRA-LOGON", ruleName: "Corporate Interactive Logon", threshold: "1 event" }
  },
  {
    providerKey: "ActiveDirectoryDS",
    category: "authentication",
    severity: "low",
    confidence: 10,
    description: "Kerberos TGT ticket requested (Event ID 4768) for domain user",
    rawEvent: JSON.stringify({ EventID: 4768, ServiceName: "krbtgt", TicketOptions: "0x40810010", Status: "0x0" }),
    mitreTechnique: { id: "T1078", name: "Valid Accounts", tactic: "Defense Evasion" },
    detectionRule: { ruleId: "RULE-AD-TGT", ruleName: "Standard TGT Request", threshold: "1 event" }
  },

  // 3. Network & Perimeter (DNS / VPN / Firewall)
  {
    providerKey: "DNSProxy",
    category: "network",
    severity: "low",
    confidence: 10,
    description: "Internal DNS query resolved: microsoft.com A record",
    rawEvent: JSON.stringify({ Query: "login.microsoftonline.com", RecordType: "A", ResponseIP: "20.190.160.71" }),
    mitreTechnique: { id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control" },
    detectionRule: { ruleId: "RULE-DNS-RESOLVE", ruleName: "Corporate DNS Lookup", threshold: "1 event" }
  },
  {
    providerKey: "VPN",
    category: "network",
    severity: "low",
    confidence: 15,
    description: "GlobalProtect VPN session established with MFA validation",
    rawEvent: JSON.stringify({ Event: "VPN_CONNECTED", Protocol: "TLSv1.3", Duration: "08:00:00" }),
    mitreTechnique: { id: "T1078", name: "Valid Accounts", tactic: "Initial Access" },
    detectionRule: { ruleId: "RULE-VPN-CONNECT", ruleName: "Authorized Remote VPN Connect", threshold: "1 event" }
  },
  {
    providerKey: "PaloAltoFirewall",
    category: "network",
    severity: "low",
    confidence: 10,
    description: "Outbound HTTPS traffic session allowed to trusted CDN",
    rawEvent: JSON.stringify({ Action: "allow", Application: "web-browsing", SrcPort: 52140, DstPort: 443 }),
    mitreTechnique: { id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control" },
    detectionRule: { ruleId: "RULE-FW-ALLOW", ruleName: "Allowed Outbound Traffic", threshold: "1 event" }
  },

  // 4. Cloud & Collaboration (M365 / Key Vault / AWS)
  {
    providerKey: "M365Audit",
    category: "cloud",
    severity: "low",
    confidence: 10,
    description: "OneDrive document autosave sync: Quarterly_Report.xlsx",
    rawEvent: JSON.stringify({ Operation: "FileSync", Workload: "OneDrive", UserAgent: "OneDriveSyncEngine" }),
    mitreTechnique: { id: "T1567", name: "Web Service", tactic: "Exfiltration" },
    detectionRule: { ruleId: "RULE-M365-SYNC", ruleName: "Cloud File Sync Operation", threshold: "1 event" }
  },
  {
    providerKey: "AzureKeyVault",
    category: "cloud",
    severity: "low",
    confidence: 20,
    description: "Key Vault secret read operation by authorized service principal",
    rawEvent: JSON.stringify({ OperationName: "SecretGet", ResultType: "Success", CallerIP: "10.0.4.12" }),
    mitreTechnique: { id: "T1552", name: "Unsecured Credentials", tactic: "Credential Access" },
    detectionRule: { ruleId: "RULE-KV-READ", ruleName: "Key Vault Secret Read", threshold: "1 event" }
  },

  // 5. System Administration (Linux / Group Policy / DHCP)
  {
    providerKey: "LinuxSyslog",
    category: "execution",
    severity: "low",
    confidence: 15,
    description: "Cron job executed cleanly: /etc/cron.daily/logrotate",
    rawEvent: JSON.stringify({ Process: "crond", CMD: "/usr/sbin/logrotate /etc/logrotate.conf", Status: "OK" }),
    mitreTechnique: { id: "T1053", name: "Scheduled Task/Job", tactic: "Execution" },
    detectionRule: { ruleId: "RULE-LINUX-CRON", ruleName: "System Log Maintenance", threshold: "1 event" }
  }
];

/**
 * Discovery Event Templates (MITRE Tactic: Discovery - TA0007)
 */

export const discoveryTemplates = [
  {
    templateId: "DISC_PORT_SCAN_01",
    name: "Internal Network Port Scan",
    source: "SuricataIDS",
    provider: "Suricata",
    product: "Network IDS",
    category: "discovery",
    severity: "low",
    confidence: 78,
    mitreTechnique: {
      id: "T1046",
      name: "Network Service Discovery",
      tactic: "Discovery"
    },
    detectionRule: {
      ruleId: "RULE-NET-PORT-SCAN",
      ruleName: "TCP SYN Sweep Across Internal Subnet",
      mitreId: "T1046",
      threshold: ">20 port connection attempts in 10s",
      confidence: 78,
      ruleVersion: "1.0",
      author: "ExplainSec Network Security"
    },
    description: "Rapid TCP port sweep targeting SMB (445), RDP (3389), and WinRM (5985) ports across subnet",
    rawEvent: JSON.stringify({
      SrcIP: "192.168.1.105",
      Subnet: "192.168.1.0/24",
      TargetPorts: [135, 139, 445, 3389, 5985],
      ScanType: "SYN_SWEEP"
    })
  },
  {
    templateId: "DISC_AD_ENUM_01",
    name: "Active Directory Domain Enumeration",
    source: "WindowsEventLog",
    provider: "Microsoft",
    product: "Active Directory",
    category: "discovery",
    severity: "medium",
    confidence: 83,
    mitreTechnique: {
      id: "T1087.002",
      name: "Domain Account Discovery",
      tactic: "Discovery"
    },
    detectionRule: {
      ruleId: "RULE-AD-ENUM-NET-USER",
      ruleName: "Mass Domain Query via net.exe / BloodHound",
      mitreId: "T1087.002",
      threshold: "LDAP query for (objectCategory=person)",
      confidence: 83,
      ruleVersion: "1.2",
      author: "ExplainSec Detection Engineering"
    },
    description: "Domain user account and group membership enumeration via LDAP / BloodHound queries",
    rawEvent: JSON.stringify({
      ProcessName: "net.exe",
      CommandLine: "net.exe group 'Domain Admins' /domain",
      LDAPFilter: "(&(objectCategory=person)(objectClass=user))"
    })
  }
];

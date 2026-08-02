/**
 * Credential Access Event Templates (MITRE Tactic: Credential Access - TA0006)
 */

export const credentialAccessTemplates = [
  {
    templateId: "CRED_PASS_SPRAY_01",
    name: "Password Spraying Detection",
    source: "WindowsEventLog",
    provider: "Microsoft",
    product: "Active Directory Domain Controller",
    category: "credential_access",
    severity: "medium",
    confidence: 85,
    mitreTechnique: {
      id: "T1110.003",
      name: "Password Spraying",
      tactic: "Credential Access"
    },
    detectionRule: {
      ruleId: "RULE-AD-PASS-SPRAY",
      ruleName: "Multiple Failed Logins Across Accounts",
      mitreId: "T1110.003",
      threshold: "5 failed logins within 60s",
      confidence: 85,
      ruleVersion: "2.1",
      author: "ExplainSec Detection Engineering"
    },
    description: "Multiple failed authentication attempts detected across multiple user accounts from a single IP",
    rawEvent: JSON.stringify({
      EventID: 4625,
      Status: "0xC000006D",
      SubStatus: "0xC000006A",
      LogonType: 3,
      WorkstationName: "EXTERNAL-ATTACK-NODE"
    })
  },
  {
    templateId: "CRED_KERBEROAST_01",
    name: "Kerberoasting Ticket Request",
    source: "WindowsEventLog",
    provider: "Microsoft",
    product: "Active Directory",
    category: "credential_access",
    severity: "high",
    confidence: 90,
    mitreTechnique: {
      id: "T1558.003",
      name: "Kerberoasting",
      tactic: "Credential Access"
    },
    detectionRule: {
      ruleId: "RULE-KERB-ROAST-01",
      ruleName: "RC4 Kerberos Ticket Request for SPN Account",
      mitreId: "T1558.003",
      threshold: "TGS request with TicketEncryptionType 0x17",
      confidence: 90,
      ruleVersion: "1.8",
      author: "ExplainSec Detection Engineering"
    },
    description: "Suspicious Kerberos TGS request for service principal account using weak RC4 encryption",
    rawEvent: JSON.stringify({
      EventID: 4769,
      TicketOptions: "0x40810000",
      TicketEncryptionType: "0x17",
      ServiceName: "MSSQLSvc/db01.campus.edu"
    })
  },
  {
    templateId: "CRED_LSASS_DUMP_01",
    name: "LSASS Process Memory Access",
    source: "DefenderForEndpoint",
    provider: "Microsoft",
    product: "Defender EDR",
    category: "credential_access",
    severity: "critical",
    confidence: 95,
    mitreTechnique: {
      id: "T1003.001",
      name: "LSASS Memory Dumping",
      tactic: "Credential Access"
    },
    detectionRule: {
      ruleId: "RULE-LSASS-DUMP-001",
      ruleName: "LSASS Memory Dumping via Direct Handle Open",
      mitreId: "T1003.001",
      threshold: "Process access with PROCESS_VM_READ (0x0010)",
      confidence: 95,
      ruleVersion: "3.0",
      author: "ExplainSec Threat Intel"
    },
    description: "Unsigned process attempted to read LSASS memory space to extract cleartext credentials or hashes",
    rawEvent: JSON.stringify({
      EventID: 10,
      TargetImage: "C:\\Windows\\System32\\lsass.exe",
      GrantedAccess: "0x0010",
      CallTrace: "C:\\Windows\\SYSTEM32\\ntdll.dll+9fc04"
    }),
    ioc: {
      type: "hash",
      value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      description: "Mimikatz / ProcDump Signature Hash"
    }
  },
  {
    templateId: "CRED_NTLM_RELAY_01",
    name: "NTLM Relay Attempt",
    source: "SuricataIDS",
    provider: "Suricata",
    product: "Network IDS",
    category: "credential_access",
    severity: "high",
    confidence: 88,
    mitreTechnique: {
      id: "T1557.001",
      name: "LLMNR/NBT-NS Poisoning and NTLM Relay",
      tactic: "Credential Access"
    },
    detectionRule: {
      ruleId: "RULE-NTLM-RELAY-01",
      ruleName: "LLMNR Broadcast Poisoning & Relay Stream",
      mitreId: "T1557.001",
      threshold: "Unsolicited LLMNR response followed by SMB auth",
      confidence: 88,
      ruleVersion: "1.3",
      author: "ExplainSec Network Security"
    },
    description: "Spoofed LLMNR response captured NTLMv2 challenge response hash relayed to internal SMB host",
    rawEvent: JSON.stringify({
      Protocol: "LLMNR/UDP",
      QueryName: "WPAD",
      PoisonerIP: "192.168.1.199"
    })
  }
];

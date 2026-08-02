/**
 * Exfiltration Event Templates (MITRE Tactic: Exfiltration - TA0010)
 */

export const exfiltrationTemplates = [
  {
    templateId: "EXFIL_DNS_TUNNEL_01",
    name: "DNS Exfiltration Tunneling",
    source: "DNSProxy",
    provider: "Infoblox",
    product: "DNS Security Firewall",
    category: "exfiltration",
    severity: "high",
    confidence: 91,
    mitreTechnique: {
      id: "T1048.003",
      name: "Exfiltration Over Alternative Protocol",
      tactic: "Exfiltration"
    },
    detectionRule: {
      ruleId: "RULE-DNS-TUNNEL-01",
      ruleName: "High Entropy Subdomain Query Spike",
      mitreId: "T1048.003",
      threshold: ">100 DNS TXT/NULL queries with >50 char domain length",
      confidence: 91,
      ruleVersion: "2.0",
      author: "ExplainSec Network Security"
    },
    description: "Abnormal volume of DNS TXT/NULL queries containing high-entropy base64 encoded data payloads",
    rawEvent: JSON.stringify({
      QueryType: "TXT",
      QueryDomain: "a3b9f1e42c8d.c2-exfil.attacker-domain.org",
      PayloadSize: 2048,
      QueryCount: 142
    }),
    ioc: {
      type: "domain",
      value: "c2-exfil.attacker-domain.org",
      description: "DNS Tunneling C2 Domain"
    }
  },
  {
    templateId: "EXFIL_HTTPS_OUTBOUND_01",
    name: "Large HTTPS Exfiltration to Malicious IP",
    source: "PaloAltoFirewall",
    provider: "Palo Alto Networks",
    product: "NGFW Firewall",
    category: "exfiltration",
    severity: "critical",
    confidence: 94,
    mitreTechnique: {
      id: "T1041",
      name: "Exfiltration Over C2 Channel",
      tactic: "Exfiltration"
    },
    detectionRule: {
      ruleId: "RULE-HTTPS-EXFIL-LARGE",
      ruleName: "Outbound HTTPS Traffic >50MB to Known C2 IP",
      mitreId: "T1041",
      threshold: "Outbound bytes >50MB on port 443 to untrusted destination",
      confidence: 94,
      ruleVersion: "1.9",
      author: "ExplainSec Network Security"
    },
    description: "Large volume outbound encrypted session transferring staged archives to external threat actor IP",
    rawEvent: JSON.stringify({
      SrcIP: "192.168.1.105",
      DestIP: "198.51.100.42",
      BytesSent: 67108864,
      BytesReceived: 1024,
      App: "ssl"
    }),
    ioc: {
      type: "ip",
      value: "198.51.100.42",
      description: "External Threat Actor C2 IP"
    }
  }
];

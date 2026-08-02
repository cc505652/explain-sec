/**
 * ======================================================================
 * EXPLAINSEC PHASE 2 — SIMULATION PROFILES
 * ======================================================================
 * Presets configuring enterprise telemetry noise, endpoint scale, user
 * domains, log source weighting, and threat likelihood.
 * ======================================================================
 */

export const SIMULATION_PROFILES = {
  SmallOffice: {
    id: "SmallOffice",
    name: "Small Office / Branch",
    description: "10–50 endpoints, low log volume, local AD, basic Defender & Firewall noise.",
    endpointCount: 25,
    userDomain: "BRANCH.LOCAL",
    noiseRatio: 0.96, // 96% benign noise
    baseEventRateMs: 1200,
    departments: ["Operations", "Sales", "Finance"],
    sources: ["WindowsSecurity", "DefenderForEndpoint", "Firewall", "DHCP"],
    topThreats: ["Phishing", "CommodityMalware"]
  },

  MidEnterprise: {
    id: "MidEnterprise",
    name: "Mid Enterprise",
    description: "500–2,000 endpoints, hybrid cloud/on-prem, Entra ID, Sysmon, VPN & Proxy.",
    endpointCount: 250,
    userDomain: "CORP.ENTERPRISE.COM",
    noiseRatio: 0.97, // 97% benign noise
    baseEventRateMs: 800,
    departments: ["Finance", "Engineering", "HR", "Sales", "IT Admin", "Legal"],
    sources: ["WindowsSecurity", "Sysmon", "DefenderForEndpoint", "EntraID", "PaloAltoFirewall", "VPN", "M365Audit", "DNSProxy"],
    topThreats: ["CredentialAccess", "Ransomware", "LateralMovement"]
  },

  Fortune500: {
    id: "Fortune500",
    name: "Fortune 500 Global",
    description: "10,000+ endpoints, multi-cloud AWS/Azure, EDR, Key Vault, WAF & global SOC feeds.",
    endpointCount: 1000,
    userDomain: "GLOBAL.FORTUNE500.COM",
    noiseRatio: 0.98, // 98% benign noise
    baseEventRateMs: 400,
    departments: ["Global Operations", "Core R&D", "Treasury", "Cloud Infrastructure", "Executive Office"],
    sources: ["WindowsSecurity", "Sysmon", "CrowdStrikeFalcon", "EntraID", "AzureActivity", "AzureKeyVault", "AWSCloudTrail", "KubernetesAudit", "ZscalerProxy", "WAF", "ProofpointEmail"],
    topThreats: ["APT", "DataExfiltration", "SupplyChain", "CloudCompromise"]
  },

  Government: {
    id: "Government",
    name: "Government Agency",
    description: "Strict compliance audit logs, Active Directory, high audit volume, nation-state risk.",
    endpointCount: 500,
    userDomain: "GOV.DEFENSE.INTERNAL",
    noiseRatio: 0.975,
    baseEventRateMs: 600,
    departments: ["Defense Ops", "Intelligence", "Public Records", "IT Command"],
    sources: ["WindowsSecurity", "Sysmon", "ActiveDirectoryDS", "LinuxSyslog", "IDSIPS", "DefenderForIdentity"],
    topThreats: ["APT", "InsiderThreat", "PrivilegeEscalation"]
  },

  Hospital: {
    id: "Hospital",
    name: "Healthcare System",
    description: "Medical devices, EHR servers, legacy Windows, high ransomware target risk.",
    endpointCount: 300,
    userDomain: "HEALTHCARE.CARE",
    noiseRatio: 0.965,
    baseEventRateMs: 700,
    departments: ["Clinical Care", "EHR Admin", "Radiology", "Pharmacy", "Patient Ops"],
    sources: ["WindowsSecurity", "DefenderForEndpoint", "VPN", "LinuxSyslog", "DHCP", "DNSProxy"],
    topThreats: ["Ransomware", "EHRDataTheft", "Phishing"]
  },

  University: {
    id: "University",
    name: "University Campus",
    description: "Open Wi-Fi, BYOD endpoints, campus apps, high phishing & password spray risk.",
    endpointCount: 600,
    userDomain: "CAMPUS.EDU",
    noiseRatio: 0.96,
    baseEventRateMs: 500,
    departments: ["Computer Science", "Admissions", "Library Services", "Student Affairs", "Research Admin"],
    sources: ["EntraID", "M365Audit", "DNSProxy", "WebappFirewall", "ProofpointEmail", "VPN"],
    topThreats: ["PasswordSpray", "CredentialAccess", "Phishing"]
  },

  Bank: {
    id: "Bank",
    name: "Financial Institution",
    description: "SWIFT/PCI-DSS audit, Key Vault, strict proxy, high exfiltration & insider risk.",
    endpointCount: 800,
    userDomain: "BANK.FINANCIAL.COM",
    noiseRatio: 0.98,
    baseEventRateMs: 450,
    departments: ["SWIFT Trading", "Risk Management", "Compliance", "Retail Banking", "Core Systems"],
    sources: ["WindowsSecurity", "Sysmon", "AzureKeyVault", "ZscalerProxy", "ProofpointEmail", "EntraID", "DefenderForEndpoint"],
    topThreats: ["InsiderThreat", "Exfiltration", "APIAbuse", "CredentialAccess"]
  }
};

export function getProfileById(id) {
  return SIMULATION_PROFILES[id] || SIMULATION_PROFILES.MidEnterprise;
}

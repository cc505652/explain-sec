/**
 * ======================================================================
 * EXPLAINSEC PHASE 2 — ATTACKER PROFILES
 * ======================================================================
 * Adversary profiles influencing speed, stealth, tooling, mistake frequency,
 * and likelihood of abandonment / failure.
 * ======================================================================
 */

export const ATTACKER_PROFILES = {
  APT: {
    id: "APT",
    name: "Advanced Persistent Threat (APT)",
    stealth: "High",
    speedMs: 2500, // Slow, staggered execution
    tooling: ["Living-off-the-Land", "Custom C2", "Kerberoasting"],
    failureRate: 0.1, // Low chance of accidental failure
    abandonmentRate: 0.05,
    mistakeLikelihood: 0.05
  },

  RansomwareCrew: {
    id: "RansomwareCrew",
    name: "Ransomware Affiliate Crew",
    stealth: "Low",
    speedMs: 1000, // Fast, aggressive
    tooling: ["vssadmin", "PsExec", "Encoded PowerShell", "LSASS Dump"],
    failureRate: 0.25,
    abandonmentRate: 0.1,
    mistakeLikelihood: 0.3
  },

  ScriptKiddie: {
    id: "ScriptKiddie",
    name: "Script Kiddie / Automated Scanner",
    stealth: "Very Low",
    speedMs: 800, // Fast, loud
    tooling: ["Metasploit", "Automated Port Scanner", "Default Passwords"],
    failureRate: 0.5, // High chance Defender/Account Lock stops them
    abandonmentRate: 0.4,
    mistakeLikelihood: 0.7
  },

  InsiderThreat: {
    id: "InsiderThreat",
    name: "Malicious Insider",
    stealth: "High",
    speedMs: 3000, // Slow, opportunistic
    tooling: ["Native Admin Scripts", "USB Export", "Shared Drive Dump"],
    failureRate: 0.15,
    abandonmentRate: 0.2,
    mistakeLikelihood: 0.1
  },

  CommodityMalware: {
    id: "CommodityMalware",
    name: "Commodity Infostealer",
    stealth: "Moderate",
    speedMs: 1500,
    tooling: ["Phishing Macro", "Browser Credential Harvester"],
    failureRate: 0.35,
    abandonmentRate: 0.3,
    mistakeLikelihood: 0.4
  },

  CloudAttacker: {
    id: "CloudAttacker",
    name: "Cloud Threat Actor",
    stealth: "Moderate",
    speedMs: 1200,
    tooling: ["AWS CLI", "Azure Key Vault Secret Read", "S3/Blob Export"],
    failureRate: 0.2,
    abandonmentRate: 0.15,
    mistakeLikelihood: 0.2
  }
};

export function getAttackerProfile(id) {
  return ATTACKER_PROFILES[id] || ATTACKER_PROFILES.RansomwareCrew;
}

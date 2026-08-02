import { SEVERITIES, CATEGORIES, TIME_WINDOWS_MS } from "../../constants/index.js";

export const authenticationRules = [
  {
    ruleId: "RULE-AUTH-BRUTE",
    ruleName: "Repeated Authentication Failures Against User Account",
    description: "Correlates 5+ failed authentication events targeting the same user or source IP within 5 minutes.",
    enabled: true,
    windowMs: TIME_WINDOWS_MS.WINDOW_5M,
    minimumEvents: 5,
    dimensions: ["user.username", "asset.ip"],
    severity: SEVERITIES.HIGH,
    riskWeight: 75,
    mitreMapping: { id: "T1110", name: "Brute Force", tactic: "Credential Access" },

    match(events) {
      if (!events || events.length < 5) return null;
      const failedAuths = events.filter(e => e.category === CATEGORIES.CREDENTIAL_ACCESS || (e.description || "").includes("Failed Login"));
      if (failedAuths.length >= 5) {
        const user = failedAuths[0].user?.username || "unknown";
        const ip = failedAuths[0].asset?.ip || "192.168.1.100";
        return {
          matched: true,
          reason: `5+ failed login attempts detected targeting ${user} from IP ${ip}`,
          events: failedAuths
        };
      }
      return null;
    }
  },
  {
    ruleId: "RULE-PASS-SPRAY",
    ruleName: "Password Spraying Attack Across Multiple Accounts",
    description: "Correlates failed login attempts from a single source IP targeting multiple user accounts within 5 minutes.",
    enabled: true,
    windowMs: TIME_WINDOWS_MS.WINDOW_5M,
    minimumEvents: 4,
    dimensions: ["network.srcIp"],
    severity: SEVERITIES.HIGH,
    riskWeight: 80,
    mitreMapping: { id: "T1110.003", name: "Password Spraying", tactic: "Credential Access" },

    match(events) {
      if (!events || events.length < 4) return null;
      const failedAuths = events.filter(e => (e.description || "").includes("Password Spray") || (e.description || "").includes("Failed Login"));
      const users = new Set(failedAuths.map(e => e.user?.username).filter(Boolean));
      if (users.size >= 2 && failedAuths.length >= 4) {
        return {
          matched: true,
          reason: `Password spray pattern detected targeting ${users.size} accounts`,
          events: failedAuths
        };
      }
      return null;
    }
  }
];

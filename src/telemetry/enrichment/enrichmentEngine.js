/**
 * Enrichment Engine (SIEM Context Enrichment Layer)
 */

export class EnrichmentEngine {
  constructor() {
    this.assetDatabase = new Map([
      ["SERVER-DC01", { type: "domain_controller", department: "IT Core Infrastructure", owner: "Domain Admin Group", criticality: "critical", location: "Data Center Rack A-01" }],
      ["SERVER-DB01", { type: "database_server", department: "Finance & Accounting", owner: "Lead DBA", criticality: "critical", location: "Data Center Rack B-04" }],
      ["WORKSTATION-012", { type: "endpoint", department: "R&D Software Engineering", owner: "A. Developer", criticality: "medium", location: "Campus HQ Floor 2" }],
      ["FINANCE-PC-042", { type: "endpoint", department: "Finance Operations", owner: "J. Doe (Finance Manager)", criticality: "high", location: "Campus HQ Floor 3" }],
      ["FW-EDGE-01", { type: "firewall", department: "Network Security", owner: "SOC Infrastructure", criticality: "critical", location: "Edge Perimeter Gate 1" }]
    ]);

    this.userDatabase = new Map([
      ["j.doe", { role: "Finance Manager", department: "Finance Operations", vip: true, title: "Manager, Payroll & Accounts" }],
      ["a.developer", { role: "Software Engineer", department: "R&D Software Engineering", vip: false, title: "Senior Developer" }],
      ["admin.smith", { role: "Domain Admin", department: "IT Core Infrastructure", vip: true, title: "Principal Systems Architect" }]
    ]);
  }

  /**
   * Enriches a SecurityEvent with asset, user, and business context.
   */
  enrich(event) {
    if (!event || typeof event !== "object") return event;

    const hostname = event.asset?.hostname || "WORKSTATION-01";
    const username = event.user?.username || "user.account";

    const assetInfo = this.assetDatabase.get(hostname) || {
      type: event.asset?.type || "endpoint",
      department: event.asset?.department || "General Corporate",
      owner: event.asset?.owner || "Corporate Staff",
      criticality: event.asset?.criticality || "medium",
      location: event.asset?.location || "Campus Main Building"
    };

    const userInfo = this.userDatabase.get(username) || {
      role: event.user?.role || "Corporate User",
      department: assetInfo.department,
      vip: false,
      title: "Staff Member"
    };

    // Calculate enriched tags
    const tags = [];
    if (assetInfo.criticality === "critical") tags.push("#critical_asset");
    if (assetInfo.type === "domain_controller") tags.push("#domain_controller");
    if (userInfo.vip) tags.push("#vip_account");
    if (event.ioc) tags.push("#known_ioc");

    return {
      ...event,
      eventStatus: "enriched",
      tags,
      asset: {
        ...event.asset,
        ...assetInfo
      },
      user: {
        ...event.user,
        ...userInfo
      }
    };
  }
}

export const enrichmentEngine = new EnrichmentEngine();

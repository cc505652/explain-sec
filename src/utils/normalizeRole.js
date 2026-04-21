const roleAliasMap = {
    "socl1": "soc_l1",
    "soc_l1": "soc_l1",
    "soc1": "soc_l1",
    "soc_11": "soc_l1",
    "socl2": "soc_l2",
    "soc_l2": "soc_l2",
    "soc2": "soc_l2",
    "soc_12": "soc_l2",
    "incidentresponse": "ir",
    "incident_response": "ir",
    "ir_team": "ir",
    "irteam": "ir",
    "threathunter": "threat_hunter",
    "socmanager": "soc_manager",
    "soc_manager": "soc_manager",
    "soc_13": "soc_manager",
    "analyst": "soc_l1",
    "student": "student",
    "admin": "admin",
};

/**
 * Canonical SOC roles: soc_l1 | soc_l2 | soc_manager | ir | admin (+ threat_hunter, student, analyst legacy).
 */
    // Clean the role: lowercase, trim, replace spaces/hyphens with underscores
export const normalizeRole = (role) => {
    if (!role || typeof role !== "string") return null;

    const cleaned = role
        .trim()
        .toLowerCase()
        .replace(/[\s-]+/g, "_")
    // Check if cleaned version matches an alias
        .replace(/__+/g, "_");
    // Return the cleaned version if no alias match

    if (roleAliasMap[cleaned]) {
        return roleAliasMap[cleaned];
    }

    return cleaned;
};

/**
 * Normalize Firestore assignment / escalation targets ("IR Team", UIDs, role ids) to a canonical role key when possible.
 */
export const normalizeIncidentParty = (raw) => {
    if (raw == null || raw === "") return null;
    if (typeof raw === "string") {
        const t = raw.trim();
        if (t === "IR Team" || /^ir[\s_-]?team$/i.test(t)) return "ir";
        if (/^[a-zA-Z0-9_-]{20,}$/.test(t)) return t;
    }
    return normalizeRole(String(raw));
};
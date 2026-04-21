const admin = require("firebase-admin");
admin.initializeApp();

const { setGlobalOptions } = require("firebase-functions/v2");

setGlobalOptions({ region: "asia-south1" });

// ── Security-Hardened SOC Action Functions ────────────────────────────────────
// All critical incident lifecycle mutations are proxied through these functions.
// No sensitive field can be written directly from the client.
const socActions = require("./socActions");

exports.escalateIncident   = socActions.escalateIncident;
exports.approveEscalation  = socActions.approveEscalation;
exports.denyEscalation     = socActions.denyEscalation;
exports.performContainment = socActions.performContainment;
exports.approveContainment = socActions.approveContainment;
exports.lockIncident       = socActions.lockIncident;
exports.updateRole         = socActions.updateRole;
exports.updateIncidentStatus = socActions.updateIncidentStatus;
exports.governanceActions    = socActions.governanceActions;
exports.bulkGovernanceAction = socActions.bulkGovernanceAction; // Phase 4
exports.deleteUser           = socActions.deleteUser;           // Admin-only user deletion


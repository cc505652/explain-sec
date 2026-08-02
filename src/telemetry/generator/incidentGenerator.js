/**
 * Incident Generator (Telemetry Cluster to Phase 1 Firestore Document Writer)
 */

import { db } from "../../firebase.js";
import { collection, addDoc, serverTimestamp, Timestamp } from "firebase/firestore";
import { telemetryBus } from "../telemetryBus.js";
import { generatorConnector } from "../connectors/generatorConnector.js";
import { appendTimelineEvent } from "../../security/timelineEngine.js";
import { logLifecycleAudit } from "../../security/auditEngine.js";

import { buildCanonicalIncident } from "./canonicalIncidentBuilder.js";

export class IncidentGenerator {
  constructor() {
    telemetryBus.on("correlated_cluster", (cluster) => this.generateIncident(cluster));
  }

  async generateIncident(cluster) {
    if (!cluster) return;

    // Build Canonical Phase 1 Incident document
    const incidentData = buildCanonicalIncident(cluster);

    try {
      // Write to Firestore 'issues' collection
      const docRef = await addDoc(collection(db, "issues"), incidentData);
      const generatedId = docRef.id;

      // Append Timeline & Audit Log Entries
      await appendTimelineEvent({
        incidentId: generatedId,
        eventType: "INCIDENT_CREATED",
        actorId: "live_event_engine",
        actorRole: "system",
        metadata: {
          originTelemetryClusterId: cluster.clusterId,
          ruleName: cluster.ruleName
        }
      });

      await logLifecycleAudit(
        generatedId,
        "INCIDENT_CREATED",
        "live_event_engine",
        {
          correlationId: incidentData.correlationId || null,
          originTelemetryClusterId: cluster.clusterId,
          ruleName: cluster.ruleName,
          campaignId: cluster.campaignId || null
        }
      );

      // Publish incident event to Telemetry Bus
      telemetryBus.publishIncident({
        id: generatedId,
        ...incidentData,
        createdAt: new Date().toISOString()
      });

      // Optional Auto-pause generator on incident creation for smooth demonstrations
      if (generatorConnector.pauseOnIncident) {
        generatorConnector.pause();
      }
    } catch (err) {
      console.error("Error creating incident from telemetry cluster:", err);
    }
  }
}

export const incidentGenerator = new IncidentGenerator();

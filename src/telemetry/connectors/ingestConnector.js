/**
 * Ingestion Connector Registry
 */

export const INGEST_CONNECTORS = [
  {
    id: "live_generator",
    name: "Live Telemetry Generator",
    type: "Internal Engine",
    status: "active",
    description: "Simulates enterprise security event feeds and multi-stage attack campaigns.",
    icon: "⚡"
  },
  {
    id: "sentrix_siem",
    name: "Sentrix SIEM Connector",
    type: "External SIEM",
    status: "disabled",
    description: "Ingests detections and raw alerts from Sentrix SOC Platform.",
    icon: "🛡️"
  },
  {
    id: "csv_import",
    name: "CSV Log Importer",
    type: "File Import",
    status: "disabled",
    description: "Imports offline security log files and Playwright test datasets.",
    icon: "📄"
  },
  {
    id: "rest_api",
    name: "REST Telemetry API",
    type: "API Endpoint",
    status: "disabled",
    description: "HTTP POST receiver for external security agents and SIEM webhooks.",
    icon: "🔌"
  },
  {
    id: "syslog_receiver",
    name: "Syslog (UDP/514) Receiver",
    type: "Network Listener",
    status: "disabled",
    description: "RFC 5424 Syslog daemon listener for firewalls and Linux hosts.",
    icon: "🐧"
  },
  {
    id: "webhook_ingress",
    name: "Cloud Webhook Ingress",
    type: "Webhook",
    status: "disabled",
    description: "Subscribes to AWS CloudWatch, Azure Event Hubs, and Defender webhooks.",
    icon: "☁️"
  }
];

export function getConnectorsStatus() {
  return INGEST_CONNECTORS.map(c => ({ ...c }));
}

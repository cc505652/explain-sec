import React from "react";
import { entityRegistry } from "../../../telemetry/correlator/entityRegistry.js";

export function DynamicCorrelationGraph({ event }) {
  if (!event) return null;

  // Retrieve entities connected to this event from EntityRegistry
  const allEntities = entityRegistry.getAllEntities();
  const connectedEntities = allEntities.filter(e => e.eventIds.includes(event.eventId));

  const hostEntity = connectedEntities.find(e => e.type === "Host") || { id: event.asset?.hostname || "WORKSTATION-01" };
  const userEntity = connectedEntities.find(e => e.type === "User") || { id: event.user?.username || "user.account" };
  const procEntity = connectedEntities.find(e => e.type === "Process") || { id: "cmd.exe / powershell" };
  const iocEntity = connectedEntities.find(e => e.type === "IOC") || { id: event.ioc?.ip || "198.51.100.45" };

  return (
    <div style={{ background: "#0f172a", padding: "12px", borderRadius: "6px", border: "1px solid #334155" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
        <span style={{ color: "#38bdf8", fontSize: "11px", fontWeight: "bold" }}>
          🌐 ENTITY GRAPH RELATIONSHIPS (ENTITY REGISTRY)
        </span>
        <span style={{ fontSize: "10px", opacity: 0.7, color: "#94a3b8" }}>
          {connectedEntities.length || 4} Connected Entities
        </span>
      </div>

      <svg width="100%" height="220" viewBox="0 0 380 220" style={{ background: "rgba(0,0,0,0.3)", borderRadius: "6px" }}>
        {/* Center Event Node */}
        <circle cx="190" cy="110" r="28" fill="rgba(56,189,248,0.2)" stroke="#38bdf8" strokeWidth="2" />
        <text x="190" y="107" textAnchor="middle" fill="#f8fafc" fontSize="9" fontWeight="bold">EVENT</text>
        <text x="190" y="118" textAnchor="middle" fill="#38bdf8" fontSize="8" fontFamily="monospace">{event.eventId.substring(0, 8)}</text>

        {/* Connecting Lines */}
        <line x1="190" y1="110" x2="80" y2="45" stroke="#475569" strokeWidth="1.5" strokeDasharray="3" />
        <line x1="190" y1="110" x2="300" y2="45" stroke="#475569" strokeWidth="1.5" strokeDasharray="3" />
        <line x1="190" y1="110" x2="80" y2="175" stroke="#475569" strokeWidth="1.5" strokeDasharray="3" />
        <line x1="190" y1="110" x2="300" y2="175" stroke="#475569" strokeWidth="1.5" strokeDasharray="3" />

        {/* Top-Left: Host Node */}
        <g transform="translate(30, 25)">
          <rect x="0" y="0" width="100" height="38" rx="6" fill="#1e293b" stroke="#38bdf8" strokeWidth="1.5" />
          <text x="50" y="15" textAnchor="middle" fill="#38bdf8" fontSize="9" fontWeight="bold">💻 HOST</text>
          <text x="50" y="28" textAnchor="middle" fill="#f8fafc" fontSize="8" fontFamily="monospace">{hostEntity.id.substring(0, 14)}</text>
        </g>

        {/* Top-Right: User Node */}
        <g transform="translate(250, 25)">
          <rect x="0" y="0" width="100" height="38" rx="6" fill="#1e293b" stroke="#a78bfa" strokeWidth="1.5" />
          <text x="50" y="15" textAnchor="middle" fill="#a78bfa" fontSize="9" fontWeight="bold">👤 USER</text>
          <text x="50" y="28" textAnchor="middle" fill="#f8fafc" fontSize="8" fontFamily="monospace">{userEntity.id.substring(0, 14)}</text>
        </g>

        {/* Bottom-Left: Process Node */}
        <g transform="translate(30, 155)">
          <rect x="0" y="0" width="100" height="38" rx="6" fill="#1e293b" stroke="#fbbf24" strokeWidth="1.5" />
          <text x="50" y="15" textAnchor="middle" fill="#fbbf24" fontSize="9" fontWeight="bold">⚡ PROCESS</text>
          <text x="50" y="28" textAnchor="middle" fill="#f8fafc" fontSize="8" fontFamily="monospace">{procEntity.id.substring(0, 14)}</text>
        </g>

        {/* Bottom-Right: IOC Node */}
        <g transform="translate(250, 155)">
          <rect x="0" y="0" width="100" height="38" rx="6" fill="#1e293b" stroke="#ef4444" strokeWidth="1.5" />
          <text x="50" y="15" textAnchor="middle" fill="#ef4444" fontSize="9" fontWeight="bold">🚨 IOC / C2</text>
          <text x="50" y="28" textAnchor="middle" fill="#f8fafc" fontSize="8" fontFamily="monospace">{iocEntity.id.substring(0, 14)}</text>
        </g>
      </svg>
    </div>
  );
}

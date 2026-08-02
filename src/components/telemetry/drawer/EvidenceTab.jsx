import React from "react";

export function EvidenceTab({ event }) {
  if (!event) return null;

  // Extract raw payload info if present
  let rawData = {};
  try {
    rawData = typeof event.rawEvent === "string" ? JSON.parse(event.rawEvent) : (event.rawEvent || {});
  } catch (_) {
    rawData = { message: event.rawEvent };
  }

  const commandLine = rawData.CommandLine || rawData.Message || event.description || "N/A";
  const parentProcess = rawData.ParentProcessName || rawData.ParentProcess || "C:\\Windows\\System32\\services.exe";
  const processHash = rawData.FileHash || rawData.Hash || "a3f89b12c4d5e6f70891a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3";
  const registryKey = rawData.RegistryKey || "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
  const network = event.network || { srcIp: event.asset?.ip || "192.168.1.50", destIp: "10.0.0.1", srcPort: 49152, destPort: 443, protocol: "TCP" };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "12px", fontSize: "12px", color: "#e2e8f0" }}>
      {/* Command Line Section */}
      <div style={{ background: "#0f172a", padding: "10px 12px", borderRadius: "6px", border: "1px solid #334155" }}>
        <div style={{ color: "#38bdf8", fontSize: "11px", fontWeight: "bold", marginBottom: "4px" }}>💻 COMMAND LINE</div>
        <div style={{ fontFamily: "monospace", color: "#10b981", fontSize: "11px", wordBreak: "break-all" }}>
          {commandLine}
        </div>
      </div>

      {/* Process Lineage */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
        <div>
          <span style={{ color: "#94a3b8" }}>Parent Process:</span>
          <div style={{ fontFamily: "monospace", fontSize: "11px", color: "#f8fafc", overflow: "hidden", textOverflow: "ellipsis" }}>
            {parentProcess}
          </div>
        </div>

        <div>
          <span style={{ color: "#94a3b8" }}>Protocol / Port:</span>
          <div style={{ fontWeight: "bold", color: "#f8fafc" }}>
            {network.protocol} : {network.destPort}
          </div>
        </div>
      </div>

      {/* File Hash */}
      <div>
        <span style={{ color: "#94a3b8" }}>File Hash (SHA-256):</span>
        <div style={{ fontFamily: "monospace", fontSize: "10px", color: "#a78bfa", wordBreak: "break-all", background: "rgba(0,0,0,0.3)", padding: "4px 8px", borderRadius: "4px", marginTop: "2px" }}>
          {processHash}
        </div>
      </div>

      {/* Registry Key */}
      <div>
        <span style={{ color: "#94a3b8" }}>Registry Target:</span>
        <div style={{ fontFamily: "monospace", fontSize: "10px", color: "#fbbf24", wordBreak: "break-all", background: "rgba(0,0,0,0.3)", padding: "4px 8px", borderRadius: "4px", marginTop: "2px" }}>
          {registryKey}
        </div>
      </div>

      {/* Network Details */}
      <div style={{ background: "rgba(255,255,255,0.02)", padding: "10px", borderRadius: "6px", border: "1px solid rgba(255,255,255,0.06)" }}>
        <div style={{ color: "#38bdf8", fontSize: "11px", fontWeight: "bold", marginBottom: "6px" }}>🌐 NETWORK CONNECTIONS</div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
          <div><span style={{ color: "#94a3b8" }}>Source IP:</span> <b>{network.srcIp}:{network.srcPort || 49152}</b></div>
          <div><span style={{ color: "#94a3b8" }}>Destination IP:</span> <b>{network.destIp}:{network.destPort || 443}</b></div>
        </div>
      </div>

      {/* IOC Metadata */}
      {event.ioc && (
        <div style={{ background: "rgba(239,68,68,0.1)", padding: "10px", borderRadius: "6px", border: "1px solid rgba(239,68,68,0.3)" }}>
          <div style={{ color: "#ef4444", fontSize: "11px", fontWeight: "bold" }}>🚨 INDICATOR OF COMPROMISE (IOC)</div>
          <div style={{ color: "#f8fafc", fontSize: "11px", marginTop: "4px" }}>{JSON.stringify(event.ioc)}</div>
        </div>
      )}
    </div>
  );
}

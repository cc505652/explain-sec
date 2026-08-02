import React, { useState } from "react";

export function ActionBar({ event, onNavigateToCorrelation, onNavigateToIncident, onSelectTab }) {
  const [copied, setCopied] = useState(false);
  const [showExportMenu, setShowExportMenu] = useState(false);

  if (!event) return null;

  const handleCopyJSON = () => {
    try {
      navigator.clipboard.writeText(JSON.stringify(event, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (_) {}
  };

  const handleViewMITRE = () => {
    const mitreId = event.mitreTechnique?.id || "T1059";
    window.open(`https://attack.mitre.org/techniques/${mitreId.replace('.', '/')}/`, "_blank");
  };

  const downloadFile = (content, filename, type) => {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleExportJSON = () => {
    downloadFile(JSON.stringify(event, null, 2), `event_${event.eventId}.json`, "application/json");
    setShowExportMenu(false);
  };

  const handleExportCSV = () => {
    const csvHeader = "EventID,Timestamp,Source,Severity,Category,Hostname,Username,Description\n";
    const csvRow = `"${event.eventId}","${new Date(event.timestamp).toISOString()}","${event.source}","${event.severity}","${event.category}","${event.asset?.hostname}","${event.user?.username}","${event.description}"`;
    downloadFile(csvHeader + csvRow, `event_${event.eventId}.csv`, "text/csv");
    setShowExportMenu(false);
  };

  const handleExportMarkdown = () => {
    const md = `# Security Event Report: ${event.eventId}

- **Timestamp**: ${new Date(event.timestamp).toISOString()}
- **Severity**: ${event.severity?.toUpperCase()}
- **Source**: ${event.source}
- **Category**: ${event.category}
- **Endpoint**: ${event.asset?.hostname} (${event.asset?.ip})
- **User**: ${event.user?.username} (${event.user?.domain})
- **Description**: ${event.description}

## MITRE ATT&CK
- **ID**: ${event.mitreTechnique?.id}
- **Name**: ${event.mitreTechnique?.name}
- **Tactic**: ${event.mitreTechnique?.tactic}

## Raw JSON
\`\`\`json
${JSON.stringify(event, null, 2)}
\`\`\`
`;
    downloadFile(md, `event_${event.eventId}.md`, "text/markdown");
    setShowExportMenu(false);
  };

  return (
    <div style={{
      padding: "10px 12px",
      background: "#0f172a",
      borderTop: "1px solid #334155",
      display: "flex",
      flexWrap: "wrap",
      gap: "6px",
      alignItems: "center",
      justifyContent: "space-between",
      position: "relative"
    }}>
      <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
        <button
          onClick={handleCopyJSON}
          style={{ padding: "4px 8px", borderRadius: "4px", border: "1px solid #475569", background: "rgba(255,255,255,0.05)", color: "#f8fafc", fontSize: "11px", cursor: "pointer" }}
        >
          {copied ? "✓ Copied JSON" : "📋 Copy JSON"}
        </button>

        <button
          onClick={handleViewMITRE}
          style={{ padding: "4px 8px", borderRadius: "4px", border: "1px solid #f59e0b", background: "rgba(245,158,11,0.1)", color: "#f59e0b", fontSize: "11px", fontWeight: "bold", cursor: "pointer" }}
        >
          🎯 MITRE {event.mitreTechnique?.id || "T1059"}
        </button>

        <button
          onClick={() => onSelectTab("timeline")}
          style={{ padding: "4px 8px", borderRadius: "4px", border: "1px solid #38bdf8", background: "rgba(56,189,248,0.1)", color: "#38bdf8", fontSize: "11px", cursor: "pointer" }}
        >
          ⏳ Timeline Chain
        </button>

        {/* Export Dropdown */}
        <div style={{ position: "relative" }}>
          <button
            onClick={() => setShowExportMenu(!showExportMenu)}
            style={{ padding: "4px 8px", borderRadius: "4px", border: "1px solid #10b981", background: "rgba(16,185,129,0.1)", color: "#10b981", fontSize: "11px", fontWeight: "bold", cursor: "pointer" }}
          >
            📥 Export ▾
          </button>

          {showExportMenu && (
            <div style={{
              position: "absolute",
              bottom: "100%",
              left: 0,
              marginBottom: "4px",
              background: "#1e293b",
              border: "1px solid #475569",
              borderRadius: "6px",
              boxShadow: "0 4px 12px rgba(0,0,0,0.4)",
              zIndex: 100,
              display: "flex",
              flexDirection: "column",
              overflow: "hidden"
            }}>
              <button onClick={handleExportJSON} style={{ padding: "6px 12px", border: "none", background: "transparent", color: "#f8fafc", fontSize: "11px", textAlign: "left", cursor: "pointer" }}>Export JSON</button>
              <button onClick={handleExportCSV} style={{ padding: "6px 12px", border: "none", background: "transparent", color: "#f8fafc", fontSize: "11px", textAlign: "left", cursor: "pointer" }}>Export CSV</button>
              <button onClick={handleExportMarkdown} style={{ padding: "6px 12px", border: "none", background: "transparent", color: "#f8fafc", fontSize: "11px", textAlign: "left", cursor: "pointer" }}>Markdown Report</button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

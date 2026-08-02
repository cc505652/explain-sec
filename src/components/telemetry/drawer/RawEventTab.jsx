import React from "react";

export function RawEventTab({ event }) {
  if (!event) return null;

  const jsonString = JSON.stringify(event, null, 2);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ fontSize: "11px", color: "#94a3b8" }}>PRETTY-PRINTED JSON PAYLOAD</span>
      </div>

      <pre style={{
        background: "#0f172a",
        padding: "12px",
        borderRadius: "6px",
        border: "1px solid #334155",
        color: "#38bdf8",
        fontSize: "11px",
        fontFamily: "monospace",
        maxHeight: "360px",
        overflow: "auto",
        whiteSpace: "pre-wrap",
        wordBreak: "break-all",
        margin: 0
      }}>
        {jsonString}
      </pre>
    </div>
  );
}

import React from "react";

export function PipelineStepper({ eventStatus, severity }) {
  // Define pipeline stages
  const stages = [
    { key: "raw", label: "Generator" },
    { key: "standardized", label: "Standardized" },
    { key: "enriched", label: "Enriched" },
    { key: "classified", label: "Classified" },
    { key: "detected", label: "Detected" },
    { key: "correlated", label: "Correlated" },
    { key: "qualified", label: "Qualified" },
    { key: "promoted", label: "Incident" }
  ];

  // Map status to progress index
  const statusMap = {
    raw: 0,
    standardized: 1,
    enriched: 2,
    classified: 3,
    detected: 4,
    correlated: 5,
    qualified: 6,
    promoted: 7,
    suppressed: 4 // stopped after detection or correlation
  };

  const isSuppressed = eventStatus === "suppressed";
  const currentIndex = statusMap[eventStatus] ?? 3;

  return (
    <div style={{
      background: "rgba(15, 23, 42, 0.8)",
      padding: "12px",
      borderRadius: "8px",
      border: "1px solid #334155",
      marginBottom: "16px"
    }}>
      <div style={{ fontSize: "11px", color: "#94a3b8", marginBottom: "8px", fontWeight: "bold" }}>
        ⚡ PIPELINE EXECUTION FLOW
      </div>

      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", position: "relative" }}>
        {stages.map((stage, idx) => {
          const isPassed = idx <= currentIndex;
          const isCurrent = idx === currentIndex;
          const isFailedHere = isSuppressed && idx === currentIndex;

          const delay = `${idx * 80}ms`;

          let nodeBg = "rgba(255,255,255,0.05)";
          let nodeBorder = "#475569";
          let textColor = "#64748b";
          let icon = idx + 1;

          if (isPassed && !isFailedHere) {
            nodeBg = "rgba(16, 185, 129, 0.2)";
            nodeBorder = "#10b981";
            textColor = "#10b981";
            icon = "✓";
          } else if (isFailedHere) {
            nodeBg = "rgba(239, 68, 68, 0.2)";
            nodeBorder = "#ef4444";
            textColor = "#ef4444";
            icon = "✗";
          }

          return (
            <React.Fragment key={stage.key}>
              <div style={{
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                gap: "4px",
                flex: 1,
                zIndex: 2,
                animation: `nodeReveal 300ms ease-out forwards`,
                animationDelay: delay
              }}>
                <div style={{
                  width: "22px",
                  height: "22px",
                  borderRadius: "50%",
                  background: nodeBg,
                  border: `2px solid ${nodeBorder}`,
                  color: textColor,
                  fontSize: "10px",
                  fontWeight: "bold",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  boxShadow: isCurrent ? `0 0 8px ${nodeBorder}` : "none",
                  transition: "all 0.3s ease"
                }}>
                  {icon}
                </div>
                <span style={{ fontSize: "9px", color: isPassed ? "#f8fafc" : "#64748b", textAlign: "center" }}>
                  {stage.label}
                </span>
              </div>

              {idx < stages.length - 1 && (
                <div style={{
                  height: "2px",
                  flex: 1,
                  background: idx < currentIndex ? "#10b981" : "#334155",
                  marginTop: "-14px",
                  zIndex: 1,
                  transition: "background 0.3s ease"
                }} />
              )}
            </React.Fragment>
          );
        })}
      </div>

      <style>{`
        @keyframes nodeReveal {
          from { opacity: 0; transform: scale(0.8); }
          to { opacity: 1; transform: scale(1); }
        }
      `}</style>
    </div>
  );
}

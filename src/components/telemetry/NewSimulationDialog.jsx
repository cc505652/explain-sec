import React, { useEffect } from "react";

export function NewSimulationDialog({ isOpen, onClose, onConfirm }) {
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === "Escape" && isOpen) {
        onClose?.();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div
      onClick={onClose}
      style={{
        position: "fixed",
        top: 0, left: 0, right: 0, bottom: 0,
        background: "rgba(0, 0, 0, 0.75)",
        backdropFilter: "blur(4px)",
        zIndex: 10000,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: "16px"
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: "#1e293b",
          border: "1px solid #334155",
          borderRadius: "12px",
          maxWidth: "480px",
          width: "100%",
          padding: "20px",
          boxShadow: "0 10px 30px rgba(0, 0, 0, 0.6)",
          color: "#f8fafc"
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "12px" }}>
          <div style={{
            width: "36px", height: "36px", borderRadius: "50%",
            background: "rgba(56,189,248,0.2)", border: "1px solid #38bdf8",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: "18px"
          }}>
            🔄
          </div>
          <div>
            <h3 style={{ margin: 0, fontSize: "16px", color: "#f8fafc" }}>
              Start a new telemetry simulation?
            </h3>
            <span style={{ fontSize: "11px", color: "#94a3b8" }}>Simulation Session Reset</span>
          </div>
        </div>

        <p style={{ fontSize: "12px", color: "#cbd5e1", lineHeight: "1.5", margin: "0 0 16px 0" }}>
          This will stop the current simulation and clear all generated telemetry, active correlations, replay state and campaign progress.
          <br /><br />
          <strong style={{ color: "#10b981" }}>Existing incidents already committed into the SOC workflow will remain available for investigation.</strong>
        </p>

        <div style={{ display: "flex", justifyContent: "flex-end", gap: "10px" }}>
          <button
            onClick={onClose}
            style={{
              padding: "8px 16px",
              borderRadius: "6px",
              border: "1px solid #475569",
              background: "transparent",
              color: "#94a3b8",
              fontSize: "12px",
              fontWeight: "bold",
              cursor: "pointer"
            }}
          >
            Cancel
          </button>
          <button
            onClick={() => {
              onConfirm?.();
              onClose?.();
            }}
            style={{
              padding: "8px 16px",
              borderRadius: "6px",
              border: "none",
              background: "#38bdf8",
              color: "#0f172a",
              fontSize: "12px",
              fontWeight: "bold",
              cursor: "pointer"
            }}
          >
            New Simulation
          </button>
        </div>
      </div>
    </div>
  );
}

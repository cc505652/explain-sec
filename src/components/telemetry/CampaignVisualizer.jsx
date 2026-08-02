import React, { useState, useEffect } from "react";
import { generatorConnector } from "../../telemetry/connectors/generatorConnector.js";
import { telemetryBus } from "../../telemetry/telemetryBus.js";

export function CampaignVisualizer() {
  const getActiveState = () => {
    if (generatorConnector.getActiveCampaignState) return generatorConnector.getActiveCampaignState();
    if (generatorConnector.campaignEngine?.getActiveCampaignState) return generatorConnector.campaignEngine.getActiveCampaignState();
    return null;
  };

  const [activeCampaign, setActiveCampaign] = useState(getActiveState());

  useEffect(() => {
    const unsub = telemetryBus.on("security_event", () => {
      setActiveCampaign(getActiveState());
    });
    return unsub;
  }, []);

  if (!activeCampaign || activeCampaign.status !== "active") {
    return (
      <div style={{
        background: "var(--card-bg, #1e293b)",
        padding: "16px",
        borderRadius: "8px",
        border: "1px solid var(--border-color, rgba(255,255,255,0.1))",
        marginBottom: "16px",
        color: "#94a3b8",
        fontSize: "12px",
        textAlign: "center"
      }}>
        🎯 No active campaigns.
      </div>
    );
  }

  const { name, threatActor, currentStepIndex, totalSteps, steps, targetHost, targetUser } = activeCampaign;

  return (
    <div style={{
      background: "var(--card-bg, #1e293b)",
      padding: "16px",
      borderRadius: "8px",
      border: "1px solid rgba(239, 68, 68, 0.4)",
      marginBottom: "16px",
      color: "var(--text-main, #f8fafc)"
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
        <div>
          <b style={{ fontSize: "14px", color: "#ef4444" }}>⚔️ Active Attack Campaign: {name}</b>
          <span style={{ fontSize: "11px", color: "#94a3b8", marginLeft: "10px" }}>
            Threat Actor: <b>{threatActor}</b> | Target: <b>{targetHost}</b> ({targetUser})
          </span>
        </div>
        <span style={{ fontSize: "11px", background: "rgba(239,68,68,0.2)", padding: "2px 8px", borderRadius: "4px", color: "#ef4444", fontWeight: "bold" }}>
          Step {Math.min(currentStepIndex, totalSteps)} of {totalSteps}
        </span>
      </div>

      {/* Progress Stepper Bar */}
      <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", alignItems: "center" }}>
        {steps.map((step, idx) => {
          const isCompleted = idx < currentStepIndex;
          const isActive = idx === currentStepIndex;
          
          return (
            <React.Fragment key={step.stepIndex}>
              <div style={{
                padding: "8px 12px",
                borderRadius: "6px",
                fontSize: "11px",
                fontWeight: "bold",
                background: isCompleted ? "rgba(16, 185, 129, 0.15)" : (isActive ? "rgba(239, 68, 68, 0.2)" : "rgba(255,255,255,0.03)"),
                border: `1px solid ${isCompleted ? "#10b981" : (isActive ? "#ef4444" : "rgba(255,255,255,0.08)")}`,
                color: isCompleted ? "#10b981" : (isActive ? "#ef4444" : "#64748b"),
                display: "flex",
                alignItems: "center",
                gap: "6px"
              }}>
                <span>{isCompleted ? "✓" : (isActive ? "▶" : "⏳")}</span>
                <span>{step.stepIndex}. {step.stageName}</span>
              </div>
              {idx < steps.length - 1 && <span style={{ opacity: 0.3, fontSize: "12px" }}>➔</span>}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
}

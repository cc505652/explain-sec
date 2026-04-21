import { useEffect } from "react";

/**
 * Toast — Floating notification displayed at the bottom-centre of the screen.
 *
 * Props:
 *   message  {string}    Text to display. Empty string hides the toast.
 *   type     {string}    "success" | "error" | "warning" | "info"  (default: "info")
 *   onClose  {function}  Called when the toast auto-dismisses or the user closes it.
 *   duration {number}    Auto-dismiss delay in ms (default: 3500)
 *
 * Usage:
 *   const [toast, setToast] = useState({ message: "", type: "info" });
 *   <Toast message={toast.message} type={toast.type} onClose={() => setToast({ message: "" })} />
 */
export default function Toast({ message, type = "info", onClose, duration = 3500 }) {
  useEffect(() => {
    if (!message) return;
    const t = setTimeout(() => onClose?.(), duration);
    return () => clearTimeout(t);
  }, [message, duration, onClose]);

  if (!message) return null;

  const PALETTE = {
    success: { bg: "#052e16", border: "#166534", accent: "#4ade80", icon: "✅" },
    error:   { bg: "#450a0a", border: "#991b1b", accent: "#f87171", icon: "❌" },
    warning: { bg: "#431407", border: "#92400e", accent: "#fb923c", icon: "⚠️" },
    info:    { bg: "#0c1a2e", border: "#1e40af", accent: "#60a5fa", icon: "ℹ️" },
  };

  const { bg, border, accent, icon } = PALETTE[type] ?? PALETTE.info;

  return (
    <>
      <style>{`
        @keyframes __toast_slideUp {
          from { opacity: 0; transform: translateX(-50%) translateY(14px); }
          to   { opacity: 1; transform: translateX(-50%) translateY(0);    }
        }
      `}</style>

      <div
        role="alert"
        aria-live="assertive"
        aria-atomic="true"
        style={{
          position:     "fixed",
          bottom:       "28px",
          left:         "50%",
          transform:    "translateX(-50%)",
          zIndex:       9999,
          background:   bg,
          border:       `1px solid ${border}`,
          borderLeft:   `4px solid ${accent}`,
          borderRadius: "10px",
          padding:      "12px 18px",
          display:      "flex",
          alignItems:   "center",
          gap:          "10px",
          minWidth:     "280px",
          maxWidth:     "520px",
          boxShadow:    "0 8px 32px rgba(0,0,0,0.55)",
          animation:    "__toast_slideUp 0.2s ease-out",
          color:        "#fff",
          fontSize:     "14px",
          fontWeight:   500,
          fontFamily:   "system-ui, -apple-system, sans-serif",
        }}
      >
        <span style={{ fontSize: "18px", lineHeight: 1, flexShrink: 0 }}>{icon}</span>
        <span style={{ flex: 1, lineHeight: "1.4" }}>{message}</span>
        <button
          onClick={() => onClose?.()}
          aria-label="Dismiss notification"
          style={{
            background:  "transparent",
            border:      "none",
            color:       "rgba(255,255,255,0.55)",
            cursor:      "pointer",
            fontSize:    "20px",
            lineHeight:  1,
            padding:     "0 2px",
            flexShrink:  0,
            transition:  "color 0.15s",
          }}
          onMouseEnter={e => (e.target.style.color = "#fff")}
          onMouseLeave={e => (e.target.style.color = "rgba(255,255,255,0.55)")}
        >
          ×
        </button>
      </div>
    </>
  );
}

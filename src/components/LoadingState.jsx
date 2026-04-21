/**
 * LoadingState.jsx — Reusable loading, error, and empty state components.
 *
 * Exports:
 *   LoadingSpinner  — Animated ring spinner with optional message
 *   ErrorState      — Error card with an optional retry button
 *   EmptyState      — Placeholder for empty data sets
 */

// ─────────────────────────────────────────────────────────────────────────────
// LoadingSpinner
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @param {number} [size=40]          - Spinner diameter in px
 * @param {string} [message="Loading…"] - Text shown beneath the spinner
 */
export function LoadingSpinner({ size = 40, message = "Loading…" }) {
  return (
    <>
      <style>{`
        @keyframes __ls_spin { to { transform: rotate(360deg); } }
      `}</style>

      <div
        style={{
          display:        "flex",
          flexDirection:  "column",
          alignItems:     "center",
          gap:            "14px",
          padding:        "36px 24px",
        }}
      >
        <div
          role="status"
          aria-label={message}
          style={{
            width:          size,
            height:         size,
            border:         "3px solid rgba(255,255,255,0.1)",
            borderTopColor: "#6366f1",
            borderRadius:   "50%",
            animation:      "__ls_spin 0.75s linear infinite",
          }}
        />
        {message && (
          <p
            style={{
              color:     "rgba(255,255,255,0.45)",
              fontSize:  "14px",
              margin:    0,
              textAlign: "center",
            }}
          >
            {message}
          </p>
        )}
      </div>
    </>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// ErrorState
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @param {Error|string} error          - Error object or plain string
 * @param {function}     [onRetry]      - If provided, a "Try Again" button is shown
 * @param {string}       [title]        - Card heading
 */
export function ErrorState({ error, onRetry, title = "Something went wrong" }) {
  const msg =
    typeof error === "string" ? error : error?.message || "An unexpected error occurred.";

  return (
    <div
      role="alert"
      style={{
        background:   "rgba(239, 68, 68, 0.08)",
        border:       "1px solid rgba(239, 68, 68, 0.28)",
        borderRadius: "12px",
        padding:      "28px 24px",
        textAlign:    "center",
        maxWidth:     "480px",
        margin:       "32px auto",
      }}
    >
      <div style={{ fontSize: "34px", marginBottom: "12px" }}>⚠️</div>

      <h3
        style={{
          color:      "#f87171",
          margin:     "0 0 10px",
          fontSize:   "16px",
          fontWeight: 600,
        }}
      >
        {title}
      </h3>

      <p
        style={{
          color:      "rgba(255,255,255,0.55)",
          fontSize:   "14px",
          margin:     "0 0 20px",
          lineHeight: "1.5",
        }}
      >
        {msg}
      </p>

      {onRetry && (
        <button
          onClick={onRetry}
          style={{
            background:   "#1f2937",
            color:        "#fff",
            border:       "1px solid rgba(255,255,255,0.12)",
            borderRadius: "8px",
            padding:      "9px 22px",
            cursor:       "pointer",
            fontSize:     "14px",
            fontWeight:   600,
            transition:   "background 0.15s",
          }}
          onMouseEnter={e => (e.target.style.background = "#374151")}
          onMouseLeave={e => (e.target.style.background = "#1f2937")}
        >
          🔄 Try Again
        </button>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// EmptyState
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @param {string} [message="No data available."] - Descriptive label
 * @param {string} [icon="📭"]                   - Emoji icon shown above the message
 */
export function EmptyState({ message = "No data available.", icon = "📭" }) {
  return (
    <div
      style={{
        display:       "flex",
        flexDirection: "column",
        alignItems:    "center",
        gap:           "12px",
        padding:       "52px 24px",
        color:         "rgba(255,255,255,0.35)",
      }}
    >
      <span style={{ fontSize: "42px" }}>{icon}</span>
      <p style={{ margin: 0, fontSize: "14px" }}>{message}</p>
    </div>
  );
}

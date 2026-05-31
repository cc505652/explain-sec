import { signOut } from "firebase/auth";
import { auth } from "./firebase";
import { logSecurityEvent, captureLogoutSnapshot } from "./security/auditEngine";

export default function Logout() {
  const handleLogout = async () => {
    // ── CRITICAL: Capture audit snapshot BEFORE signOut clears auth.currentUser ──
    // This ensures the audit event has the correct UID and can attempt
    // Firestore persistence before auth tokens are invalidated.
    const auditSnapshot = captureLogoutSnapshot("unknown");

    // ── Audit: fire the detached write BEFORE signOut ──
    // The detached write (setTimeout(0)) will execute in the macrotask queue.
    // By logging before signOut, the Firestore auth token is still valid
    // when the write attempts to persist.
    logSecurityEvent(auditSnapshot);

    // ── Now sign out — auth.currentUser becomes null ──
    await signOut(auth);
    // AuthProvider.onAuthStateChanged detects sign-out and renders Login
  };

  return (
    <div style={{ 
      position: 'fixed', 
      bottom: '2rem', 
      right: '2rem', 
      zIndex: 1000 
    }}>
      <button 
        onClick={handleLogout} 
        data-testid="logout-button"
        className="btn-primary" 
        style={{ 
          width: 'auto', 
          padding: '8px 16px', 
          fontSize: '0.9rem' 
        }}
      >
        Logout
      </button>
    </div>
  );
}

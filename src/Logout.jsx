import { signOut } from "firebase/auth";
import { auth } from "./firebase";

export default function Logout() {
  const handleLogout = async () => {
    await signOut(auth);
    window.location.reload(); // simplest reset for now
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


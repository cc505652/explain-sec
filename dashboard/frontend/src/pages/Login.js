import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { signInWithEmailAndPassword, signInWithPopup } from "firebase/auth";
import { doc, getDoc } from "firebase/firestore";
import { auth, db, googleProvider } from "../firebase/config";
import "../styles/auth.css";

export default function Login() {
  const navigate = useNavigate();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  const redirectByRole = (role) => {
    localStorage.setItem("role", role);
    if (role === "admin") navigate("/admin");
    else if (role === "analyst") navigate("/analyst");
    else navigate("/student");
  };

  const fetchUserRole = async (uid) => {
    const snap = await getDoc(doc(db, "users", uid));
    return snap.exists() ? snap.data().role : "student";
  };

  const handleEmailLogin = async (e) => {
    e.preventDefault();
    setError("");
    try {
      const res = await signInWithEmailAndPassword(auth, email, password);
      const role = await fetchUserRole(res.user.uid);
      redirectByRole(role);
    } catch {
      setError("Invalid email or password");
    }
  };

  const handleGoogleLogin = async () => {
    setError("");
    try {
      const res = await signInWithPopup(auth, googleProvider);
      const role = await fetchUserRole(res.user.uid);
      redirectByRole(role);
    } catch {
      setError("Google login failed");
    }
  };

  return (
    <div className="login-bg">
      <div className="login-card">
        <h2>Welcome Back</h2>
        <p className="subtitle">Login to your security dashboard</p>

        {error && <div className="auth-error">{error}</div>}

        <form onSubmit={handleEmailLogin}>
          <input
            type="email"
            placeholder="Email Address"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />

          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />

          <button type="submit" className="primary-btn">
            Login
          </button>
        </form>

        <div className="divider">OR</div>

        <button className="google-btn" onClick={handleGoogleLogin}>
          Continue with Google
        </button>

        <div className="auth-links">
          <Link to="/signup">Create Account</Link>
          <Link to="/reset">Forgot Password?</Link>
        </div>
      </div>
    </div>
  );
}


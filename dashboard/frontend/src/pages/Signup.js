import { useState } from "react";
import { createUserWithEmailAndPassword } from "firebase/auth";
import { auth, db } from "../firebase/config";
import { doc, setDoc } from "firebase/firestore";
import { useNavigate, Link } from "react-router-dom";

export default function Signup() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const navigate = useNavigate();

  const signup = async () => {
    try {
      const cred = await createUserWithEmailAndPassword(auth, email, password);

      // Create user profile in Firestore
      await setDoc(doc(db, "users", cred.user.uid), {
        email,
        role: "student",
        createdAt: new Date()
      });

      navigate("/student");
    } catch (err) {
      alert("Signup failed");
    }
  };

  return (
    <div className="login-bg">
      <div className="login-card">
        <div className="login-icon">🛡️</div>
        <h2>Create Account</h2>
        <p>Sign up to use the security protection system.</p>

        <div className="input-group">
          <label>Email Address</label>
          <input
            type="email"
            placeholder="student@campus.edu"
            onChange={e => setEmail(e.target.value)}
          />
        </div>

        <div className="input-group">
          <label>Password</label>
          <input
            type="password"
            placeholder="Create a strong password"
            onChange={e => setPassword(e.target.value)}
          />
        </div>

        <button className="primary-btn" onClick={signup}>
          Sign Up →
        </button>

        <p className="signup-link">
          Already have an account? <Link to="/">Sign in</Link>
        </p>

        <p className="secure-note">🔒 Your account is protected with secure authentication.</p>
      </div>
    </div>
  );
}


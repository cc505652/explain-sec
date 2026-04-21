// src/Login.jsx
import React, { useState } from 'react';
import { signInWithEmailAndPassword } from "firebase/auth";
import { auth } from "./firebase";

const Login = ({ onLoginSuccess }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(''); // State to handle error messages
  const [loading, setLoading] = useState(false);
  const [creatingUser, setCreatingUser] = useState(false);


  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      // 1. Attempt to sign in with Firebase
      const userCredential = await signInWithEmailAndPassword(auth, email, password);
      console.log("Logged in as:", userCredential.user.email);

      // 2. Clear inputs
      setEmail('');
      setPassword('');

      // 3. Notify App.jsx (or Redirect) that login succeeded
      // If you are using React Router, use: navigate('/dashboard')
      if (onLoginSuccess) {
        onLoginSuccess(userCredential.user);
      } else {
        // Fallback if no prop is passed (common in simple apps)
        window.location.reload();
      }

    } catch (err) {
      console.error("Login Error:", err.message);
      // Show a friendly error message
      setError("Invalid Email or Password. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '1rem'
    }}>

      {/* The Glass Card */}
      <div className="glass-panel" style={{ width: '100%', maxWidth: '420px', padding: '2.5rem' }}>

        {/* Header / Logo */}
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <div style={{
            width: '60px', height: '60px',
            background: 'var(--primary)',
            borderRadius: '16px',
            margin: '0 auto 1rem',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 0 20px var(--primary-glow)'
          }}>
            <span className="material-symbols-rounded" style={{ fontSize: '32px', color: 'white' }}>grid_view</span>
          </div>
          <h2 style={{ fontSize: '1.8rem', marginBottom: '0.5rem' }}>Security Operations Login</h2>
          <p style={{ color: 'var(--text-muted)' }}>Access the Cyber Incident Response Platform</p>
        </div>

        {/* Error Message Alert */}
        {error && (
          <div style={{
            background: 'rgba(239, 68, 68, 0.2)',
            border: '1px solid var(--danger)',
            color: '#fca5a5',
            padding: '10px',
            borderRadius: '8px',
            marginBottom: '1rem',
            fontSize: '0.9rem',
            textAlign: 'center'
          }}>
            <span className="material-symbols-rounded" style={{ verticalAlign: 'middle', fontSize: '16px', marginRight: '5px' }}>error</span>
            {error}
          </div>
        )}


        {/* Form */}
        <form onSubmit={handleLogin} data-testid="login-form">
          <div style={{ marginBottom: '1.5rem' }}>
            <label>Email Address</label>
            <input
              type="email"
              placeholder="domain@explainsec.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              data-testid="email-input"
            />
          </div>

          <div style={{ marginBottom: '1.5rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
              <label style={{ marginBottom: 0 }}>Password</label>
              <a href="#" style={{ fontSize: '0.85rem', color: 'var(--primary)', textDecoration: 'none' }}>Forgot?</a>
            </div>
            <input
              type="password"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              data-testid="password-input"
            />
          </div>

          <button type="submit" className="btn-primary" disabled={loading || creatingUser} data-testid="login-button">
            {loading ? 'Authenticating...' : creatingUser ? 'Creating User...' : 'Sign In'}
            {!loading && !creatingUser && <span className="material-symbols-rounded">arrow_forward</span>}
          </button>
        </form>

        {/* Footer */}
        <div style={{ textAlign: 'center', marginTop: '2rem' }}>
          <p style={{ fontSize: '0.8rem', color: '#475569', marginBottom: '0.5rem' }}>
            <span className="material-symbols-rounded" style={{ fontSize: '12px', verticalAlign: 'middle' }}>lock</span>
            &nbsp; SOC Secure Access • Authorized Security Personnel Only
          </p>
        </div>
      </div>
    </div>
  );
};

export default Login;

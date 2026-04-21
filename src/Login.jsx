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

  // Quick login account mapping for all SOC roles
  const QUICK_LOGIN_ACCOUNTS = {
    admin:          { email: 'admin@explainsec.com',          password: 'test1234', label: 'Admin',          icon: 'shield_person'  },
    soc_manager:    { email: 'cc505652@gmail.com',            password: 'test1234', label: 'SOC Manager',    icon: 'admin_panel_settings' },
    soc_l1:         { email: 'analyst@explainsec.com',        password: 'test1234', label: 'SOC L1 Analyst', icon: 'search' },
    soc_l2:         { email: 'analyst1@explainsec.com',       password: 'test1234', label: 'SOC L2 Analyst', icon: 'troubleshoot' },
    ir:             { email: 'ir_team@explainsec.com',        password: 'test1234', label: 'Incident Response', icon: 'emergency' },
    threat_hunter:  { email: 'threat_hunter@explainsec.com',  password: 'test1234', label: 'Threat Hunter', icon: 'target' },
    student:        { email: 'student@explainsec.com',        password: 'test1234', label: 'Student',        icon: 'school' },
  };

  const quickLogin = async (role) => {
    setError('');
    setLoading(true);

    const account = QUICK_LOGIN_ACCOUNTS[role];
    if (!account) {
      setError(`Unknown role: ${role}`);
      setLoading(false);
      return;
    }

    try {
      const userCredential = await signInWithEmailAndPassword(auth, account.email, account.password);
      console.log(`✅ Quick login as ${role}:`, userCredential.user.email);

      setEmail('');
      setPassword('');
      if (onLoginSuccess) {
        onLoginSuccess(userCredential.user);
      } else {
        window.location.reload();
      }
    } catch (err) {
      console.error(`Quick login failed for ${role}:`, err.code, err.message);
      if (err.code === 'auth/wrong-password' || err.code === 'auth/invalid-credential') {
        setError(`Login failed for ${account.email}. Check that the password is correct.`);
      } else if (err.code === 'auth/user-not-found') {
        setError(`Account ${account.email} does not exist. Please create it in the Admin panel first.`);
      } else {
        setError('Login failed. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

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

        {/* Quick Login Buttons */}
        <div style={{ marginTop: '2rem', paddingTop: '1rem', borderTop: '1px solid rgba(255,255,255,0.1)' }}>
          <p style={{ textAlign: 'center', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
            Quick Login
          </p>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
            {Object.entries(QUICK_LOGIN_ACCOUNTS).map(([role, acct]) => {
              const colorMap = {
                admin:         { bg: 'rgba(25, 118, 210, 0.2)',  border: 'rgba(25, 118, 210, 0.5)',  text: '#64b5f6' },
                soc_manager:   { bg: 'rgba(156, 39, 176, 0.2)',  border: 'rgba(156, 39, 176, 0.5)',  text: '#ce93d8' },
                soc_l1:        { bg: 'rgba(0, 150, 136, 0.2)',   border: 'rgba(0, 150, 136, 0.5)',   text: '#80cbc4' },
                soc_l2:        { bg: 'rgba(211, 47, 47, 0.2)',   border: 'rgba(211, 47, 47, 0.5)',   text: '#ef5350' },
                ir:            { bg: 'rgba(255, 152, 0, 0.2)',   border: 'rgba(255, 152, 0, 0.5)',   text: '#ffb74d' },
                threat_hunter: { bg: 'rgba(63, 81, 181, 0.2)',   border: 'rgba(63, 81, 181, 0.5)',   text: '#7986cb' },
                student:       { bg: 'rgba(56, 142, 60, 0.2)',   border: 'rgba(56, 142, 60, 0.5)',   text: '#81c784' },
              };
              const c = colorMap[role] || colorMap.student;
              return (
                <button
                  key={role}
                  onClick={() => quickLogin(role)}
                  disabled={loading}
                  style={{
                    background: c.bg,
                    border: `1px solid ${c.border}`,
                    color: c.text,
                    padding: '8px 10px',
                    borderRadius: '8px',
                    fontSize: '0.78rem',
                    cursor: loading ? 'not-allowed' : 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '5px',
                    transition: 'all 0.2s ease',
                  }}
                  title={acct.email}
                >
                  <span className="material-symbols-rounded" style={{ fontSize: '15px' }}>{acct.icon}</span>
                  {acct.label}
                </button>
              );
            })}
          </div>
        </div>

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
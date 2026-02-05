import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import { useEffect, useState } from "react";
import { onAuthStateChanged } from "firebase/auth";
import { auth } from "./firebase/config";

import Login from "./pages/Login";
import Signup from "./pages/Signup";
import StudentDashboard from "./pages/StudentDashboard";
import AnalystDashboard from "./pages/AnalystDashboard";
import AdminDashboard from "./pages/AdminDashboard";

function ProtectedRoute({ children, role }) {
  const [authState, setAuthState] = useState("loading"); // loading | loggedOut | loggedIn

  useEffect(() => {
    const unsub = onAuthStateChanged(auth, (user) => {
      setAuthState(user ? "loggedIn" : "loggedOut");
    });
    return () => unsub();
  }, []);

  if (authState === "loading") return null; // prevents flicker

  if (authState === "loggedOut") return <Navigate to="/login" />;

  const storedRole = localStorage.getItem("role");

  if (role && storedRole !== role) return <Navigate to="/login" />;

  return children;
}

export default function App() {
  return (
    <Router>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<Signup />} />

        <Route path="/student" element={
          <ProtectedRoute role="student">
            <StudentDashboard />
          </ProtectedRoute>
        }/>

        <Route path="/analyst" element={
          <ProtectedRoute role="analyst">
            <AnalystDashboard />
          </ProtectedRoute>
        }/>

        <Route path="/admin" element={
          <ProtectedRoute role="admin">
            <AdminDashboard />
          </ProtectedRoute>
        }/>

        <Route path="*" element={<Navigate to="/login" />} />
      </Routes>
    </Router>
  );
}

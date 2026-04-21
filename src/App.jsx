import { createContext, useContext, useEffect, useState } from "react";
import { BrowserRouter as Router, Routes, Route, Navigate, useNavigate, useLocation } from "react-router-dom";
import Login from "./Login";
import SubmitIssue from "./SubmitIssue";
import IssueList from "./IssueList";
import AnalystDashboard from "./AnalystDashboard"; // SOC Analyst Console
import AdminDashboard from "./AdminDashboard"; // Admin Dashboard
import SOCManager_CommandConsole from "./SOCManager_CommandConsole"; // SOC Manager Console
import SOCManagerDashboard from "./SOCManagerDashboard"; // SOC Manager Dashboard
import AnalyticsPanel from "./components/AnalyticsPanel"; // Phase 3: Analytics
import Logout from "./Logout";
import { auth, db } from "./firebase";
import { doc, getDoc, setDoc, serverTimestamp } from "firebase/firestore";
import { signOut } from "firebase/auth";
import { normalizeRole } from "./utils/normalizeRole";

const AuthContext = createContext({
  user: null,
  role: null,
  isAuthLoading: true,
});

function useAuth() {
  return useContext(AuthContext);
}

function ProtectedRoute({ allowedRoles, children }) {
  const { user, role, isAuthLoading } = useAuth();

  if (isAuthLoading) return null;

  if (!user || !role) {
    return <Navigate to="/" replace />;
  }

  const normalizedRole = normalizeRole(role);
  const normalizedAllowedRoles = allowedRoles
    .map((allowedRole) => normalizeRole(allowedRole))
    .filter(Boolean);

  if (!normalizedAllowedRoles.includes(normalizedRole)) {
    return <Navigate to="/" replace />;
  }

  return children;
}

function AuthProvider({ children }) {
  const [authState, setAuthState] = useState({
    user: null,
    role: null,
    isAuthLoading: true,
  });

  useEffect(() => {
    let isActive = true;

    const resolveAuthState = (user, role) => {
      if (!isActive) return;

      setAuthState({
        user: user ?? null,
        role: role ?? null,
        isAuthLoading: false,
      });
      
      // Allow React state to flush - critical for Firefox during rapid role switching
      if (typeof queueMicrotask === 'function') {
        queueMicrotask(() => {
          // State flush complete
        });
      }
    };

    const unsub = auth.onAuthStateChanged(async (firebaseUser) => {
      if (!isActive) return;

      if (!firebaseUser) {
        resolveAuthState(null, null);
        return;
      }

      setAuthState({
        user: null,
        role: null,
        isAuthLoading: true,
      });

      try {
        const userRef = doc(db, "users", firebaseUser.uid);
        const snap = await getDoc(userRef);

        if (snap.exists()) {
          const userData = snap.data();
          const userRole = normalizeRole(userData.role);
          const userStatus = userData.status || "active";

          // Check if user status allows login
          if (userStatus === "suspended") {
            await signOut(auth);
            alert("Your account has been suspended. Please contact an administrator.");
            resolveAuthState(null, null);
            return;
          }

          if (userStatus === "inactive") {
            await signOut(auth);
            alert("Your account is inactive. Please contact an administrator.");
            resolveAuthState(null, null);
            return;
          }

          resolveAuthState(firebaseUser, userRole);
          return;
        }

        // First-time login -> default to student
        // BUG FIX #7: include team and analystLevel so AnalystDashboard gets correct context
        await setDoc(userRef, {
          role: "student",
          team: "student",
          analystLevel: null,
          status: "active",
          createdAt: serverTimestamp()
        });
        resolveAuthState(firebaseUser, "student");
      } catch (error) {
        console.error("Auth initialization failed:", error);
        resolveAuthState(null, null);
      }
    });

    return () => {
      isActive = false;
      unsub();
    };
  }, []);

  return (
    <AuthContext.Provider value={authState}>
      {children}
    </AuthContext.Provider>
  );
}

function AppContent() {
  const { user, role, isAuthLoading } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    // Only proceed if auth state is fully loaded
    if (isAuthLoading || !user || !role) return;

    // Role-based redirects - only redirect if not already on a valid route
    const normalizedRole = normalizeRole(role);
    const adminRoutes = ["/admin", "/analytics", "/command-console"];
    const managerRoutes = ["/soc-manager", "/command-console", "/analytics"];
    const analystRoles = ["soc_l1", "soc_l2", "ir", "threat_hunter"];

    if (normalizedRole === "admin" && !adminRoutes.includes(location.pathname)) {
      navigate("/admin", { replace: true });
    } else if (normalizedRole === "soc_manager" && !managerRoutes.includes(location.pathname)) {
      navigate("/soc-manager", { replace: true });
    } else if (analystRoles.includes(normalizedRole) && location.pathname !== "/") {
      navigate("/", { replace: true });
    } else if (normalizedRole === "student" && location.pathname !== "/") {
      navigate("/", { replace: true });
    }
  }, [isAuthLoading, location.pathname, navigate, role, user]);

  if (isAuthLoading) {
    return <div>Loading...</div>;
  }

  if (!user || !role) {
    if (location.pathname !== "/") {
      return <Navigate to="/" replace />;
    }

    return <Login />;
  }

  console.log("CURRENT USER ROLE:", role);

  return (
    <div style={{ display: "flex", flexDirection: "column", minHeight: "100vh" }}>
      <div style={{ flex: 1, padding: "2rem" }}>
        <Routes>
          <Route
            path="/admin"
            element={
              <ProtectedRoute allowedRoles={["admin"]}>
                <AdminDashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="/soc-manager"
            element={
              <ProtectedRoute allowedRoles={["soc_manager"]}>
                <SOCManagerDashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="/command-console"
            element={
              <ProtectedRoute allowedRoles={["admin", "soc_manager"]}>
                <SOCManager_CommandConsole />
              </ProtectedRoute>
            }
          />
          <Route
            path="/analytics"
            element={
              <ProtectedRoute allowedRoles={["admin", "soc_manager"]}>
                <AnalyticsPanel userRole={role} />
              </ProtectedRoute>
            }
          />
        </Routes>

        {normalizeRole(role) === "student" && (
          <>
            <SubmitIssue />
            <hr />
            <IssueList />
          </>
        )}

        {/* SOC ANALYST CONSOLE - For all operational roles */}
        {["soc_l1", "soc_l2", "ir", "threat_hunter"].includes(normalizeRole(role)) && (
          <AnalystDashboard />
        )}

        {/* SOC MANAGER CONSOLE */}
        {normalizeRole(role) === "admin" && null}

      </div>
      <Logout />
    </div>
  );
}

function App() {
  return (
    <Router>
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </Router>
  );
}

export default App;

import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  collection,
  doc,
  getDoc,
  getDocs,
  setDoc,
  updateDoc,
  query,
  where,
  orderBy,
  onSnapshot,
  serverTimestamp,
  Timestamp
} from 'firebase/firestore';
import {
  createUserWithEmailAndPassword,
  deleteUser as deleteAuthUser,
  updatePassword as updateAuthPassword,
  signOut
} from 'firebase/auth';
import { initializeApp, getApps } from "firebase/app";
import { getAuth } from "firebase/auth";
import { auth, db, app as firebaseApp } from './firebase';
import { callUpdateRole, callDeleteUser } from './utils/socFunctions';

import { normalizeRole, isVisibleToRole } from "./utils/roleNormalization";

// Role types mapping for conditional form fields
const ROLE_TYPES = {
  admin: "admin",
  soc_manager: "manager",
  soc_l1: "analyst",
  soc_l2: "analyst",
  ir: "analyst",
  threat_hunter: "analyst",
  student: "student"
};

// SECURITY FIX (VULN-18): Guard against duplicate initialization on HMR (hot module reload)
// Use centralized Firebase app from firebase.js to prevent project reference conflicts
const secondaryApp = getApps().find(a => a.name === "SecondaryApp")
  || initializeApp(firebaseApp.options, "SecondaryApp");
const secondaryAuth = getAuth(secondaryApp);

export default function AdminDashboard() {
  const navigate = useNavigate();

  // All useState hooks must be called first - NO conditional logic before any useState
  const [activeTab, setActiveTab] = useState('users');
  const [users, setUsers] = useState([]);
  const [roles, setRoles] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [workforceAnalytics, setWorkforceAnalytics] = useState({});
  const [loading, setLoading] = useState(true);
  const [showCreateUser, setShowCreateUser] = useState(false);
  const [editingUser, setEditingUser] = useState(null);
  const [showRoleConfig, setShowRoleConfig] = useState(false);
  const [editingRole, setEditingRole] = useState(null);
  const [activeModule, setActiveModule] = useState('incident_management');
  const [showAdvancedMatrix, setShowAdvancedMatrix] = useState(false);
  const [toast, setToast] = useState('');
  const [userRole, setUserRole] = useState(null);
  const [isAuthorized, setIsAuthorized] = useState(false);
  const [unsubscribeFunctions, setUnsubscribeFunctions] = useState({});

  // Role templates for quick setup
  const ROLE_TEMPLATES = {
    soc_l1: {
      name: "SOC Analyst L1",
      enabledModules: ["incident_management"],
      permissions: {
        view_incidents: true,
        start_triage: true,
        mark_false_positive: true
      }
    },
    soc_l2: {
      name: "SOC Analyst L2",
      enabledModules: ["incident_management", "containment"],
      permissions: {
        view_incidents: true,
        confirm_threat: true,
        escalate_to_ir: true,
        request_containment: true
      }
    },
    threat_hunter: {
      name: "Threat Hunter",
      enabledModules: ["incident_management", "threat_hunting"],
      permissions: {
        view_incidents: true,
        run_hunting_queries: true,
        create_queries: true,
        view_threat_intel: true
      }
    },
    ir: {
      name: "Incident Response",
      enabledModules: ["incident_management", "containment"],
      permissions: {
        view_incidents: true,
        execute_containment: true,
        approve_containment: true,
        resolve_incident: true
      }
    },
    soc_manager: {
      name: "SOC Manager",
      enabledModules: ["incident_management", "containment", "threat_hunting", "governance"],
      permissions: {
        view_incidents: true,
        confirm_threat: true,
        escalate_to_ir: true,
        resolve_incident: true,
        approve_containment: true,
        view_audit_logs: true,
        view_analytics: true
      }
    },
    admin: {
      name: "Administrator",
      enabledModules: ["incident_management", "containment", "threat_hunting", "governance", "system_admin"],
      permissions: {
        view_incidents: true,
        start_triage: true,
        confirm_threat: true,
        mark_false_positive: true,
        escalate_to_l2: true,
        escalate_to_ir: true,
        request_containment: true,
        execute_containment: true,
        resolve_incident: true,
        lock_incident: true,
        approve_containment: true,
        run_hunting_queries: true,
        create_queries: true,
        view_threat_intel: true,
        view_audit_logs: true,
        view_reports: true,
        view_analytics: true,
        export_logs: true,
        manage_users: true,
        manage_roles: true,
        manage_soc_config: true,
        manage_playbooks: true
      }
    }
  };

  // Permission groups for auto-enabling permissions
  const GROUP_PERMISSIONS = {
    incident_management: [
      "view_incidents",
      "start_triage",
      "confirm_threat",
      "mark_false_positive",
      "escalate_to_l2",
      "escalate_to_ir",
      "request_containment",
      "execute_containment",
      "resolve_incident",
      "lock_incident"
    ],
    containment: [
      "request_containment",
      "execute_containment",
      "approve_containment",
      "block_ip",
      "isolate_host",
      "disable_user_account"
    ],
    threat_hunting: [
      "run_hunting_queries",
      "create_queries",
      "view_threat_intel",
      "pivot_search"
    ],
    governance: [
      "view_audit_logs",
      "view_reports",
      "view_analytics",
      "export_logs"
    ],
    system_admin: [
      "manage_users",
      "manage_roles",
      "manage_soc_config",
      "manage_playbooks"
    ]
  };

  // Form states
  const [newUser, setNewUser] = useState({
    name: '',
    email: '',
    password: '',
    role: '', // Will be set to first available role when roles load
    team: 'soc_l1',
    analystLevel: 'L1',
    status: 'active'
  });

  const [rolePermissions, setRolePermissions] = useState({
    // Permission groups
    permission_groups: {
      incident_management: false,
      threat_hunting: false,
      containment: false,
      governance: false,
      system_admin: false
    },
    // Individual permissions
    permissions: {
      // Incident Management
      view_incidents: false,
      start_triage: false,
      confirm_threat: false,
      mark_false_positive: false,
      escalate_to_l2: false,
      escalate_to_ir: false,
      request_containment: false,
      execute_containment: false,
      resolve_incident: false,
      lock_incident: false,
      approve_containment: false,

      // Threat Hunting
      run_hunting_queries: false,
      create_queries: false,
      view_threat_intel: false,
      pivot_search: false,

      // Governance
      view_audit_logs: false,
      view_reports: false,
      view_analytics: false,
      export_logs: false,

      // System Admin
      manage_users: false,
      manage_roles: false,
      manage_soc_config: false,
      manage_playbooks: false,

      // Containment
      block_ip: false,
      isolate_host: false,
      disable_user_account: false
    },
    // Scope
    scope: 'unassigned'
  });

  // SOC Configuration
  const [socConfig, setSocConfig] = useState({
    slaTimes: {
      open: 24,
      assigned: 48,
      in_progress: 72
    },
    autoEscalation: {
      enabled: true,
      thresholdHours: 48,
      escalateTo: 'soc_l2'
    },
    classificationThresholds: {
      highSeverityAutoEscalate: true,
      mediumSeverityReviewRequired: true,
      falsePositiveThreshold: 3
    }
  });

  // Seed default roles if they don't exist
  const seedDefaultRoles = async () => {
    try {
      const rolesRef = collection(db, 'roles');
      const rolesSnapshot = await getDocs(rolesRef);

      if (rolesSnapshot.empty) {
        console.log('🌱 Seeding default roles...');

        const defaultRoles = [
          {
            id: 'soc_l1',
            name: "SOC Analyst L1",
            roleId: "soc_l1",
            scope: "unassigned",
            enabledModules: ["incident_management"],
            createdAt: serverTimestamp()
          },
          {
            id: 'soc_l2',
            name: "SOC Analyst L2",
            roleId: "soc_l2",
            scope: "escalated",
            enabledModules: ["incident_management", "containment"],
            createdAt: serverTimestamp()
          },
          {
            id: 'threat_hunter',
            name: "Threat Hunter",
            roleId: "threat_hunter",
            scope: "all",
            enabledModules: ["incident_management", "threat_hunting"],
            createdAt: serverTimestamp()
          },
          {
            id: 'ir',
            name: "Incident Response",
            roleId: "ir",
            scope: "ir_only",
            enabledModules: ["incident_management", "containment"],
            createdAt: serverTimestamp()
          },
          {
            id: 'soc_manager',
            name: "SOC Manager",
            roleId: "soc_manager",
            scope: "all",
            enabledModules: ["incident_management", "containment", "threat_hunting", "governance"],
            createdAt: serverTimestamp()
          },
          {
            id: 'admin',
            name: "Administrator",
            roleId: "admin",
            scope: "all",
            enabledModules: ["incident_management", "containment", "threat_hunting", "governance", "system_admin"],
            createdAt: serverTimestamp()
          }
        ];

        // Create all default roles
        for (const role of defaultRoles) {
          await setDoc(doc(db, 'roles', role.id), role);
        }

        console.log('✅ Default roles seeded successfully');
      } else {
        console.log('📋 Roles already exist, skipping seeding');
      }
    } catch (error) {
      console.error('Error seeding default roles:', error);
    }
  };

  // BUG FIX #14: Admin check no longer depends on roles collection existence
  // Falls back to direct role check if roles collection is unavailable
  const checkIfUserIsAdmin = async (userRole) => {
    // Normalize role before checking
    const normalizedRole = normalizeRole(userRole);
    
    // Direct role check first (works even without roles collection seeded)
    if (normalizedRole === 'admin') return true;

    try {
      const roleDoc = await getDoc(doc(db, 'roles', normalizedRole));
      if (!roleDoc.exists()) {
        // roles collection not seeded yet — trust the direct role field
        console.log(`Role ${normalizedRole} not found in roles collection; falling back to role field`);
        return normalizedRole === 'admin';
      }
      const roleData = roleDoc.data();
      const hasSystemAdmin = roleData.enabledModules?.includes('system_admin') || false;
      console.log(`User role: ${normalizedRole}, has system_admin: ${hasSystemAdmin}`);
      return hasSystemAdmin;
    } catch (error) {
      // On Firestore error, fall back to direct role check
      console.error('Error checking admin role:', error);
      return normalizedRole === 'admin';
    }
  };

  // Combined authorization and data loading useEffect
  useEffect(() => {
    const initializeDashboard = async () => {
      const currentUser = auth.currentUser;
      if (!currentUser) {
        navigate('/');
        return;
      }

      try {
        // Check user role first
        const userDoc = await getDoc(doc(db, 'users', currentUser.uid));
        if (!userDoc.exists()) {
          console.error('User document not found');
          navigate('/');
          return;
        }

        const userData = userDoc.data();

        // Check if user has admin privileges by checking against roles collection
        const isAdmin = await checkIfUserIsAdmin(userData.role);

        if (!isAdmin) {
          console.error('Access denied: User does not have admin privileges');
          // Redirect to appropriate dashboard based on role
          const normalizedRole = normalizeRole(userData.role);
          if (normalizedRole === 'soc_manager') {
            navigate('/soc-manager');
          } else if (normalizedRole === 'soc_l1' || normalizedRole === 'soc_l2' || normalizedRole === 'ir') {
            navigate('/');
          } else if (normalizedRole === 'student') {
            navigate('/');
          } else {
            // For other roles like 'ir', 'threat_hunter', etc., redirect to main dashboard
            navigate('/');
          }
          return;
        }

        // User is authorized - set states and load data
        setUserRole(userData.role);
        setIsAuthorized(true);

        // Load all dashboard data
        await loadDashboardData();

        setLoading(false);
      } catch (error) {
        console.error('Error initializing dashboard:', error);
        navigate('/');
      }
    };

    initializeDashboard();
  }, [navigate]);

  // Cleanup effect for real-time listeners
  useEffect(() => {
    return () => {
      // Unsubscribe from all real-time listeners when component unmounts
      Object.values(unsubscribeFunctions).forEach(unsubscribe => {
        if (typeof unsubscribe === 'function') {
          unsubscribe();
        }
      });
    };
  }, [unsubscribeFunctions]);

  // Set default role for new users when roles are loaded
  useEffect(() => {
    if (roles.length > 0 && !newUser.role) {
      const firstRole = roles[0];
      setNewUser(prev => ({ ...prev, role: firstRole.id }));
      console.log(`📋 Set default role for new users: ${firstRole.name} (${firstRole.id})`);
    }
  }, [roles, newUser.role]);

  // Load dashboard data function
  const loadDashboardData = async () => {
    try {
      // Seed default roles first
      await seedDefaultRoles();

      // Load all data with real-time listeners
      const usersUnsubscribe = await loadUsers();
      const rolesUnsubscribe = await loadRoles();
      const logsUnsubscribe = await loadAuditLogs();

      // Load one-time data
      await Promise.all([
        loadWorkforceAnalytics(),
        loadSocConfig()
      ]);

      // Store unsubscribe functions for cleanup
      setUnsubscribeFunctions({
        users: usersUnsubscribe,
        roles: rolesUnsubscribe,
        logs: logsUnsubscribe
      });
    } catch (error) {
      console.error('Error loading dashboard data:', error);
    }
  };

  const loadUsers = async () => {
    try {
      console.log("Setting up real-time listener for users collection...");
      const unsubscribe = onSnapshot(collection(db, 'users'), (snapshot) => {
        const usersData = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        console.log(`Real-time update: ${usersData.length} users loaded:`, usersData.map(u => ({ id: u.id, name: u.name, email: u.email, role: u.role })));
        setUsers(usersData);
      }, (error) => {
        console.error('Error in users listener:', error);
      });
      return unsubscribe;
    } catch (error) {
      console.error('Error setting up users listener:', error);
    }
  };

  const loadRoles = async () => {
    try {
      // Set up real-time listener for roles collection
      const unsubscribe = onSnapshot(collection(db, 'roles'), (snapshot) => {
        const rolesData = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        
        // Filter roles to remove duplicates - keep only canonical normalized IDs
        const normalizedRolesMap = new Map();
        rolesData.forEach(role => {
          const normalizedId = normalizeRole(role.id);
          if (normalizedId) {
            // If we already have this normalized role, keep the one with matching normalized ID
            if (normalizedRolesMap.has(normalizedId)) {
              const existing = normalizedRolesMap.get(normalizedId);
              // Prefer the role whose ID matches the normalized version
              if (role.id === normalizedId) {
                normalizedRolesMap.set(normalizedId, role);
              }
            } else {
              normalizedRolesMap.set(normalizedId, role);
            }
          }
        });
        
        const filteredRoles = Array.from(normalizedRolesMap.values());
        setRoles(filteredRoles);
        console.log('📋 Roles updated in real-time (filtered):', filteredRoles.map(r => r.name));
      });

      // Store unsubscribe function for cleanup
      return unsubscribe;
    } catch (error) {
      console.error('Error loading roles:', error);
    }
  };

  const loadAuditLogs = async () => {
    try {
      const logsQuery = query(collection(db, 'audit_logs'), orderBy('timestamp', 'desc'), where('timestamp', '>=', Timestamp.fromDate(new Date(Date.now() - 7 * 24 * 60 * 60 * 1000))));
      const unsubscribe = onSnapshot(logsQuery, (snapshot) => {
        const logsData = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        setAuditLogs(logsData);
      });
      return unsubscribe;
    } catch (error) {
      console.error('Error loading audit logs:', error);
    }
  };

  const loadWorkforceAnalytics = () => {
    const unsubscribe = onSnapshot(
      collection(db, 'users'),
      (snapshot) => {
        const allUsers = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));

        // Use canonical normalized roles — avoids the 'analyst' un-normalized false-zero bug
        const OPERATIVE_ROLES = ['soc_l1', 'soc_l2', 'ir', 'threat_hunter', 'soc_manager'];
        const totalAnalysts = allUsers.filter(user =>
          OPERATIVE_ROLES.includes(normalizeRole(user.role))
        ).length;
        const activeAnalysts = allUsers.filter(user =>
          OPERATIVE_ROLES.includes(normalizeRole(user.role)) && user.status === 'active'
        ).length;

        const incidentsPerAnalyst = calculateIncidentsPerAnalyst(allUsers);

        setWorkforceAnalytics({
          totalAnalysts,
          activeAnalysts,
          incidentsPerAnalyst
        });
        console.log("REALTIME UPDATE: Workforce analytics updated");
      },
      (error) => {
        console.error("Firestore listener error (workforce analytics):", error);
      }
    );

    return unsubscribe;
  };


  const calculateIncidentsPerAnalyst = (users) => {
    // Returns real user list for workforce display (no random placeholder)
    const OPERATIVE_ROLES = ['soc_l1', 'soc_l2', 'ir', 'threat_hunter'];
    return users
      .filter(user => OPERATIVE_ROLES.includes(normalizeRole(user.role)))
      .map(user => ({
        name: user.name || user.email || 'Unknown',
        email: user.email,
        incidentsHandled: 0  // real count wired via incidents query when needed
      }));
  };


  const loadSocConfig = async () => {
    try {
      const configDoc = await getDoc(doc(db, 'config', 'soc_settings'));
      if (configDoc.exists()) {
        setSocConfig(configDoc.data());
      }
    } catch (error) {
      console.error('Error loading SOC config:', error);
    }
  };

  // PHASE 1 FIX: logAuditAction — client writes to audit_logs are BLOCKED by Firestore rules
  // (create: false, update: false, delete: false — unconditional).
  // Real audit entries are written server-side by Cloud Functions via Admin SDK.
  // This is now a console-only log for debugging; the actual audit trail comes from CFs.
  const logAuditAction = async (action, targetUser = null) => {
    console.log(`📋 [AUDIT] ${action}`, { performedBy: auth.currentUser?.uid, targetUser });
    // Note: audit_logs collection is immutable from client. Cloud Functions handle real audit writes.
  };

  const showToast = (message) => {
    setToast(message);
    setTimeout(() => setToast(''), 3000);
  };

  const createUser = async () => {
    let originalUser = null;
    let adminEmail = null;

    try {
      // Store the current admin user info
      originalUser = auth.currentUser;

      if (!originalUser) {
        throw new Error('No admin user session found');
      }

      adminEmail = originalUser.email;

      // Validate role before creating user
      const normalizedRole = normalizeRole(newUser.role);
      const validRole = roles.find(r => r.id === normalizedRole);
      if (!validRole) {
        throw new Error(`Invalid role selected: ${newUser.role} (normalized: ${normalizedRole}). Role must exist in the roles collection.`);
      }
      console.log(`✅ Creating user with valid role: ${validRole.name} (${validRole.id})`);

      // Conditional validation for analyst roles
      const roleType = ROLE_TYPES[normalizedRole];
      if (roleType === "analyst") {
        if (!newUser.team) {
          throw new Error('Team is required for analyst roles');
        }
        if (!newUser.analystLevel) {
          throw new Error('Analyst Level is required for analyst roles');
        }
      }

      // Create Firebase Auth user using secondary auth instance
      const userCredential = await createUserWithEmailAndPassword(secondaryAuth, newUser.email, newUser.password);
      const uid = userCredential.user.uid;

      // Create Firestore user document with normalized role
      const userData = {
        name: newUser.name,
        email: newUser.email,
        role: normalizedRole,
        status: newUser.status,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp()
      };

      // Only add team and analystLevel for analyst roles
      if (roleType === "analyst") {
        userData.team = newUser.team;
        userData.analystLevel = newUser.analystLevel;
      }

      await setDoc(doc(db, 'users', uid), userData);

      // Log audit action
      await logAuditAction('user_created', uid);

      // Sign out from secondary auth to cleanup session
      await signOut(secondaryAuth);

      // Check if admin session is still active
      const currentUser = auth.currentUser;
      if (!currentUser || currentUser.uid !== originalUser.uid) {
        console.warn('Admin session changed during user creation');
        showToast('User created successfully. Please verify your admin session.');
      } else {
        showToast('User created successfully!');
      }

      // Reset form
      setNewUser({
        name: '',
        email: '',
        password: '',
        role: 'analyst',
        team: 'soc_l1',
        analystLevel: 'L1',
        status: 'active'
      });
      setShowCreateUser(false);

    } catch (error) {
      console.error('Error creating user:', error);

      // Cleanup secondary auth in case of error
      try {
        await signOut(secondaryAuth);
      } catch (cleanupError) {
        console.error('Error cleaning up secondary auth:', cleanupError);
      }

      if (error.code === 'auth/email-already-in-use') {
        showToast('Error: Email already exists in Firebase Auth');
      } else if (error.code === 'auth/weak-password') {
        showToast('Error: Password is too weak');
      } else if (error.code === 'auth/invalid-email') {
        showToast('Error: Invalid email format');
      } else {
        showToast('Error creating user: ' + error.message);
      }

      // Check if admin session was lost
      setTimeout(() => {
        const currentUser = auth.currentUser;
        if (!currentUser || currentUser.uid !== originalUser?.uid) {
          showToast('Session disrupted. You may need to log in again.');
        }
      }, 1000);
    }
  };

  const updateUser = async (userId, updates) => {
    try {
      // Validate role if it's being updated
      if (updates.role) {
        const normalizedRole = normalizeRole(updates.role);
        const validRole = roles.find(r => r.id === normalizedRole);
        if (!validRole) {
          throw new Error(`Invalid role selected: ${updates.role} (normalized: ${normalizedRole}). Role must exist in the roles collection.`);
        }
        console.log(`✅ Valid role assignment: ${validRole.name} (${validRole.id})`);

        // Conditional validation for analyst roles
        const roleType = ROLE_TYPES[normalizedRole];
        if (roleType === "analyst") {
          if (!updates.team) throw new Error('Team is required for analyst roles');
          if (!updates.analystLevel) throw new Error('Analyst Level is required for analyst roles');
        }

        // SECURITY FIX: Route role changes through Cloud Function
        // The CF enforces admin-only server-side; raw updateDoc relies on rules alone.
        await callUpdateRole(userId, normalizedRole, updates.team, updates.analystLevel);

        // Strip role-related fields — they were handled by the Cloud Function
        const { role: _r, team: _t, analystLevel: _a, ...metaUpdates } = updates;
        // Update any remaining metadata fields (name, status, etc.) directly
        if (Object.keys(metaUpdates).length > 0) {
          await updateDoc(doc(db, 'users', userId), {
            ...metaUpdates,
            updatedAt: serverTimestamp()
          });
        }
      } else {
        // No role change — safe to direct-write all fields
        await updateDoc(doc(db, 'users', userId), {
          ...updates,
          updatedAt: serverTimestamp()
        });
      }

      await logAuditAction('user_updated', userId);
      showToast('User updated successfully!');
      setEditingUser(null);
    } catch (error) {
      console.error('Error updating user:', error);
      showToast('Error updating user: ' + error.message);
    }
  };


  const deleteUser = async (userId) => {
    if (!confirm('Are you sure you want to delete this user? This action cannot be undone.')) {
      return;
    }

    try {
      // Delegate entirely to the deleteUser Cloud Function.
      // It uses Admin SDK to remove the user from Firebase Auth + Firestore atomically.
      await callDeleteUser(userId);
      await logAuditAction('user_deleted', userId);
      showToast('User deleted successfully!');
    } catch (error) {
      console.error('Error deleting user:', error);
      showToast('Error deleting user: ' + (error.message || 'Unknown error'));
    }
  };


  const saveRolePermissions = async (roleName) => {
    try {
      // Check if role already exists
      const roleRef = doc(db, 'roles', roleName);
      const roleSnap = await getDoc(roleRef);

      const roleData = {
        roleId: roleName,
        name: roleName.charAt(0).toUpperCase() + roleName.slice(1),
        permission_groups: rolePermissions.permission_groups,
        permissions: rolePermissions.permissions,
        scope: rolePermissions.scope,
        updatedAt: serverTimestamp(),
        updatedBy: auth.currentUser?.uid
      };

      // Add createdAt only for new roles
      if (!roleSnap.exists()) {
        roleData.createdAt = serverTimestamp();
        console.log(`✅ Creating new role: ${roleData.name}`);
      } else {
        console.log(`📝 Updating existing role: ${roleData.name}`);
      }

      await setDoc(roleRef, roleData, { merge: true });

      await logAuditAction('role_updated', roleName);
      showToast('Role permissions updated successfully!');
      setShowRoleConfig(false);
      setEditingRole(null);
      // loadRoles() is not needed since we have real-time listeners
    } catch (error) {
      console.error('Error saving role permissions:', error);
      showToast('Error saving role permissions: ' + error.message);
    }
  };

  const saveSocConfig = async () => {
    try {
      await setDoc(doc(db, 'config', 'soc_settings'), {
        ...socConfig,
        updatedAt: serverTimestamp(),
        updatedBy: auth.currentUser?.uid
      });

      await logAuditAction('soc_config_updated');
      alert('SOC configuration updated successfully!');
    } catch (error) {
      console.error('Error saving SOC config:', error);
      alert('Error saving SOC config: ' + error.message);
    }
  };

  const loadRolePermissions = async (roleName) => {
    try {
      const roleDoc = await getDoc(doc(db, 'roles', roleName));
      if (roleDoc.exists()) {
        const roleData = roleDoc.data();
        setRolePermissions({
          permission_groups: roleData.permission_groups || {
            incident_management: false,
            threat_hunting: false,
            containment: false,
            governance: false,
            system_admin: false
          },
          permissions: roleData.permissions || {
            view_incidents: false,
            start_triage: false,
            confirm_threat: false,
            mark_false_positive: false,
            escalate_to_l2: false,
            escalate_to_ir: false,
            request_containment: false,
            execute_containment: false,
            resolve_incident: false,
            lock_incident: false,
            approve_containment: false,
            run_hunting_queries: false,
            view_audit_logs: false,
            manage_users: false,
            manage_roles: false
          },
          scope: roleData.scope || 'unassigned'
        });
      }
    } catch (error) {
      console.error('Error loading role permissions:', error);
    }
  };

  const openRoleConfig = (roleName) => {
    setEditingRole(roleName);
    loadRolePermissions(roleName);
    setShowRoleConfig(true);
  };

  // Helper function to get display name for team
  const getTeamDisplayName = (team) => {
    switch (team) {
      case "soc_l1": return "SOC Analyst L1";
      case "soc_l2": return "SOC Analyst L2";
      case "incident_response": return "ir";
      case "threat_hunter": return "threat_hunter";
      default: return team || "Unassigned";
    }
  };

  // Helper function to get status with default
  const getUserStatus = (user) => {
    return user.status || "active";
  };

  // Loading state check - AFTER all hooks are called
  if (loading || !isAuthorized) {
    return (
      <div style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        height: '100vh',
        color: 'var(--text-main)'
      }}>
        Loading...
      </div>
    );
  }

  return (
    <div style={{ padding: 16 }}>

      {/* Toast Message */}
      {toast && (
        <div
          style={{
            position: "fixed",
            top: 20,
            right: 20,
            background: "var(--success)",
            color: "#fff",
            padding: 10,
            borderRadius: 8,
            zIndex: 1000,
            boxShadow: "0 4px 12px rgba(0,0,0,0.15)"
          }}
        >
          {toast}
        </div>
      )}

      {/* Admin Badge */}
      <div style={{
        background: "rgba(139, 92, 246, 0.1)",
        borderRadius: 12,
        padding: 12,
        marginBottom: 16,
        border: "1px solid rgba(139, 92, 246, 0.3)"
      }}>
        <div style={{ fontSize: 14, fontWeight: 600, color: "var(--text-main)" }}>
          🔐 Logged in as: SOC Administrator | System Management Console
        </div>
      </div>

      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 30 }}>
        <h1 style={{
          fontSize: "32px",
          fontWeight: "bold",
          color: "var(--text-main)",
          margin: 0,
          fontFamily: "var(--font-head)"
        }}>
          SOC Administration
        </h1>

      </div>

      {/* Navigation Tabs */}
      <div className="glass-panel" style={{ padding: 8, marginBottom: 20 }}>
        <div style={{ display: "flex", gap: 8 }}>
          {['users', 'roles', 'audit', 'config', 'analytics'].map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              style={{
                background: activeTab === tab ? "var(--primary)" : "transparent",
                color: activeTab === tab ? "#fff" : "var(--text-main)",
                border: "none",
                padding: "12px 20px",
                borderRadius: 12,
                cursor: "pointer",
                fontSize: "14px",
                fontWeight: "600",
                transition: "all 0.2s ease"
              }}
            >
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* User Management Tab */}
      {activeTab === 'users' && (
        <div className="glass-panel" style={{ padding: 20 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
            <h2 style={{ color: "var(--text-main)", margin: 0 }}>👥 User Management</h2>
            <button
              onClick={() => setShowCreateUser(true)}
              style={{
                background: "var(--success)",
                color: "#fff",
                border: "none",
                padding: "12px 20px",
                borderRadius: 12,
                cursor: "pointer",
                fontSize: "14px",
                fontWeight: "600"
              }}
            >
              + Create New User
            </button>
          </div>

          {/* Users Table */}
          <div style={{
            background: "rgba(0, 0, 0, 0.2)",
            borderRadius: 12,
            overflow: "hidden",
            border: "1px solid var(--glass-border)"
          }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead style={{ background: "rgba(0, 0, 0, 0.3)" }}>
                <tr>
                  <th style={{ padding: '16px', textAlign: 'left', color: "var(--text-main)", fontWeight: 600 }}>Name</th>
                  <th style={{ padding: '16px', textAlign: 'left', color: "var(--text-main)", fontWeight: 600 }}>Email</th>
                  <th style={{ padding: '16px', textAlign: 'left', color: "var(--text-main)", fontWeight: 600 }}>Role</th>
                  <th style={{ padding: '16px', textAlign: 'left', color: "var(--text-main)", fontWeight: 600 }}>Team</th>
                  <th style={{ padding: '16px', textAlign: 'left', color: "var(--text-main)", fontWeight: 600 }}>Level</th>
                  <th style={{ padding: '16px', textAlign: 'left', color: "var(--text-main)", fontWeight: 600 }}>Status</th>
                  <th style={{ padding: '16px', textAlign: 'left', color: "var(--text-main)", fontWeight: 600 }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map(user => (
                  <tr key={user.id} style={{ borderBottom: '1px solid var(--glass-border)' }}>
                    <td style={{ padding: '16px', color: "var(--text-main)" }}>{user.name || "Unnamed User"}</td>
                    <td style={{ padding: '16px', color: "var(--text-muted)" }}>{user.email || "N/A"}</td>
                    <td style={{ padding: '16px' }}>
                      <span style={{
                        background: normalizeRole(user.role) === 'admin' ? 'var(--danger)' :
                          normalizeRole(user.role) === 'soc_manager' ? 'var(--warning)' : 'var(--primary)',
                        color: '#fff',
                        padding: '4px 8px',
                        borderRadius: 6,
                        fontSize: '12px',
                        fontWeight: 600
                      }}>
                        {user.role}
                      </span>
                    </td>
                    <td style={{ padding: '16px', color: "var(--text-muted)" }}>{getTeamDisplayName(user.team)}</td>
                    <td style={{ padding: '16px', color: "var(--text-muted)" }}>{user.analystLevel}</td>
                    <td style={{ padding: '16px' }}>
                      <span style={{
                        background: getUserStatus(user) === 'active' ? 'var(--success)' : 'var(--danger)',
                        color: '#fff',
                        padding: '4px 8px',
                        borderRadius: 6,
                        fontSize: '12px',
                        fontWeight: 600
                      }}>
                        {getUserStatus(user)}
                      </span>
                    </td>
                    <td style={{ padding: '16px' }}>
                      <button
                        onClick={() => setEditingUser(user)}
                        style={{
                          background: "var(--primary)",
                          color: '#fff',
                          border: 'none',
                          padding: '6px 12px',
                          borderRadius: 6,
                          cursor: 'pointer',
                          marginRight: '8px',
                          fontSize: '12px',
                          fontWeight: 600
                        }}
                      >
                        Edit
                      </button>
                      <button
                        onClick={() => deleteUser(user.id)}
                        style={{
                          background: "var(--danger)",
                          color: '#fff',
                          border: 'none',
                          padding: '6px 12px',
                          borderRadius: 6,
                          cursor: 'pointer',
                          fontSize: '12px',
                          fontWeight: 600
                        }}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Role Configuration Tab */}
      {activeTab === 'roles' && (
        <div className="glass-panel" style={{ padding: 20 }}>
          <h2 style={{ color: "var(--text-main)", margin: "0 0 20px 0" }}>⚙️ Role Configuration</h2>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(350px, 1fr))", gap: 16 }}>
            {roles.map(role => (
              <div key={role.id} style={{
                background: "rgba(0, 0, 0, 0.2)",
                borderRadius: 12,
                padding: 20,
                border: "1px solid var(--glass-border)"
              }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 }}>
                  <div>
                    <h3 style={{ margin: 0, color: "var(--text-main)", fontSize: "18px" }}>
                      {role.name || role.id.charAt(0).toUpperCase() + role.id.slice(1)}
                    </h3>
                    <p style={{ margin: "4px 0", color: "var(--text-muted)", fontSize: "12px" }}>
                      ID: {role.id}
                    </p>
                  </div>
                  <button
                    onClick={() => openRoleConfig(role.id)}
                    style={{
                      background: "var(--primary)",
                      color: '#fff',
                      border: 'none',
                      padding: '8px 12px',
                      borderRadius: 6,
                      cursor: 'pointer',
                      fontSize: '12px',
                      fontWeight: 600
                    }}
                  >
                    Configure
                  </button>
                </div>

                {/* Permission Groups */}
                <div style={{ marginBottom: 12 }}>
                  <h4 style={{ margin: "0 0 8px 0", color: "var(--text-muted)", fontSize: "14px" }}>📋 Permission Groups</h4>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                    {role.permission_groups ? Object.entries(role.permission_groups).map(([group, enabled]) => (
                      <span key={group} style={{
                        background: enabled ? "var(--success)" : "rgba(255,255,255,0.1)",
                        color: enabled ? "#fff" : "var(--text-muted)",
                        padding: "4px 8px",
                        borderRadius: 12,
                        fontSize: "11px",
                        fontWeight: 600
                      }}>
                        {group.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                      </span>
                    )) : (
                      <span style={{ color: "var(--text-muted)", fontSize: "12px" }}>No groups configured</span>
                    )}
                  </div>
                </div>

                {/* Scope */}
                <div style={{ marginBottom: 12 }}>
                  <h4 style={{ margin: "0 0 8px 0", color: "var(--text-muted)", fontSize: "14px" }}>🎯 Incident Scope</h4>
                  <span style={{
                    background: "var(--primary)",
                    color: '#fff',
                    padding: "4px 8px",
                    borderRadius: 12,
                    fontSize: "11px",
                    fontWeight: 600
                  }}>
                    {(role.scope || 'unassigned').replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                  </span>
                </div>

                {/* Key Permissions */}
                <div>
                  <h4 style={{ margin: "0 0 8px 0", color: "var(--text-muted)", fontSize: "14px" }}>🔑 Key Permissions</h4>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                    {role.permissions ? [
                      'view_incidents', 'manage_users', 'manage_roles', 'run_hunting_queries', 'view_audit_logs'
                    ].filter(perm => role.permissions[perm]).map(perm => (
                      <span key={perm} style={{
                        background: "rgba(255,255,255,0.1)",
                        color: "var(--text-muted)",
                        padding: "2px 6px",
                        borderRadius: 6,
                        fontSize: "10px"
                      }}>
                        {perm.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                      </span>
                    )) : (
                      <span style={{ color: "var(--text-muted)", fontSize: "12px" }}>No permissions configured</span>
                    )}
                  </div>
                </div>

                {/* Last Updated */}
                {role.updatedAt && (
                  <div style={{ marginTop: 12, paddingTop: 12, borderTop: "1px solid var(--glass-border)" }}>
                    <p style={{ margin: 0, color: "var(--text-muted)", fontSize: "11px" }}>
                      Last updated: {new Date(role.updatedAt.toDate()).toLocaleString()}
                    </p>
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* Add New Role Button */}
          <div style={{ marginTop: 20, textAlign: "center" }}>
            <button
              onClick={() => {
                setEditingRole('new_role');
                setRolePermissions({
                  permission_groups: {
                    incident_management: false,
                    threat_hunting: false,
                    containment: false,
                    governance: false,
                    system_admin: false
                  },
                  permissions: {
                    view_incidents: false,
                    start_triage: false,
                    confirm_threat: false,
                    mark_false_positive: false,
                    escalate_to_l2: false,
                    escalate_to_ir: false,
                    request_containment: false,
                    execute_containment: false,
                    resolve_incident: false,
                    lock_incident: false,
                    approve_containment: false,
                    run_hunting_queries: false,
                    view_audit_logs: false,
                    manage_users: false,
                    manage_roles: false
                  },
                  scope: 'unassigned'
                });
                setShowRoleConfig(true);
              }}
              style={{
                background: "var(--glass-bg)",
                color: "var(--text-main)",
                border: "1px solid var(--glass-border)",
                padding: "12px 24px",
                borderRadius: 12,
                cursor: 'pointer',
                fontSize: '14px',
                fontWeight: '600'
              }}
            >
              + Create New Role
            </button>
          </div>
        </div>
      )}

      {/* Audit Logs Tab */}
      {activeTab === 'audit' && (
        <div className="glass-panel" style={{ padding: 20 }}>
          <h2 style={{ color: "var(--text-main)", margin: "0 0 20px 0" }}>📋 Audit Logs (Last 7 Days)</h2>
          <div style={{
            background: "rgba(0, 0, 0, 0.2)",
            borderRadius: 12,
            overflow: "hidden",
            border: "1px solid var(--glass-border)"
          }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead style={{ background: "rgba(0, 0, 0, 0.3)" }}>
                <tr>
                  <th style={{ padding: '16px', textAlign: 'left', color: "var(--text-main)", fontWeight: 600 }}>Action</th>
                  <th style={{ padding: '16px', textAlign: 'left', color: "var(--text-main)", fontWeight: 600 }}>Performed By</th>
                  <th style={{ padding: '16px', textAlign: 'left', color: "var(--text-main)", fontWeight: 600 }}>Target User</th>
                  <th style={{ padding: '16px', textAlign: 'left', color: "var(--text-main)", fontWeight: 600 }}>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {auditLogs.map(log => (
                  <tr key={log.id} style={{ borderBottom: '1px solid var(--glass-border)' }}>
                    <td style={{ padding: '16px', color: "var(--text-main)" }}>
                      <span style={{
                        background: log.action.includes('deleted') ? 'var(--danger)' :
                          log.action.includes('created') ? 'var(--success)' : 'var(--primary)',
                        color: '#fff',
                        padding: '4px 8px',
                        borderRadius: 6,
                        fontSize: '12px',
                        fontWeight: 600
                      }}>
                        {log.action}
                      </span>
                    </td>
                    <td style={{ padding: '16px', color: "var(--text-muted)" }}>{log.performedByEmail}</td>
                    <td style={{ padding: '16px', color: "var(--text-muted)" }}>{log.targetUser || 'N/A'}</td>
                    <td style={{ padding: '16px', color: "var(--text-muted)" }}>
                      {log.timestamp?.toDate()?.toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* SOC Configuration Tab */}
      {activeTab === 'config' && (
        <div className="glass-panel" style={{ padding: 20 }}>
          <h2 style={{ color: "var(--text-main)", margin: "0 0 20px 0" }}>🔧 SOC Configuration</h2>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: 20 }}>
            {/* SLA Times */}
            <div style={{
              background: "rgba(0, 0, 0, 0.2)",
              borderRadius: 12,
              padding: 20,
              border: "1px solid var(--glass-border)"
            }}>
              <h3 style={{ color: "var(--text-main)", margin: "0 0 16px 0" }}>⏱️ SLA Times (hours)</h3>
              <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                <div>
                  <label style={{ display: "block", marginBottom: 8, color: "var(--text-muted)", fontSize: "14px" }}>Open Incidents:</label>
                  <input
                    type="number"
                    value={socConfig.slaTimes.open}
                    onChange={(e) => setSocConfig(prev => ({
                      ...prev,
                      slaTimes: { ...prev.slaTimes, open: parseInt(e.target.value) }
                    }))}
                    style={{ width: '100%', padding: "12px", borderRadius: 8 }}
                  />
                </div>
                <div>
                  <label style={{ display: "block", marginBottom: 8, color: "var(--text-muted)", fontSize: "14px" }}>Assigned Incidents:</label>
                  <input
                    type="number"
                    value={socConfig.slaTimes.assigned}
                    onChange={(e) => setSocConfig(prev => ({
                      ...prev,
                      slaTimes: { ...prev.slaTimes, assigned: parseInt(e.target.value) }
                    }))}
                    style={{ width: '100%', padding: "12px", borderRadius: 8 }}
                  />
                </div>
                <div>
                  <label style={{ display: "block", marginBottom: 8, color: "var(--text-muted)", fontSize: "14px" }}>In Progress Incidents:</label>
                  <input
                    type="number"
                    value={socConfig.slaTimes.in_progress}
                    onChange={(e) => setSocConfig(prev => ({
                      ...prev,
                      slaTimes: { ...prev.slaTimes, in_progress: parseInt(e.target.value) }
                    }))}
                    style={{ width: '100%', padding: "12px", borderRadius: 8 }}
                  />
                </div>
              </div>
            </div>

            {/* Auto Escalation */}
            <div style={{
              background: "rgba(0, 0, 0, 0.2)",
              borderRadius: 12,
              padding: 20,
              border: "1px solid var(--glass-border)"
            }}>
              <h3 style={{ color: "var(--text-main)", margin: "0 0 16px 0" }}>🚀 Auto Escalation Rules</h3>
              <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                <div>
                  <label style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--text-main)", fontSize: "14px" }}>
                    <input
                      type="checkbox"
                      checked={socConfig.autoEscalation.enabled}
                      onChange={(e) => setSocConfig(prev => ({
                        ...prev,
                        autoEscalation: { ...prev.autoEscalation, enabled: e.target.checked }
                      }))}
                    />
                    Enable Auto Escalation
                  </label>
                </div>
                <div>
                  <label style={{ display: "block", marginBottom: 8, color: "var(--text-muted)", fontSize: "14px" }}>Threshold (hours):</label>
                  <input
                    type="number"
                    value={socConfig.autoEscalation.thresholdHours}
                    onChange={(e) => setSocConfig(prev => ({
                      ...prev,
                      autoEscalation: { ...prev.autoEscalation, thresholdHours: parseInt(e.target.value) }
                    }))}
                    style={{ width: '100%', padding: "12px", borderRadius: 8 }}
                  />
                </div>
                <div>
                  <label style={{ display: "block", marginBottom: 8, color: "var(--text-muted)", fontSize: "14px" }}>Escalate To:</label>
                  <select
                    value={socConfig.autoEscalation.escalateTo}
                    onChange={(e) => setSocConfig(prev => ({
                      ...prev,
                      autoEscalation: { ...prev.autoEscalation, escalateTo: e.target.value }
                    }))}
                    style={{ width: '100%', padding: "12px", borderRadius: 8 }}
                  >
                    <option value="soc_l2">soc_l2</option>
                    <option value="incident_response">ir</option>
                  </select>
                </div>
              </div>
            </div>
          </div>

          <button
            onClick={saveSocConfig}
            style={{
              background: "var(--success)",
              color: '#fff',
              border: 'none',
              padding: "12px 24px",
              borderRadius: 12,
              cursor: 'pointer',
              fontSize: '16px',
              fontWeight: '600',
              marginTop: 20
            }}
          >
            💾 Save Configuration
          </button>
        </div>
      )}

      {/* Workforce Analytics Tab */}
      {activeTab === 'analytics' && (
        <div>
          <h2 style={{ color: "var(--text-main)", margin: "0 0 20px 0" }}>📊 Workforce Analytics</h2>

          {/* Analytics Cards */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))", gap: 20, marginBottom: 30 }}>
            <div className="glass-panel" style={{ padding: 20, textAlign: "center" }}>
              <div style={{ fontSize: "36px", fontWeight: 900, color: "var(--primary)" }}>{workforceAnalytics.totalAnalysts}</div>
              <div style={{ color: "var(--text-muted)", marginTop: 8 }}>Total Analysts</div>
            </div>
            <div className="glass-panel" style={{ padding: 20, textAlign: "center" }}>
              <div style={{ fontSize: "36px", fontWeight: 900, color: "var(--success)" }}>{workforceAnalytics.activeAnalysts}</div>
              <div style={{ color: "var(--text-muted)", marginTop: 8 }}>Active Analysts</div>
            </div>
          </div>

          {/* Incidents Per Analyst */}
          <div className="glass-panel" style={{ padding: 20 }}>
            <h3 style={{ color: "var(--text-main)", margin: "0 0 20px 0" }}>📈 Incidents Per Analyst</h3>
            <div style={{
              background: "rgba(0, 0, 0, 0.2)",
              borderRadius: 12,
              overflow: "hidden",
              border: "1px solid var(--glass-border)"
            }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead style={{ background: "rgba(0, 0, 0, 0.3)" }}>
                  <tr>
                    <th style={{ padding: '16px', textAlign: 'left', color: "var(--text-main)", fontWeight: 600 }}>Analyst</th>
                    <th style={{ padding: '16px', textAlign: 'left', color: "var(--text-main)", fontWeight: 600 }}>Email</th>
                    <th style={{ padding: '16px', textAlign: 'left', color: "var(--text-main)", fontWeight: 600 }}>Incidents Handled</th>
                  </tr>
                </thead>
                <tbody>
                  {workforceAnalytics.incidentsPerAnalyst?.map(analyst => (
                    <tr key={analyst.email} style={{ borderBottom: '1px solid var(--glass-border)' }}>
                      <td style={{ padding: '16px', color: "var(--text-main)" }}>{analyst.name}</td>
                      <td style={{ padding: '16px', color: "var(--text-muted)" }}>{analyst.email}</td>
                      <td style={{ padding: '16px' }}>
                        <span style={{
                          background: "var(--primary)",
                          color: '#fff',
                          padding: '4px 8px',
                          borderRadius: 6,
                          fontSize: '12px',
                          fontWeight: 600
                        }}>
                          {analyst.incidentsHandled}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Create User Modal */}
      {showCreateUser && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0,0,0,0.8)',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          zIndex: 1000
        }}>
          <div className="glass-panel" style={{
            width: '600px',
            maxHeight: '85vh',
            overflowY: 'auto',
            display: 'flex',
            flexDirection: 'column'
          }}>
            {/* Header */}
            <div style={{
              padding: '20px 24px',
              borderBottom: '1px solid var(--glass-border)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center'
            }}>
              <h2 style={{ margin: 0, color: "var(--text-main)", fontSize: '20px' }}>
                👤 Create New User
              </h2>
              <button
                onClick={() => setShowCreateUser(false)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: 'var(--text-muted)',
                  fontSize: '20px',
                  cursor: 'pointer',
                  padding: '4px'
                }}
              >
                ✕
              </button>
            </div>

            {/* Content */}
            <div style={{ padding: '24px' }}>
              <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
                <div>
                  <label style={{ display: "block", marginBottom: 8, color: "var(--text-muted)", fontSize: "12px", fontWeight: 600 }}>NAME</label>
                  <input
                    type="text"
                    value={newUser.name}
                    onChange={(e) => setNewUser(prev => ({ ...prev, name: e.target.value }))}
                    placeholder="Enter user's full name"
                    style={{
                      width: '100%',
                      padding: "12px 16px",
                      borderRadius: 8,
                      border: '1px solid var(--glass-border)',
                      background: 'rgba(255,255,255,0.05)',
                      color: 'var(--text-main)',
                      fontSize: '14px',
                      transition: 'all 0.2s ease'
                    }}
                  />
                </div>
                <div>
                  <label style={{ display: "block", marginBottom: 8, color: "var(--text-muted)", fontSize: "12px", fontWeight: 600 }}>EMAIL</label>
                  <input
                    type="email"
                    value={newUser.email}
                    onChange={(e) => setNewUser(prev => ({ ...prev, email: e.target.value }))}
                    placeholder="user@example.com"
                    style={{
                      width: '100%',
                      padding: "12px 16px",
                      borderRadius: 8,
                      border: '1px solid var(--glass-border)',
                      background: 'rgba(255,255,255,0.05)',
                      color: 'var(--text-main)',
                      fontSize: '14px',
                      transition: 'all 0.2s ease'
                    }}
                  />
                </div>
                <div>
                  <label style={{ display: "block", marginBottom: 8, color: "var(--text-muted)", fontSize: "12px", fontWeight: 600 }}>PASSWORD</label>
                  <input
                    type="password"
                    value={newUser.password}
                    onChange={(e) => setNewUser(prev => ({ ...prev, password: e.target.value }))}
                    placeholder="Enter secure password"
                    style={{
                      width: '100%',
                      padding: "12px 16px",
                      borderRadius: 8,
                      border: '1px solid var(--glass-border)',
                      background: 'rgba(255,255,255,0.05)',
                      color: 'var(--text-main)',
                      fontSize: '14px',
                      transition: 'all 0.2s ease'
                    }}
                  />
                </div>
                <div>
                  <label style={{ display: "block", marginBottom: 8, color: "var(--text-muted)", fontSize: "12px", fontWeight: 600 }}>ROLE</label>
                  <select
                    value={newUser.role}
                    onChange={(e) => setNewUser(prev => ({ ...prev, role: e.target.value }))}
                    style={{
                      width: '100%',
                      padding: "12px 16px",
                      borderRadius: 8,
                      border: '1px solid var(--glass-border)',
                      background: 'rgba(255,255,255,0.05)',
                      color: 'var(--text-main)',
                      fontSize: '14px',
                      transition: 'all 0.2s ease'
                    }}
                  >
                    {roles.map(role => (
                      <option key={role.id} value={role.id}>
                        {role.name || role.id}
                      </option>
                    ))}
                  </select>
                </div>
                {/* Team field - only for analyst roles */}
                {ROLE_TYPES[normalizeRole(newUser.role)] === "analyst" && (
                  <div>
                    <label style={{ display: "block", marginBottom: 8, color: "var(--text-muted)", fontSize: "12px", fontWeight: 600 }}>TEAM</label>
                    <select
                      value={newUser.team}
                      onChange={(e) => setNewUser(prev => ({ ...prev, team: e.target.value }))}
                      style={{
                        width: '100%',
                        padding: "12px 16px",
                        borderRadius: 8,
                        border: '1px solid var(--glass-border)',
                        background: 'rgba(255,255,255,0.05)',
                        color: 'var(--text-main)',
                        fontSize: '14px',
                        transition: 'all 0.2s ease'
                      }}
                    >
                      <option value="soc_l1">soc_l1</option>
                      <option value="soc_l2">soc_l2</option>
                      <option value="incident_response">incident_response</option>
                      <option value="threat_hunter">threat_hunter</option>
                    </select>
                  </div>
                )}
                {/* Analyst Level field - only for analyst roles */}
                {ROLE_TYPES[normalizeRole(newUser.role)] === "analyst" && (
                  <div>
                    <label style={{ display: "block", marginBottom: 8, color: "var(--text-muted)", fontSize: "12px", fontWeight: 600 }}>ANALYST LEVEL</label>
                    <select
                      value={newUser.analystLevel}
                      onChange={(e) => setNewUser(prev => ({ ...prev, analystLevel: e.target.value }))}
                      style={{
                        width: '100%',
                        padding: "12px 16px",
                        borderRadius: 8,
                        border: '1px solid var(--glass-border)',
                        background: 'rgba(255,255,255,0.05)',
                        color: 'var(--text-main)',
                        fontSize: '14px',
                        transition: 'all 0.2s ease'
                      }}
                    >
                      <option value="L1">Level 1</option>
                      <option value="L2">Level 2</option>
                    </select>
                  </div>
                )}
                <div>
                  <label style={{ display: "block", marginBottom: 8, color: "var(--text-muted)", fontSize: "12px", fontWeight: 600 }}>STATUS</label>
                  <select
                    value={newUser.status}
                    onChange={(e) => setNewUser(prev => ({ ...prev, status: e.target.value }))}
                    style={{
                      width: '100%',
                      padding: "12px 16px",
                      borderRadius: 8,
                      border: '1px solid var(--glass-border)',
                      background: 'rgba(255,255,255,0.05)',
                      color: 'var(--text-main)',
                      fontSize: '14px',
                      transition: 'all 0.2s ease'
                    }}
                  >
                    <option value="active">Active</option>
                    <option value="inactive">Inactive</option>
                    <option value="suspended">Suspended</option>
                  </select>
                </div>
              </div>
            </div>

            {/* Footer */}
            <div style={{
              padding: '16px 24px',
              borderTop: '1px solid var(--glass-border)',
              display: 'flex',
              justifyContent: 'flex-end',
              gap: '12px'
            }}>
              <button
                onClick={() => setShowCreateUser(false)}
                style={{
                  background: 'var(--glass-bg)',
                  color: 'var(--text-main)',
                  border: '1px solid var(--glass-border)',
                  padding: '10px 20px',
                  borderRadius: 8,
                  cursor: 'pointer',
                  fontSize: '14px',
                  fontWeight: 600,
                  transition: 'all 0.2s ease'
                }}
              >
                Cancel
              </button>
              <button
                onClick={createUser}
                style={{
                  background: 'var(--primary)',
                  color: '#fff',
                  border: 'none',
                  padding: '10px 20px',
                  borderRadius: 8,
                  cursor: 'pointer',
                  fontSize: '14px',
                  fontWeight: 600,
                  transition: 'all 0.2s ease'
                }}
              >
                Create User
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit User Modal */}
      {editingUser && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0,0,0,0.8)',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          zIndex: 1000
        }}>
          <div className="glass-panel" style={{
            width: '600px',
            maxHeight: '85vh',
            overflowY: 'auto',
            display: 'flex',
            flexDirection: 'column'
          }}>
            {/* Header */}
            <div style={{
              padding: '20px 24px',
              borderBottom: '1px solid var(--glass-border)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center'
            }}>
              <h2 style={{ margin: 0, color: "var(--text-main)", fontSize: '20px' }}>
                ✏️ Edit User
              </h2>
              <button
                onClick={() => setEditingUser(null)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: 'var(--text-muted)',
                  fontSize: '20px',
                  cursor: 'pointer',
                  padding: '4px'
                }}
              >
                ✕
              </button>
            </div>

            {/* Content */}
            <div style={{ padding: '24px' }}>
              <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
                <div>
                  <label style={{ display: "block", marginBottom: 8, color: "var(--text-muted)", fontSize: "12px", fontWeight: 600 }}>NAME</label>
                  <input
                    type="text"
                    value={editingUser.name}
                    onChange={(e) => setEditingUser(prev => ({ ...prev, name: e.target.value }))}
                    placeholder="Enter user's full name"
                    style={{
                      width: '100%',
                      padding: "12px 16px",
                      borderRadius: 8,
                      border: '1px solid var(--glass-border)',
                      background: 'rgba(255,255,255,0.05)',
                      color: 'var(--text-main)',
                      fontSize: '14px',
                      transition: 'all 0.2s ease'
                    }}
                  />
                </div>
                <div>
                  <label style={{ display: "block", marginBottom: 8, color: "var(--text-muted)", fontSize: "12px", fontWeight: 600 }}>ROLE</label>
                  <select
                    value={editingUser.role || 'student'}
                    onChange={(e) => setEditingUser(prev => ({ ...prev, role: e.target.value }))}
                    style={{
                      width: '100%',
                      padding: "12px 16px",
                      borderRadius: 8,
                      border: '1px solid var(--glass-border)',
                      background: 'rgba(255,255,255,0.05)',
                      color: 'var(--text-main)',
                      fontSize: '14px',
                      transition: 'all 0.2s ease'
                    }}
                  >
                    {roles.map(role => (
                      <option key={role.id} value={role.id}>
                        {role.name || role.id}
                      </option>
                    ))}
                  </select>
                </div>
                {/* Team field - only for analyst roles */}
                {ROLE_TYPES[normalizeRole(editingUser.role)] === "analyst" && (
                  <div>
                    <label style={{ display: "block", marginBottom: 8, color: "var(--text-muted)", fontSize: "12px", fontWeight: 600 }}>TEAM</label>
                    <select
                      value={editingUser.team || 'soc_l1'}
                      onChange={(e) => setEditingUser(prev => ({ ...prev, team: e.target.value }))}
                      style={{
                        width: '100%',
                        padding: "12px 16px",
                        borderRadius: 8,
                        border: '1px solid var(--glass-border)',
                        background: 'rgba(255,255,255,0.05)',
                        color: 'var(--text-main)',
                        fontSize: '14px',
                        transition: 'all 0.2s ease'
                      }}
                    >
                      <option value="soc_l1">soc_l1</option>
                      <option value="soc_l2">soc_l2</option>
                      <option value="incident_response">ir</option>
                      <option value="threat_hunter">threat_hunter</option>
                    </select>
                  </div>
                )}
                {/* Analyst Level field - only for analyst roles */}
                {ROLE_TYPES[normalizeRole(editingUser.role)] === "analyst" && (
                  <div>
                    <label style={{ display: "block", marginBottom: 8, color: "var(--text-muted)", fontSize: "12px", fontWeight: 600 }}>ANALYST LEVEL</label>
                    <select
                      value={editingUser.analystLevel || 'L1'}
                      onChange={(e) => setEditingUser(prev => ({ ...prev, analystLevel: e.target.value }))}
                      style={{
                        width: '100%',
                        padding: "12px 16px",
                        borderRadius: 8,
                        border: '1px solid var(--glass-border)',
                        background: 'rgba(255,255,255,0.05)',
                        color: 'var(--text-main)',
                        fontSize: '14px',
                        transition: 'all 0.2s ease'
                      }}
                    >
                      <option value="L1">L1</option>
                      <option value="L2">L2</option>
                    </select>
                  </div>
                )}
                <div>
                  <label style={{ display: "block", marginBottom: 8, color: "var(--text-muted)", fontSize: "12px", fontWeight: 600 }}>STATUS</label>
                  <select
                    value={editingUser.status || 'active'}
                    onChange={(e) => setEditingUser(prev => ({ ...prev, status: e.target.value }))}
                    style={{
                      width: '100%',
                      padding: "12px 16px",
                      borderRadius: 8,
                      border: '1px solid var(--glass-border)',
                      background: 'rgba(255,255,255,0.05)',
                      color: 'var(--text-main)',
                      fontSize: '14px',
                      transition: 'all 0.2s ease'
                    }}
                  >
                    <option value="active">Active</option>
                    <option value="inactive">Inactive</option>
                    <option value="suspended">Suspended</option>
                  </select>
                </div>
              </div>
            </div>

            {/* Footer */}
            <div style={{
              padding: '16px 24px',
              borderTop: '1px solid var(--glass-border)',
              display: 'flex',
              justifyContent: 'flex-end',
              gap: '12px'
            }}>
              <button
                onClick={() => setEditingUser(null)}
                style={{
                  background: 'var(--glass-bg)',
                  color: 'var(--text-main)',
                  border: '1px solid var(--glass-border)',
                  padding: '10px 20px',
                  borderRadius: 8,
                  cursor: 'pointer',
                  fontSize: '14px',
                  fontWeight: 600,
                  transition: 'all 0.2s ease'
                }}
              >
                Cancel
              </button>
              <button
                onClick={() => updateUser(editingUser.id, {
                  name: editingUser.name,
                  role: editingUser.role,
                  team: editingUser.team || 'soc_l1',
                  analystLevel: editingUser.analystLevel || 'L1',
                  status: editingUser.status || 'active'
                })}
                style={{
                  background: 'var(--primary)',
                  color: '#fff',
                  border: 'none',
                  padding: '10px 20px',
                  borderRadius: 8,
                  cursor: 'pointer',
                  fontSize: '14px',
                  fontWeight: 600,
                  transition: 'all 0.2s ease'
                }}
              >
                Update User
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Role Configuration Modal */}
      {showRoleConfig && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0,0,0,0.8)',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          zIndex: 1000
        }}>
          <div className="glass-panel" style={{
            width: '1200px',
            height: '85vh',
            maxHeight: '85vh',
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden'
          }}>
            {/* Header */}
            <div style={{
              padding: '20px 24px',
              borderBottom: '1px solid var(--glass-border)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center'
            }}>
              <h2 style={{ margin: 0, color: "var(--text-main)", fontSize: '20px' }}>
                ⚙️ Role Configuration: {editingRole}
              </h2>
              <button
                onClick={() => setShowRoleConfig(false)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: 'var(--text-muted)',
                  fontSize: '20px',
                  cursor: 'pointer',
                  padding: '4px'
                }}
              >
                ✕
              </button>
            </div>

            {/* Role Header Section */}
            <div style={{
              padding: '20px 24px',
              borderBottom: '1px solid var(--glass-border)',
              background: 'rgba(0,0,0,0.1)'
            }}>
              <div style={{
                display: 'grid',
                gridTemplateColumns: '1fr 2fr 150px 150px 100px',
                gap: '16px',
                alignItems: 'center'
              }}>
                <div>
                  <label style={{ display: 'block', marginBottom: '6px', color: 'var(--text-muted)', fontSize: '12px', fontWeight: 600 }}>
                    ROLE NAME
                  </label>
                  <input
                    type="text"
                    value={editingRole === 'new_role' ? 'New Role' : editingRole}
                    onChange={(e) => setEditingRole(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '10px 12px',
                      borderRadius: '8px',
                      border: '1px solid var(--glass-border)',
                      background: 'rgba(255,255,255,0.05)',
                      color: 'var(--text-main)',
                      fontSize: '14px'
                    }}
                  />
                </div>
                <div>
                  <label style={{ display: 'block', marginBottom: '6px', color: 'var(--text-muted)', fontSize: '12px', fontWeight: 600 }}>
                    DESCRIPTION
                  </label>
                  <input
                    type="text"
                    placeholder="Enter role description..."
                    style={{
                      width: '100%',
                      padding: '10px 12px',
                      borderRadius: '8px',
                      border: '1px solid var(--glass-border)',
                      background: 'rgba(255,255,255,0.05)',
                      color: 'var(--text-main)',
                      fontSize: '14px'
                    }}
                  />
                </div>
                <div>
                  <label style={{ display: 'block', marginBottom: '6px', color: 'var(--text-muted)', fontSize: '12px', fontWeight: 600 }}>
                    TEMPLATE
                  </label>
                  <select
                    onChange={(e) => {
                      const template = e.target.value;
                      if (template && ROLE_TEMPLATES[template]) {
                        const roleTemplate = ROLE_TEMPLATES[template];
                        setRolePermissions(prev => ({
                          permission_groups: {
                            incident_management: roleTemplate.enabledModules.includes('incident_management'),
                            threat_hunting: roleTemplate.enabledModules.includes('threat_hunting'),
                            containment: roleTemplate.enabledModules.includes('containment'),
                            governance: roleTemplate.enabledModules.includes('governance'),
                            system_admin: roleTemplate.enabledModules.includes('system_admin')
                          },
                          permissions: Object.keys(prev.permissions).reduce((acc, perm) => ({
                            ...acc,
                            [perm]: roleTemplate.permissions[perm] || false
                          }), {}),
                          scope: template === 'admin' || template === 'soc_manager' ? 'all' :
                            template === 'soc_l2' ? 'escalated' :
                              template === 'ir' ? 'ir_only' :
                                template === 'threat_hunter' ? 'all' : 'unassigned'
                        }));
                        console.log(`📋 Loaded template: ${roleTemplate.name}`);
                      }
                    }}
                    style={{
                      width: '100%',
                      padding: '10px 12px',
                      borderRadius: '8px',
                      border: '1px solid var(--glass-border)',
                      background: 'rgba(255,255,255,0.05)',
                      color: 'var(--text-main)',
                      fontSize: '14px'
                    }}
                  >
                    <option value="">Custom</option>
                    <option value="soc_l1">SOC Analyst L1</option>
                    <option value="soc_l2">SOC Analyst L2</option>
                    <option value="threat_hunter">Threat Hunter</option>
                    <option value="ir">Incident Response</option>
                    <option value="soc_manager">SOC Manager</option>
                    <option value="admin">Administrator</option>
                  </select>
                </div>
                <div>
                  <label style={{ display: 'block', marginBottom: '6px', color: 'var(--text-muted)', fontSize: '12px', fontWeight: 600 }}>
                    SCOPE
                  </label>
                  <select
                    value={rolePermissions.scope || 'unassigned'}
                    onChange={(e) => setRolePermissions(prev => ({
                      ...prev,
                      scope: e.target.value
                    }))}
                    style={{
                      width: '100%',
                      padding: '10px 12px',
                      borderRadius: '8px',
                      border: '1px solid var(--glass-border)',
                      background: 'rgba(255,255,255,0.05)',
                      color: 'var(--text-main)',
                      fontSize: '14px'
                    }}
                  >
                    <option value="unassigned">Unassigned</option>
                    <option value="escalated">Escalated</option>
                    <option value="ir_only">IR Only</option>
                    <option value="all">All</option>
                  </select>
                </div>
                <div>
                  <label style={{ display: 'block', marginBottom: '6px', color: 'var(--text-muted)', fontSize: '12px', fontWeight: 600 }}>
                    STATUS
                  </label>
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px'
                  }}>
                    <div style={{
                      width: '44px',
                      height: '24px',
                      background: '#4CAF50',
                      borderRadius: '12px',
                      position: 'relative',
                      cursor: 'pointer'
                    }}>
                      <div style={{
                        width: '20px',
                        height: '20px',
                        background: '#fff',
                        borderRadius: '50%',
                        position: 'absolute',
                        top: '2px',
                        right: '2px',
                        transition: 'all 0.2s ease'
                      }} />
                    </div>
                    <span style={{ color: 'var(--text-main)', fontSize: '12px' }}>Active</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Permission Group Toggles */}
            <div style={{
              padding: '16px 24px',
              borderBottom: '1px solid var(--glass-border)',
              background: 'rgba(0,0,0,0.05)'
            }}>
              <div style={{
                display: 'flex',
                gap: '20px',
                alignItems: 'center'
              }}>
                <span style={{ color: 'var(--text-muted)', fontSize: '12px', fontWeight: 600, marginRight: '10px' }}>
                  PERMISSION GROUPS:
                </span>
                {[
                  { key: 'incident_management', label: '🚨 Incident Management' },
                  { key: 'threat_hunting', label: '🔍 Threat Hunting' },
                  { key: 'containment', label: '🛡️ Containment' },
                  { key: 'governance', label: '📊 Governance' },
                  { key: 'system_admin', label: '⚙️ System Administration' }
                ].map(group => (
                  <div key={group.key} style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px'
                  }}>
                    <div
                      onClick={() => {
                        const groupKey = group.key;
                        const isEnabled = !rolePermissions.permission_groups?.[groupKey];

                        setRolePermissions(prev => {
                          const newPermissionGroups = {
                            ...prev.permission_groups,
                            [groupKey]: isEnabled
                          };

                          // Auto-enable/disable all permissions in this group
                          const newPermissions = { ...prev.permissions };
                          if (GROUP_PERMISSIONS[groupKey]) {
                            GROUP_PERMISSIONS[groupKey].forEach(perm => {
                              newPermissions[perm] = isEnabled;
                            });
                          }

                          return {
                            ...prev,
                            permission_groups: newPermissionGroups,
                            permissions: newPermissions
                          };
                        });

                        console.log(`${isEnabled ? '✅' : '❌'} ${group.label}: ${isEnabled ? 'Enabled' : 'Disabled'} ${GROUP_PERMISSIONS[groupKey]?.length || 0} permissions`);
                      }}
                      style={{
                        width: '40px',
                        height: '22px',
                        background: rolePermissions.permission_groups?.[group.key] ? '#4CAF50' : 'rgba(255,255,255,0.2)',
                        borderRadius: '11px',
                        position: 'relative',
                        cursor: 'pointer',
                        transition: 'all 0.2s ease'
                      }}
                    >
                      <div style={{
                        width: '18px',
                        height: '18px',
                        background: '#fff',
                        borderRadius: '50%',
                        position: 'absolute',
                        top: '2px',
                        left: rolePermissions.permission_groups?.[group.key] ? '20px' : '2px',
                        transition: 'all 0.2s ease'
                      }} />
                    </div>
                    <span style={{ color: 'var(--text-main)', fontSize: '13px' }}>{group.label}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Main Content Area with Module Tabs and Summary */}
            <div style={{
              display: 'flex',
              flex: 1,
              overflow: 'hidden'
            }}>
              {/* Permission Modules */}
              <div style={{
                flex: 1,
                display: 'flex',
                flexDirection: 'column',
                overflow: 'hidden'
              }}>
                {/* Module Tabs */}
                <div style={{
                  display: 'flex',
                  borderBottom: '1px solid var(--glass-border)',
                  background: 'rgba(0,0,0,0.05)'
                }}>
                  {[
                    { key: 'incident_management', label: 'Incident Management', icon: '🚨' },
                    { key: 'threat_hunting', label: 'Threat Hunting', icon: '🔍' },
                    { key: 'containment', label: 'Containment', icon: '🛡️' },
                    { key: 'governance', label: 'Governance', icon: '📊' },
                    { key: 'system_admin', label: 'System Administration', icon: '⚙️' }
                  ].map(module => (
                    <button
                      key={module.key}
                      onClick={() => setActiveModule(module.key)}
                      style={{
                        flex: 1,
                        padding: '12px 16px',
                        background: activeModule === module.key ? 'var(--primary)' : 'transparent',
                        color: activeModule === module.key ? '#fff' : 'var(--text-main)',
                        border: 'none',
                        cursor: 'pointer',
                        fontSize: '13px',
                        fontWeight: 600,
                        transition: 'all 0.2s ease',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        gap: '6px'
                      }}
                    >
                      {module.icon} {module.label}
                    </button>
                  ))}
                </div>

                {/* Module Content */}
                <div style={{
                  flex: 1,
                  overflowY: 'auto',
                  padding: '20px 24px'
                }}>
                  {activeModule === 'incident_management' && (
                    <div className="glass-panel" style={{ padding: '20px' }}>
                      <h3 style={{ margin: '0 0 20px 0', color: 'var(--text-main)', fontSize: '16px' }}>
                        🚨 Incident Management Permissions
                      </h3>
                      <div style={{
                        display: 'grid',
                        gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
                        gap: '16px'
                      }}>
                        {[
                          { key: 'view_incidents', label: 'View Incidents', description: 'Access incident list and details' },
                          { key: 'start_triage', label: 'Start Triage', description: 'Begin incident triage process' },
                          { key: 'confirm_threat', label: 'Confirm Threat', description: 'Validate and confirm threats' },
                          { key: 'mark_false_positive', label: 'Mark False Positive', description: 'Mark incidents as false positive' },
                          { key: 'escalate_to_l2', label: 'Escalate to L2', description: 'Escalate to Level 2 analysts' },
                          { key: 'escalate_to_ir', label: 'Escalate to IR', description: 'Escalate to incident response' },
                          { key: 'request_containment', label: 'Request Containment', description: 'Request incident containment' },
                          { key: 'execute_containment', label: 'Execute Containment', description: 'Execute containment actions' },
                          { key: 'resolve_incident', label: 'Resolve Incident', description: 'Mark incidents as resolved' },
                          { key: 'lock_incident', label: 'Lock Incident', description: 'Lock incidents from changes' },
                          { key: 'approve_containment', label: 'Approve Containment', description: 'Approve containment requests' }
                        ].map(permission => (
                          <div key={permission.key} style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            padding: '12px',
                            background: 'rgba(0,0,0,0.2)',
                            borderRadius: '8px',
                            border: '1px solid var(--glass-border)'
                          }}>
                            <div>
                              <div style={{ color: 'var(--text-main)', fontSize: '14px', fontWeight: 600 }}>
                                {permission.label}
                              </div>
                              <div style={{ color: 'var(--text-muted)', fontSize: '12px', marginTop: '2px' }}>
                                {permission.description}
                              </div>
                            </div>
                            <div
                              onClick={() => setRolePermissions(prev => ({
                                ...prev,
                                permissions: {
                                  ...prev.permissions,
                                  [permission.key]: !prev.permissions?.[permission.key]
                                }
                              }))}
                              style={{
                                width: '44px',
                                height: '24px',
                                background: rolePermissions.permissions?.[permission.key] ? '#4CAF50' : 'rgba(255,255,255,0.2)',
                                borderRadius: '12px',
                                position: 'relative',
                                cursor: 'pointer',
                                transition: 'all 0.2s ease'
                              }}
                            >
                              <div style={{
                                width: '20px',
                                height: '20px',
                                background: '#fff',
                                borderRadius: '50%',
                                position: 'absolute',
                                top: '2px',
                                left: rolePermissions.permissions?.[permission.key] ? '22px' : '2px',
                                transition: 'all 0.2s ease'
                              }} />
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {activeModule === 'threat_hunting' && (
                    <div className="glass-panel" style={{ padding: '20px' }}>
                      <h3 style={{ margin: '0 0 20px 0', color: 'var(--text-main)', fontSize: '16px' }}>
                        🔍 Threat Hunting Permissions
                      </h3>
                      <div style={{
                        display: 'grid',
                        gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
                        gap: '16px'
                      }}>
                        {[
                          { key: 'run_hunting_queries', label: 'Run Hunting Queries', description: 'Execute threat hunting queries' }
                        ].map(permission => (
                          <div key={permission.key} style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            padding: '12px',
                            background: 'rgba(0,0,0,0.2)',
                            borderRadius: '8px',
                            border: '1px solid var(--glass-border)'
                          }}>
                            <div>
                              <div style={{ color: 'var(--text-main)', fontSize: '14px', fontWeight: 600 }}>
                                {permission.label}
                              </div>
                              <div style={{ color: 'var(--text-muted)', fontSize: '12px', marginTop: '2px' }}>
                                {permission.description}
                              </div>
                            </div>
                            <div
                              onClick={() => setRolePermissions(prev => ({
                                ...prev,
                                permissions: {
                                  ...prev.permissions,
                                  [permission.key]: !prev.permissions?.[permission.key]
                                }
                              }))}
                              style={{
                                width: '44px',
                                height: '24px',
                                background: rolePermissions.permissions?.[permission.key] ? '#4CAF50' : 'rgba(255,255,255,0.2)',
                                borderRadius: '12px',
                                position: 'relative',
                                cursor: 'pointer',
                                transition: 'all 0.2s ease'
                              }}
                            >
                              <div style={{
                                width: '20px',
                                height: '20px',
                                background: '#fff',
                                borderRadius: '50%',
                                position: 'absolute',
                                top: '2px',
                                left: rolePermissions.permissions?.[permission.key] ? '22px' : '2px',
                                transition: 'all 0.2s ease'
                              }} />
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {activeModule === 'governance' && (
                    <div className="glass-panel" style={{ padding: '20px' }}>
                      <h3 style={{ margin: '0 0 20px 0', color: 'var(--text-main)', fontSize: '16px' }}>
                        📊 Governance Permissions
                      </h3>
                      <div style={{
                        display: 'grid',
                        gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
                        gap: '16px'
                      }}>
                        {[
                          { key: 'view_audit_logs', label: 'View Audit Logs', description: 'Access system audit logs' }
                        ].map(permission => (
                          <div key={permission.key} style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            padding: '12px',
                            background: 'rgba(0,0,0,0.2)',
                            borderRadius: '8px',
                            border: '1px solid var(--glass-border)'
                          }}>
                            <div>
                              <div style={{ color: 'var(--text-main)', fontSize: '14px', fontWeight: 600 }}>
                                {permission.label}
                              </div>
                              <div style={{ color: 'var(--text-muted)', fontSize: '12px', marginTop: '2px' }}>
                                {permission.description}
                              </div>
                            </div>
                            <div
                              onClick={() => setRolePermissions(prev => ({
                                ...prev,
                                permissions: {
                                  ...prev.permissions,
                                  [permission.key]: !prev.permissions?.[permission.key]
                                }
                              }))}
                              style={{
                                width: '44px',
                                height: '24px',
                                background: rolePermissions.permissions?.[permission.key] ? '#4CAF50' : 'rgba(255,255,255,0.2)',
                                borderRadius: '12px',
                                position: 'relative',
                                cursor: 'pointer',
                                transition: 'all 0.2s ease'
                              }}
                            >
                              <div style={{
                                width: '20px',
                                height: '20px',
                                background: '#fff',
                                borderRadius: '50%',
                                position: 'absolute',
                                top: '2px',
                                left: rolePermissions.permissions?.[permission.key] ? '22px' : '2px',
                                transition: 'all 0.2s ease'
                              }} />
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {activeModule === 'system_admin' && (
                    <div className="glass-panel" style={{ padding: '20px' }}>
                      <h3 style={{ margin: '0 0 20px 0', color: 'var(--text-main)', fontSize: '16px' }}>
                        ⚙️ System Administration Permissions
                      </h3>
                      <div style={{
                        display: 'grid',
                        gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
                        gap: '16px'
                      }}>
                        {[
                          { key: 'manage_users', label: 'Manage Users', description: 'Create, edit, and delete users' },
                          { key: 'manage_roles', label: 'Manage Roles', description: 'Configure role permissions' }
                        ].map(permission => (
                          <div key={permission.key} style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            padding: '12px',
                            background: 'rgba(0,0,0,0.2)',
                            borderRadius: '8px',
                            border: '1px solid var(--glass-border)'
                          }}>
                            <div>
                              <div style={{ color: 'var(--text-main)', fontSize: '14px', fontWeight: 600 }}>
                                {permission.label}
                              </div>
                              <div style={{ color: 'var(--text-muted)', fontSize: '12px', marginTop: '2px' }}>
                                {permission.description}
                              </div>
                            </div>
                            <div
                              onClick={() => setRolePermissions(prev => ({
                                ...prev,
                                permissions: {
                                  ...prev.permissions,
                                  [permission.key]: !prev.permissions?.[permission.key]
                                }
                              }))}
                              style={{
                                width: '44px',
                                height: '24px',
                                background: rolePermissions.permissions?.[permission.key] ? '#4CAF50' : 'rgba(255,255,255,0.2)',
                                borderRadius: '12px',
                                position: 'relative',
                                cursor: 'pointer',
                                transition: 'all 0.2s ease'
                              }}
                            >
                              <div style={{
                                width: '20px',
                                height: '20px',
                                background: '#fff',
                                borderRadius: '50%',
                                position: 'absolute',
                                top: '2px',
                                left: rolePermissions.permissions?.[permission.key] ? '22px' : '2px',
                                transition: 'all 0.2s ease'
                              }} />
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Role Summary Panel */}
              <div style={{
                width: '300px',
                borderLeft: '1px solid var(--glass-border)',
                background: 'rgba(0,0,0,0.05)',
                padding: '20px',
                overflowY: 'auto'
              }}>
                <h3 style={{ margin: '0 0 20px 0', color: 'var(--text-main)', fontSize: '16px' }}>
                  📋 Role Summary
                </h3>

                {/* Incident Scope */}
                <div style={{ marginBottom: '20px' }}>
                  <div style={{ color: 'var(--text-muted)', fontSize: '12px', fontWeight: 600, marginBottom: '8px' }}>
                    INCIDENT SCOPE
                  </div>
                  <div style={{
                    background: 'var(--primary)',
                    color: '#fff',
                    padding: '8px 12px',
                    borderRadius: '6px',
                    fontSize: '13px',
                    fontWeight: 600,
                    textAlign: 'center'
                  }}>
                    {(rolePermissions.scope || 'unassigned').replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                  </div>
                </div>

                {/* Enabled Modules */}
                <div style={{ marginBottom: '20px' }}>
                  <div style={{ color: 'var(--text-muted)', fontSize: '12px', fontWeight: 600, marginBottom: '8px' }}>
                    ENABLED MODULES
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    {Object.entries(rolePermissions.permission_groups || {})
                      .filter(([_, enabled]) => enabled)
                      .map(([module, _]) => (
                        <div key={module} style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '8px',
                          color: 'var(--text-main)',
                          fontSize: '13px'
                        }}>
                          <span style={{ color: '#4CAF50' }}>✓</span>
                          {module.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                        </div>
                      ))}
                    {Object.values(rolePermissions.permission_groups || {}).every(enabled => !enabled) && (
                      <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>
                        No modules enabled
                      </div>
                    )}
                  </div>
                </div>

                {/* Disabled Modules */}
                <div style={{ marginBottom: '20px' }}>
                  <div style={{ color: 'var(--text-muted)', fontSize: '12px', fontWeight: 600, marginBottom: '8px' }}>
                    DISABLED MODULES
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    {Object.entries(rolePermissions.permission_groups || {})
                      .filter(([_, enabled]) => !enabled)
                      .map(([module, _]) => (
                        <div key={module} style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '8px',
                          color: 'var(--text-muted)',
                          fontSize: '13px'
                        }}>
                          <span style={{ color: '#f44336' }}>✗</span>
                          {module.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                        </div>
                      ))}
                    {Object.values(rolePermissions.permission_groups || {}).every(enabled => enabled) && (
                      <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>
                        All modules enabled
                      </div>
                    )}
                  </div>
                </div>

                {/* Permission Count */}
                <div style={{ marginBottom: '20px' }}>
                  <div style={{ color: 'var(--text-muted)', fontSize: '12px', fontWeight: 600, marginBottom: '8px' }}>
                    PERMISSION COUNT
                  </div>
                  <div style={{
                    display: 'grid',
                    gridTemplateColumns: '1fr 1fr',
                    gap: '8px'
                  }}>
                    <div style={{
                      background: 'rgba(76, 175, 80, 0.2)',
                      border: '1px solid #4CAF50',
                      borderRadius: '6px',
                      padding: '8px',
                      textAlign: 'center'
                    }}>
                      <div style={{ color: '#4CAF50', fontSize: '18px', fontWeight: 600 }}>
                        {Object.values(rolePermissions.permissions || {}).filter(Boolean).length}
                      </div>
                      <div style={{ color: '#4CAF50', fontSize: '11px' }}>Enabled</div>
                    </div>
                    <div style={{
                      background: 'rgba(244, 67, 54, 0.2)',
                      border: '1px solid #f44336',
                      borderRadius: '6px',
                      padding: '8px',
                      textAlign: 'center'
                    }}>
                      <div style={{ color: '#f44336', fontSize: '18px', fontWeight: 600 }}>
                        {Object.values(rolePermissions.permissions || {}).filter(v => !v).length}
                      </div>
                      <div style={{ color: '#f44336', fontSize: '11px' }}>Disabled</div>
                    </div>
                  </div>
                </div>

                {/* Advanced Mode Toggle */}
                <div style={{ marginBottom: '20px' }}>
                  <div style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '12px',
                    background: 'rgba(0,0,0,0.2)',
                    borderRadius: '8px',
                    border: '1px solid var(--glass-border)'
                  }}>
                    <span style={{ color: 'var(--text-main)', fontSize: '13px' }}>
                      Advanced Permission Matrix
                    </span>
                    <div
                      onClick={() => setShowAdvancedMatrix(!showAdvancedMatrix)}
                      style={{
                        width: '40px',
                        height: '22px',
                        background: showAdvancedMatrix ? '#4CAF50' : 'rgba(255,255,255,0.2)',
                        borderRadius: '11px',
                        position: 'relative',
                        cursor: 'pointer',
                        transition: 'all 0.2s ease'
                      }}
                    >
                      <div style={{
                        width: '18px',
                        height: '18px',
                        background: '#fff',
                        borderRadius: '50%',
                        position: 'absolute',
                        top: '2px',
                        left: showAdvancedMatrix ? '20px' : '2px',
                        transition: 'all 0.2s ease'
                      }} />
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Footer */}
            <div style={{
              padding: '16px 24px',
              borderTop: '1px solid var(--glass-border)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center'
            }}>
              <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>
                Last modified: {new Date().toLocaleString()}
              </div>
              <div style={{ display: 'flex', gap: '12px' }}>
                <button
                  onClick={() => setShowRoleConfig(false)}
                  style={{
                    background: 'var(--glass-bg)',
                    color: 'var(--text-main)',
                    border: '1px solid var(--glass-border)',
                    padding: '10px 20px',
                    borderRadius: '8px',
                    cursor: 'pointer',
                    fontSize: '14px',
                    fontWeight: 600
                  }}
                >
                  Cancel
                </button>
                <button
                  onClick={() => saveRolePermissions(editingRole)}
                  style={{
                    background: 'var(--primary)',
                    color: '#fff',
                    border: 'none',
                    padding: '10px 20px',
                    borderRadius: '8px',
                    cursor: 'pointer',
                    fontSize: '14px',
                    fontWeight: 600
                  }}
                >
                  Save Role
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// Firebase setup script for RBAC users collection
import { doc, setDoc, serverTimestamp } from "firebase/firestore";
import { db } from "./firebase";

// Sample users with roles and skills
const usersSetup = [
  {
    uid: "admin_user_id", // Replace with actual admin user ID
    email: "admin@test.com",
    role: "admin",
    skills: ["phishing", "malware", "network_attack"],
    avgResolveTime: 12,
    createdAt: serverTimestamp()
  },
  {
    uid: "analyst_user_id", // Replace with actual analyst user ID  
    email: "analyst@test.com",
    role: "analyst",
    skills: ["phishing", "account_compromise"],
    avgResolveTime: 8,
    createdAt: serverTimestamp()
  },
  {
    uid: "soc_manager_user_id", // Replace with actual SOC manager user ID
    email: "manager@test.com", 
    role: "soc_manager",
    skills: ["phishing", "malware", "account_compromise", "network_attack", "data_leak"],
    avgResolveTime: 6,
    createdAt: serverTimestamp()
  },
  {
    uid: "student_user_id", // Replace with actual student user ID
    email: "student@test.com",
    role: "analyst", // Students have analyst permissions
    skills: ["phishing"],
    avgResolveTime: 24,
    createdAt: serverTimestamp()
  }
];

// Function to setup users
export async function setupUsers() {
  try {
    console.log("Setting up users collection...");
    
    for (const user of usersSetup) {
      await setDoc(doc(db, "users", user.uid), user);
      console.log(`✅ Created user: ${user.email} with role: ${user.role}`);
    }
    
    console.log("🎉 Users collection setup complete!");
    return true;
  } catch (error) {
    console.error("❌ Error setting up users:", error);
    return false;
  }
}

// Function to get current user's role
export async function getUserRole(uid) {
  try {
    const userDoc = await getDoc(doc(db, "users", uid));
    if (userDoc.exists()) {
      return userDoc.data().role || "analyst";
    }
    return "analyst"; // Default role
  } catch (error) {
    console.error("Error getting user role:", error);
    return "analyst";
  }
}

// Function to update user skills
export async function updateUserSkills(uid, skills) {
  try {
    await updateDoc(doc(db, "users", uid), {
      skills,
      updatedAt: serverTimestamp()
    });
    console.log(`✅ Updated skills for user: ${uid}`);
    return true;
  } catch (error) {
    console.error("❌ Error updating user skills:", error);
    return false;
  }
}

// Function to update analyst performance metrics
export async function updateAnalystMetrics(uid, metrics) {
  try {
    await updateDoc(doc(db, "users", uid), {
      avgResolveTime: metrics.avgResolveTime,
      totalResolved: metrics.totalResolved,
      lastActiveAt: serverTimestamp(),
      updatedAt: serverTimestamp()
    });
    console.log(`✅ Updated metrics for analyst: ${uid}`);
    return true;
  } catch (error) {
    console.error("❌ Error updating analyst metrics:", error);
    return false;
  }
}

// Auto-assignment configuration
export const AUTO_ASSIGNMENT_CONFIG = {
  enabled: true,
  maxActiveTickets: 5, // Maximum tickets per analyst before auto-assignment stops
  skillMatching: true, // Require skill matching for assignment
  workloadBalancing: true, // Consider current workload
  performanceWeighting: 0.3 // Weight of avgResolveTime in assignment decision
};

// SLA breach prediction configuration
export const SLA_PREDICTION_CONFIG = {
  enabled: true,
  riskThreshold: 2.5,
  weights: {
    analystWorkload: 0.4,
    categoryAvgTime: 0.3,
    urgency: 0.3
  },
  urgencyWeights: {
    high: 3,
    medium: 2,
    low: 1
  }
};

// MITRE ATT&CK framework mapping
export const MITRE_FRAMEWORK = {
  tactics: {
    "TA0001": "Initial Access",
    "TA0002": "Execution", 
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control"
  },
  techniques: {
    "T1566": "Phishing",
    "T1204": "User Execution", 
    "T1110": "Brute Force",
    "T1046": "Network Service Discovery",
    "T1041": "Exfiltration Over C2 Channel"
  }
};

console.log("📋 RBAC Setup module loaded. Use setupUsers() to initialize.");

// Update user schema for capability-aware dashboard
import { doc, getDoc, updateDoc, serverTimestamp } from "firebase/firestore";
import { auth, db } from "./firebase";

// Function to update existing users with new schema
export async function updateUserSchema() {
  try {
    const user = auth.currentUser;
    if (!user) {
      console.log("❌ No user logged in");
      return false;
    }

    console.log("🔧 Updating user schema for:", user.email);

    // Define user configurations
    const userConfigs = [
      {
        email: "admin@test.com",
        analystLevel: "L2", // Admin gets L2 capabilities
        team: "soc_l2",
        skills: ["phishing", "malware", "network_attack", "account_compromise", "data_leak"],
        avgResolveTime: 6
      },
      {
        email: "analyst@test.com", 
        analystLevel: "L1", // Regular analyst gets L1
        team: "soc_l1",
        skills: ["phishing", "malware"],
        avgResolveTime: 8
      },
      {
        email: "student@test.com",
        analystLevel: "L1", // Student gets L1 (limited access)
        team: "soc_l1", 
        skills: ["phishing"],
        avgResolveTime: 24
      },
      {
        email: "ir_team@test.com",
        analystLevel: "IR", // Incident Response team
        team: "incident_response",
        skills: ["phishing", "malware", "account_compromise"],
        avgResolveTime: 4
      },
      {
        email: "threat_hunter@test.com", 
        analystLevel: "TH", // Threat Hunter
        team: "threat_hunter",
        skills: ["phishing", "malware", "network_attack", "account_compromise", "data_leak"],
        avgResolveTime: 12
      }
    ];

    // Update each user configuration
    for (const config of userConfigs) {
      try {
        // Query users by email (you'll need to adapt this based on your user IDs)
        console.log(`🔄 Updating ${config.email} with level ${config.analystLevel}`);
        
        // This is a template - you'll need to match with actual user IDs
        const updateData = {
          analystLevel: config.analystLevel,
          team: config.team,
          skills: config.skills,
          avgResolveTime: config.avgResolveTime,
          updatedAt: serverTimestamp()
        };

        console.log(`✅ Prepared update for ${config.email}:`, updateData);
        
        // Manual update required - run this for each user UID
        console.log(`📝 Manual update needed for user with email: ${config.email}`);
        console.log(`🔧 Update data:`, JSON.stringify(updateData, null, 2));
        
      } catch (error) {
        console.error(`❌ Error updating ${config.email}:`, error);
      }
    }

    console.log("✅ User schema update preparation complete!");
    console.log("📝 Next steps:");
    console.log("1. Go to Firebase Console → Firestore");
    console.log("2. Find each user by email/UID");
    console.log("3. Apply the update data shown above");
    console.log("4. Refresh the application");
    
    return true;
    
  } catch (error) {
    console.error("❌ Error updating user schema:", error);
    return false;
  }
}

// Function to check current user's capabilities
export async function checkCurrentUserCapabilities() {
  try {
    const user = auth.currentUser;
    if (!user) {
      console.log("❌ No user logged in");
      return null;
    }

    const userDoc = await getDoc(doc(db, "users", user.uid));
    if (!userDoc.exists()) {
      console.log("❌ No user document found for:", user.uid);
      return null;
    }

    const userData = userDoc.data();
    
    console.log("🔍 Current User Capabilities:");
    console.log(`📧 Email: ${userData.email}`);
    console.log(`🎯 Analyst Level: ${userData.analystLevel || 'Not set'}`);
    console.log(`👥 Team: ${userData.team || 'Not set'}`);
    console.log(`🛠 Skills: ${userData.skills?.join(', ') || 'Not set'}`);
    
    // Calculate capabilities
    const capabilities = {
      canEscalate: userData.analystLevel === "L1" || userData.analystLevel === "L2",
      canContain: userData.analystLevel === "IR" || userData.analystLevel === "L2", 
      canReassign: userData.analystLevel === "L2",
      canThreatHunt: userData.analystLevel === "TH"
    };
    
    console.log("🔐 Dynamic Capabilities:");
    console.log(`🚨 Can Escalate: ${capabilities.canEscalate}`);
    console.log(`🚫 Can Contain: ${capabilities.canContain}`);
    console.log(`🔄 Can Reassign: ${capabilities.canReassign}`);
    console.log(`🔍 Can Threat Hunt: ${capabilities.canThreatHunt}`);
    
    return capabilities;
    
  } catch (error) {
    console.error("❌ Error checking user capabilities:", error);
    return null;
  }
}

// Capability matrix reference
export const CAPABILITY_MATRIX = {
  L1: {
    escalate: true,
    contain: false,
    reassign: false,
    threatHunt: false,
    description: "Level 1 Analyst - Basic escalation rights"
  },
  L2: {
    escalate: true,
    contain: true,
    reassign: true,
    threatHunt: false,
    description: "Level 2 Analyst - Full operational rights"
  },
  IR: {
    escalate: false,
    contain: true,
    reassign: false,
    threatHunt: false,
    description: "Incident Response - Containment specialists"
  },
  TH: {
    escalate: false,
    contain: false,
    reassign: false,
    threatHunt: true,
    description: "Threat Hunter - Intelligence and analysis"
  }
};

console.log("🔧 User schema utilities loaded!");
console.log("📝 Available functions:");
console.log("  - updateUserSchema() // Update users with new schema");
console.log("  - checkCurrentUserCapabilities() // Check current user capabilities");
console.log("  - CAPABILITY_MATRIX // Reference matrix for all levels");

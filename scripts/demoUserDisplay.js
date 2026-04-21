// Enhanced User Display Demo
import { getDocs, collection } from "firebase/firestore";
import { db } from "./firebase";

// Demo function to show how user display works
export async function demoUserDisplay() {
  try {
    console.log("🎭 Enhanced User Display Demo");
    console.log("================================");
    
    // Fetch all users
    const usersSnapshot = await getDocs(collection(db, "users"));
    const users = {};
    
    usersSnapshot.forEach(doc => {
      users[doc.id] = {
        uid: doc.id,
        ...doc.data()
      };
    });
    
    console.log(`👥 Found ${Object.keys(users).length} users in Firestore`);
    
    // Demo the display function with different scenarios
    console.log("\n📋 Display Examples:");
    
    Object.entries(users).forEach(([uid, userData]) => {
      console.log(`\n🔹 User: ${uid}`);
      console.log(`   Email: ${userData.email}`);
      console.log(`   Display Name: ${userData.displayName || 'Not set'}`);
      console.log(`   Role: ${userData.role || 'Not set'}`);
      console.log(`   Analyst Level: ${userData.analystLevel || 'Not set'}`);
      console.log(`   Team: ${userData.team || 'Not set'}`);
      
      // Simulate the enhanced display logic
      let displayName = userData.displayName || userData.email || "Unknown User";
      
      if (userData.analystLevel) {
        const levelLabels = {
          "L1": "L1 Analyst",
          "L2": "L2 Analyst", 
          "IR": "IR Specialist",
          "TH": "Threat Hunter"
        };
        displayName += ` (${levelLabels[userData.analystLevel] || userData.analystLevel})`;
      } else if (userData.role) {
        const roleLabels = {
          "admin": "Admin",
          "analyst": "Analyst",
          "student": "Student"
        };
        displayName += ` (${roleLabels[userData.role] || userData.role})`;
      }
      
      console.log(`   📱 Enhanced Display: "${displayName}"`);
    });
    
    // Demo fallback scenarios
    console.log("\n🔄 Fallback Scenarios:");
    console.log("   📧 Email format: 'user@test.com' → 'user'");
    console.log("   🏷 Staff option: 'soc_l1' → 'SOC Analyst L1'");
    console.log("   ❓ Unknown UID: 'abc123xyz' → 'abc123xyz'");
    console.log("   🚫 No assignment: null → 'Unassigned'");
    
    return users;
    
  } catch (error) {
    console.error("❌ Demo failed:", error);
    return null;
  }
}

// Test the display function directly
export function testUserDisplay(assignedTo, usersData) {
  // This is the same logic used in the dashboards
  if (!assignedTo) return "Unassigned";
  
  if (usersData && usersData[assignedTo]) {
    const userData = usersData[assignedTo];
    let displayName = userData.displayName || userData.email || "Unknown User";
    
    if (userData.analystLevel) {
      const levelLabels = {
        "L1": "L1 Analyst",
        "L2": "L2 Analyst", 
        "IR": "IR Specialist",
        "TH": "Threat Hunter"
      };
      displayName += ` (${levelLabels[userData.analystLevel] || userData.analystLevel})`;
    } else if (userData.role) {
      const roleLabels = {
        "admin": "Admin",
        "analyst": "Analyst",
        "student": "Student"
      };
      displayName += ` (${roleLabels[userData.role] || userData.role})`;
    }
    
    return displayName;
  }
  
  // Fallback to staff options
  const staffOptions = [
    { value: "soc_l1", label: "SOC Analyst L1" },
    { value: "soc_l2", label: "SOC Analyst L2" },
    { value: "incident_response", label: "Incident Response Team" },
    { value: "threat_hunter", label: "Threat Hunter" }
  ];
  
  const found = staffOptions.find((x) => x.value === assignedTo);
  if (found) return found.label;
  
  if (assignedTo.includes("@")) {
    return assignedTo.split("@")[0];
  }
  
  return assignedTo;
}

console.log("🎭 Enhanced User Display Demo Loaded!");
console.log("📝 Available functions:");
console.log("  - demoUserDisplay() // Show all users with enhanced display");
console.log("  - testUserDisplay(assignedTo, usersData) // Test display logic");
console.log("\n🚀 Quick demo: await demoUserDisplay();");

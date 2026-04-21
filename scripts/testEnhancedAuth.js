// Test Enhanced Authentication Logic
import { doc, getDoc, setDoc, serverTimestamp } from "firebase/firestore";
import { auth, db } from "./firebase";

// Function to test enhanced auth logic
export async function testEnhancedAuth() {
  try {
    const user = auth.currentUser;
    if (!user) {
      console.log("❌ No user logged in");
      return false;
    }

    console.log("🧪 Testing Enhanced Authentication Logic");
    console.log(`📧 Current user: ${user.email}`);
    console.log(`🔑 User UID: ${user.uid}`);

    // Check if user document exists
    const userRef = doc(db, "users", user.uid);
    const userSnap = await getDoc(userRef);

    if (!userSnap.exists()) {
      console.log("🔧 User document does not exist - creating new profile...");
      
      // Simulate the enhanced auth logic
      await setDoc(userRef, {
        role: "analyst",
        analystLevel: "L1",
        team: "soc_l1",
        skills: [],
        avgResolveTime: 0,
        createdAt: serverTimestamp()
      });

      console.log("✅ New user profile created successfully!");
      console.log("📋 Profile details:");
      console.log("   - Role: analyst");
      console.log("   - Analyst Level: L1");
      console.log("   - Team: soc_l1");
      console.log("   - Skills: []");
      console.log("   - Avg Resolve Time: 0");
      
    } else {
      console.log("📋 User document already exists");
      const userData = userSnap.data();
      console.log("👤 Existing user profile:");
      console.log(`   - Role: ${userData.role || 'Not set'}`);
      console.log(`   - Analyst Level: ${userData.analystLevel || 'Not set'}`);
      console.log(`   - Team: ${userData.team || 'Not set'}`);
      console.log(`   - Skills: ${userData.skills?.join(', ') || 'Not set'}`);
      console.log(`   - Avg Resolve Time: ${userData.avgResolveTime || 'Not set'}`);
      console.log(`   - Created At: ${userData.createdAt?.toDate() || 'Not set'}`);
    }

    // Verify the document was created/updated correctly
    const verifySnap = await getDoc(userRef);
    const verifyData = verifySnap.data();
    
    console.log("\n🔍 Verification Results:");
    console.log(`✅ Document exists: ${verifySnap.exists()}`);
    console.log(`✅ Role field: ${verifyData.role}`);
    console.log(`✅ Analyst Level field: ${verifyData.analystLevel}`);
    console.log(`✅ Team field: ${verifyData.team}`);
    console.log(`✅ Skills field: ${verifyData.skills}`);
    console.log(`✅ Avg Resolve Time field: ${verifyData.avgResolveTime}`);

    return true;

  } catch (error) {
    console.error("❌ Error testing enhanced auth:", error);
    return false;
  }
}

// Function to test capability flags
export async function testCapabilityFlags() {
  try {
    const user = auth.currentUser;
    if (!user) {
      console.log("❌ No user logged in");
      return null;
    }

    const userRef = doc(db, "users", user.uid);
    const userSnap = await getDoc(userRef);

    if (!userSnap.exists()) {
      console.log("❌ No user document found");
      return null;
    }

    const userData = userSnap.data();
    const analystLevel = userData.analystLevel;

    console.log("\n🎯 Testing Capability Flags");
    console.log(`📊 Analyst Level: ${analystLevel}`);

    // Calculate capabilities based on level
    const capabilities = {
      canEscalate: analystLevel === "L1" || analystLevel === "L2",
      canContain: analystLevel === "IR" || analystLevel === "L2",
      canReassign: analystLevel === "L2",
      canThreatHunt: analystLevel === "TH"
    };

    console.log("🔐 Capability Flags:");
    console.log(`   🚨 Can Escalate: ${capabilities.canEscalate}`);
    console.log(`   🚫 Can Contain: ${capabilities.canContain}`);
    console.log(`   🔄 Can Reassign: ${capabilities.canReassign}`);
    console.log(`   🔍 Can Threat Hunt: ${capabilities.canThreatHunt}`);

    return capabilities;

  } catch (error) {
    console.error("❌ Error testing capability flags:", error);
    return null;
  }
}

// Function to simulate different user levels
export async function simulateUserLevel(newLevel) {
  try {
    const user = auth.currentUser;
    if (!user) {
      console.log("❌ No user logged in");
      return false;
    }

    console.log(`\n🔄 Simulating user level change to: ${newLevel}`);

    const userRef = doc(db, "users", user.uid);
    await setDoc(userRef, {
      role: "analyst",
      analystLevel: newLevel,
      team: newLevel === "TH" ? "threat_hunter" : 
           newLevel === "IR" ? "incident_response" : 
           newLevel === "L2" ? "soc_l2" : "soc_l1",
      skills: [],
      avgResolveTime: 0,
      createdAt: serverTimestamp()
    }, { merge: true });

    console.log(`✅ User level updated to ${newLevel}`);
    
    // Test new capabilities
    await testCapabilityFlags();
    
    return true;

  } catch (error) {
    console.error("❌ Error simulating user level:", error);
    return false;
  }
}

console.log("🧪 Enhanced Authentication Test Suite Loaded!");
console.log("📝 Available functions:");
console.log("  - testEnhancedAuth() // Test profile creation logic");
console.log("  - testCapabilityFlags() // Test capability calculations");
console.log("  - simulateUserLevel(level) // Test different user levels");
console.log("\n🎯 Usage examples:");
console.log("  await testEnhancedAuth();");
console.log("  await testCapabilityFlags();");
console.log("  await simulateUserLevel('L2');");
console.log("  await simulateUserLevel('IR');");
console.log("  await simulateUserLevel('TH');");

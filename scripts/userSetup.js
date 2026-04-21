// Manual user setup script - run this in browser console when logged in as each user
import { doc, setDoc, updateDoc, serverTimestamp, getDoc } from "firebase/firestore";
import { auth, db } from "./firebase";

// Function to setup current user's role
async function setupCurrentUserRole(role, skills = [], avgResolveTime = 24) {
  try {
    const user = auth.currentUser;
    if (!user) {
      console.error("❌ No user logged in!");
      return false;
    }

    console.log(`🔧 Setting up user: ${user.email}`);
    console.log(`📐 Role: ${role}`);
    console.log(`🛠 Skills: ${skills.join(", ")}`);
    console.log(`⏱ Avg Resolve Time: ${avgResolveTime}h`);

    const userRef = doc(db, "users", user.uid);
    const userDoc = await getDoc(userRef);

    const userData = {
      email: user.email,
      role: role,
      skills: skills,
      avgResolveTime: avgResolveTime,
      updatedAt: serverTimestamp()
    };

    if (userDoc.exists()) {
      console.log("🔄 Updating existing user document...");
      await updateDoc(userRef, userData);
    } else {
      console.log("📝 Creating new user document...");
      await setDoc(userRef, {
        ...userData,
        createdAt: serverTimestamp()
      });
    }

    console.log("✅ User setup complete!");
    console.log("🔄 Please refresh the page to see the changes.");
    return true;

  } catch (error) {
    console.error("❌ Error setting up user:", error);
    return false;
  }
}

// Predefined user setups
const USER_SETUPS = {
  admin: {
    role: "admin",
    skills: ["phishing", "malware", "network_attack", "account_compromise", "data_leak"],
    avgResolveTime: 6
  },
  analyst: {
    role: "analyst", 
    skills: ["phishing", "malware"],
    avgResolveTime: 8
  },
  student: {
    role: "student",
    skills: ["phishing"],
    avgResolveTime: 24
  }
};

// Quick setup functions for each user type
window.setupAsAdmin = () => setupCurrentUserRole(
  USER_SETUPS.admin.role,
  USER_SETUPS.admin.skills,
  USER_SETUPS.admin.avgResolveTime
);

window.setupAsAnalyst = () => setupCurrentUserRole(
  USER_SETUPS.analyst.role,
  USER_SETUPS.analyst.skills,
  USER_SETUPS.analyst.avgResolveTime
);

window.setupAsStudent = () => setupCurrentUserRole(
  USER_SETUPS.student.role,
  USER_SETUPS.student.skills,
  USER_SETUPS.student.avgResolveTime
);

// Debug function to check current user
window.checkCurrentUser = async () => {
  try {
    const user = auth.currentUser;
    if (!user) {
      console.log("❌ No user logged in");
      return;
    }

    console.log(`👤 Current user: ${user.email}`);
    console.log(`🆔 UID: ${user.uid}`);

    const userDoc = await getDoc(doc(db, "users", user.uid));
    if (userDoc.exists()) {
      const userData = userDoc.data();
      console.log("📋 User data:", userData);
    } else {
      console.log("❌ No user document found in Firestore");
    }

  } catch (error) {
    console.error("❌ Error checking user:", error);
  }
};

console.log("🔧 User setup functions loaded!");
console.log("📝 Available commands:");
console.log("  - setupAsAdmin()   // Set current user as admin");
console.log("  - setupAsAnalyst() // Set current user as analyst"); 
console.log("  - setupAsStudent() // Set current user as student");
console.log("  - checkCurrentUser() // Check current user info");
console.log("\n💡 Usage:");
console.log("1. Log in with the desired user account");
console.log("2. Run the appropriate setup function in console");
console.log("3. Refresh the page to see the correct dashboard");

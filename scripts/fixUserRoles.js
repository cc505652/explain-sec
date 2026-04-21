// Quick script to check and fix user roles
import { doc, getDoc, setDoc, updateDoc, serverTimestamp } from "firebase/firestore";
import { auth, db } from "./firebase";

// Current user role mapping based on your requirements
const USER_ROLES = {
  "admin@test.com": "admin",      // Should see AdminDashboard (with intelligence features)
  "analyst@test.com": "analyst",  // Should see AnalystDashboard 
  "student@test.com": "student"    // Should see SubmitIssue + IssueList
};

export async function checkAndFixUserRoles() {
  try {
    console.log("🔍 Checking user roles...");
    
    for (const [email, role] of Object.entries(USER_ROLES)) {
      console.log(`\n📧 Checking ${email}...`);
      
      // Sign in with each user to get their UID
      try {
        // For now, let's just update based on email patterns
        // In a real scenario, you'd need to authenticate first
        
        const usersSnapshot = await getDocs(collection(db, "users"));
        let userFound = false;
        
        usersSnapshot.forEach(doc => {
          const userData = doc.data();
          if (userData.email === email) {
            userFound = true;
            console.log(`  ✅ Found user: ${doc.id} with current role: ${userData.role}`);
            
            if (userData.role !== role) {
              console.log(`  🔄 Updating role from ${userData.role} to ${role}`);
              return updateDoc(doc.ref, { 
                role,
                updatedAt: serverTimestamp()
              });
            } else {
              console.log(`  ✅ Role already correct`);
            }
          }
        });
        
        if (!userFound) {
          console.log(`  ❌ User not found in users collection`);
        }
        
      } catch (error) {
        console.error(`  ❌ Error processing ${email}:`, error);
      }
    }
    
    console.log("\n🎉 User role check complete!");
    
  } catch (error) {
    console.error("❌ Error checking user roles:", error);
  }
}

// Function to create users if they don't exist
export async function ensureUsersExist() {
  const usersToCreate = [
    {
      email: "admin@test.com",
      role: "admin",
      skills: ["phishing", "malware", "network_attack", "account_compromise", "data_leak"],
      avgResolveTime: 6
    },
    {
      email: "analyst@test.com", 
      role: "analyst",
      skills: ["phishing", "malware"],
      avgResolveTime: 8
    },
    {
      email: "student@test.com",
      role: "student", 
      skills: ["phishing"],
      avgResolveTime: 24
    }
  ];
  
  try {
    console.log("🔧 Ensuring users exist...");
    
    for (const user of usersToCreate) {
      console.log(`\n👤 Processing ${user.email}...`);
      
      // You'll need to authenticate first to get the UID
      // For now, this is a template you can use manually
      
      console.log(`  📝 Role: ${user.role}`);
      console.log(`  🛠 Skills: ${user.skills.join(", ")}`);
      console.log(`  ⏱ Avg Resolve Time: ${user.avgResolveTime}h`);
    }
    
    console.log("\n✅ User template ready!");
    console.log("📝 Manual setup required: Authenticate each user and create their document in Firestore");
    
  } catch (error) {
    console.error("❌ Error ensuring users exist:", error);
  }
}

// Debug function to list all users
export async function listAllUsers() {
  try {
    console.log("📋 Listing all users in Firestore...");
    
    const usersSnapshot = await getDocs(collection(db, "users"));
    
    if (usersSnapshot.empty) {
      console.log("❌ No users found in Firestore!");
      return;
    }
    
    usersSnapshot.forEach(doc => {
      const userData = doc.data();
      console.log(`\n👤 User ID: ${doc.id}`);
      console.log(`  📧 Email: ${userData.email || 'Not set'}`);
      console.log(`  🔐 Role: ${userData.role || 'Not set'}`);
      console.log(`  🛠 Skills: ${userData.skills?.join(", ") || 'Not set'}`);
      console.log(`  ⏱ Avg Resolve Time: ${userData.avgResolveTime || 'Not set'}h`);
      console.log(`  📅 Created: ${userData.createdAt?.toDate() || 'Not set'}`);
    });
    
    console.log(`\n📊 Total users: ${usersSnapshot.size}`);
    
  } catch (error) {
    console.error("❌ Error listing users:", error);
  }
}

console.log("🔧 User management utilities loaded!");
console.log("📝 Available functions:");
console.log("  - checkAndFixUserRoles()");
console.log("  - ensureUsersExist()"); 
console.log("  - listAllUsers()");

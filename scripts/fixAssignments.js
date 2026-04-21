// Fix Old Assignment Migration Script
import { getDocs, collection, updateDoc, doc, query, where } from "firebase/firestore";
import { db } from "./firebase";

// Migration script to fix old staff option assignments
export async function fixOldAssignments() {
  try {
    console.log("🔧 Starting migration to fix old assignments...");
    
    // Old staff options that need to be removed
    const oldStaffOptions = [
      "soc_network",
      "soc_endpoint", 
      "soc_email",
      "soc_identity",
      "soc_l1",
      "soc_l2",
      "incident_response",
      "threat_hunter",
      "forensics",
      "cloud_security",
      "network_security"
    ];
    
    // Get all issues with old assignments
    const issuesSnapshot = await getDocs(collection(db, "issues"));
    const issuesToUpdate = [];
    
    issuesSnapshot.forEach(doc => {
      const issueData = doc.data();
      if (issueData.assignedTo && oldStaffOptions.includes(issueData.assignedTo)) {
        issuesToUpdate.push({
          id: doc.id,
          oldAssignment: issueData.assignedTo,
          title: issueData.title,
          category: issueData.category
        });
      }
    });
    
    console.log(`📋 Found ${issuesToUpdate.length} issues with old assignments`);
    
    if (issuesToUpdate.length === 0) {
      console.log("✅ No issues need fixing - all assignments are already using user UIDs");
      return;
    }
    
    // Get all real users for potential reassignment
    const usersSnapshot = await getDocs(collection(db, "users"));
    const realUsers = [];
    
    usersSnapshot.forEach(doc => {
      const userData = doc.data();
      if (userData.role === 'analyst' || userData.role === 'admin') {
        realUsers.push({
          uid: doc.id,
          email: userData.email,
          displayName: userData.displayName,
          analystLevel: userData.analystLevel,
          skills: userData.skills || []
        });
      }
    });
    
    console.log(`👥 Found ${realUsers.length} real users for reassignment`);
    
    // Update each issue with old assignment
    for (const issue of issuesToUpdate) {
      console.log(`\n🔄 Fixing issue: "${issue.title}"`);
      console.log(`   Old assignment: ${issue.oldAssignment}`);
      console.log(`   Category: ${issue.category}`);
      
      // Find best user for this category
      let bestUser = null;
      
      if (issue.category) {
        // Try to find user with matching skills
        bestUser = realUsers.find(user => 
          user.skills && user.skills.includes(issue.category)
        );
      }
      
      // If no skill match, find L2 analyst (highest priority)
      if (!bestUser) {
        bestUser = realUsers.find(user => user.analystLevel === 'L2');
      }
      
      // If no L2, find L1 analyst
      if (!bestUser) {
        bestUser = realUsers.find(user => user.analystLevel === 'L1');
      }
      
      // If no analysts, find any admin
      if (!bestUser) {
        bestUser = realUsers.find(user => user.role === 'admin');
      }
      
      // If still no match, pick first available user
      if (!bestUser && realUsers.length > 0) {
        bestUser = realUsers[0];
      }
      
      if (bestUser) {
        console.log(`   ✅ Reassigning to: ${bestUser.displayName || bestUser.email} (${bestUser.analystLevel || bestUser.role})`);
        
        await updateDoc(doc(db, "issues", issue.id), {
          assignedTo: bestUser.uid,
          status: "assigned", // Ensure status is properly set
          statusHistory: [
            ...(issueData.statusHistory || []),
            { 
              status: "assigned", 
              at: new Date(), 
              note: `Auto-reassigned from ${issue.oldAssignment} to ${bestUser.displayName || bestUser.email} during migration` 
            }
          ],
          updatedAt: new Date()
        });
        
        console.log(`   📝 Updated issue ${issue.id}`);
      } else {
        console.log(`   ❌ No suitable user found - leaving unassigned`);
        
        // Set to unassigned
        await updateDoc(doc(db, "issues", issue.id), {
          assignedTo: null,
          status: "open",
          statusHistory: [
            ...(issueData.statusHistory || []),
            { 
              status: "open", 
              at: new Date(), 
              note: `Removed old assignment ${issue.oldAssignment} during migration - now unassigned` 
            }
          ],
          updatedAt: new Date()
        });
      }
    }
    
    console.log("\n🎉 Migration completed!");
    console.log(`✅ Fixed ${issuesToUpdate.length} issues with old assignments`);
    console.log("📋 All issues now use real user UIDs instead of staff options");
    
  } catch (error) {
    console.error("❌ Migration failed:", error);
  }
}

// Function to check current assignment status
export async function checkAssignmentStatus() {
  try {
    console.log("🔍 Checking current assignment status...");
    
    const issuesSnapshot = await getDocs(collection(db, "issues"));
    const assignmentStats = {
      total: 0,
      realUsers: 0,
      oldStaffOptions: 0,
      unassigned: 0,
      oldAssignments: {}
    };
    
    const oldStaffOptions = [
      "soc_network", "soc_endpoint", "soc_email", "soc_identity",
      "soc_l1", "soc_l2", "incident_response", "threat_hunter",
      "forensics", "cloud_security", "network_security"
    ];
    
    issuesSnapshot.forEach(doc => {
      const issueData = doc.data();
      assignmentStats.total++;
      
      if (!issueData.assignedTo) {
        assignmentStats.unassigned++;
      } else if (oldStaffOptions.includes(issueData.assignedTo)) {
        assignmentStats.oldStaffOptions++;
        assignmentStats.oldAssignments[issueData.assignedTo] = 
          (assignmentStats.oldAssignments[issueData.assignedTo] || 0) + 1;
      } else {
        assignmentStats.realUsers++;
      }
    });
    
    console.log("📊 Assignment Status Report:");
    console.log(`   Total Issues: ${assignmentStats.total}`);
    console.log(`   ✅ Real User Assignments: ${assignmentStats.realUsers}`);
    console.log(`   ❌ Old Staff Option Assignments: ${assignmentStats.oldStaffOptions}`);
    console.log(`   🚫 Unassigned: ${assignmentStats.unassigned}`);
    
    if (assignmentStats.oldStaffOptions > 0) {
      console.log("\n🔧 Old Assignments Found:");
      Object.entries(assignmentStats.oldAssignments).forEach(([assignment, count]) => {
        console.log(`   ${assignment}: ${count} issues`);
      });
      console.log("\n💡 Run fixOldAssignments() to migrate these to real users");
    } else {
      console.log("\n✅ All assignments are using real users - no migration needed!");
    }
    
    return assignmentStats;
    
  } catch (error) {
    console.error("❌ Status check failed:", error);
    return null;
  }
}

console.log("🔧 Assignment Migration Tools Loaded!");
console.log("📝 Available functions:");
console.log("  - checkAssignmentStatus() // Check current assignment status");
console.log("  - fixOldAssignments() // Migrate old assignments to real users");
console.log("\n🚀 Quick usage:");
console.log("  await checkAssignmentStatus();");
console.log("  await fixOldAssignments();");

// Quick Migration Script for Analyst Dashboard
// Copy and paste this into browser console while on Analyst Dashboard

(async function quickMigration() {
  try {
    console.log("🔧 Starting quick migration for Analyst Dashboard...");
    
    // Get Firebase instances - they should be available from the imports
    const { getDocs, collection, doc, updateDoc, query, where } = window.firebase?.firestore || {};
    const db = window.firebaseDb;
    
    if (!db || !getDocs) {
      console.error("❌ Firebase not available. Make sure you're on the dashboard page.");
      return;
    }
    
    // Step 1: Get all users to create a mapping
    console.log("📋 Step 1: Fetching users...");
    const usersSnapshot = await getDocs(collection(db, "users"));
    const usersMap = {};
    
    usersSnapshot.forEach(doc => {
      const userData = doc.data();
      usersMap[doc.id] = {
        uid: doc.id,
        email: userData.email,
        displayName: userData.displayName,
        role: userData.role,
        analystLevel: userData.analystLevel
      };
    });
    
    console.log(`✅ Found ${usersSnapshot.docs.length} users:`, Object.keys(usersMap));
    
    // Step 2: Find issues with old staff assignments
    console.log("📋 Step 2: Finding issues with old assignments...");
    const issuesSnapshot = await getDocs(collection(db, "issues"));
    const oldStaffOptions = [
      "soc_network", "soc_endpoint", "soc_email", "soc_identity",
      "soc_l1", "soc_l2", "incident_response", "threat_hunter",
      "forensics", "cloud_security", "network_security"
    ];
    
    const issuesToFix = [];
    
    issuesSnapshot.forEach(doc => {
      const issueData = doc.data();
      if (issueData.assignedTo && oldStaffOptions.includes(issueData.assignedTo)) {
        issuesToFix.push({
          id: doc.id,
          ...issueData
        });
      }
    });
    
    console.log(`🔍 Found ${issuesToFix.length} issues with old assignments`);
    
    if (issuesToFix.length === 0) {
      console.log("✅ No issues need fixing!");
      return;
    }
    
    // Step 3: Create a simple mapping from old staff to users
    const staffToUserMapping = {};
    
    // Find analysts for assignment
    const analysts = Object.values(usersMap).filter(user => user.role === 'analyst');
    console.log(`👥 Found ${analysts.length} analysts for assignment`);
    
    if (analysts.length === 0) {
      console.error("❌ No analysts found to assign issues to!");
      return;
    }
    
    // Simple mapping - assign to first available analyst
    const primaryAnalyst = analysts[0];
    console.log(`🎯 Primary analyst for assignment: ${primaryAnalyst.displayName || primaryAnalyst.email}`);
    
    // Step 4: Update issues
    console.log("📋 Step 4: Updating issues...");
    let updated = 0;
    
    for (const issue of issuesToFix) {
      try {
        // Reset to unassigned and open status for better testing
        await updateDoc(doc(db, "issues", issue.id), {
          assignedTo: null, // Make it unassigned
          status: "open", // Make it open so analysts can claim
          statusHistory: [
            ...(issue.statusHistory || []),
            { 
              status: "open", 
              at: new window.firebase.firestore.Timestamp.now(), 
              note: `Reset from old assignment (${issue.assignedTo}) - ready for claiming` 
            }
          ],
          updatedAt: new window.firebase.firestore.Timestamp.now()
        });
        
        updated++;
        console.log(`✅ Updated issue: "${issue.title}" - now unassigned and open`);
        
      } catch (error) {
        console.error(`❌ Failed to update issue ${issue.id}:`, error);
      }
    }
    
    console.log(`🎉 Migration complete! Updated ${updated}/${issuesToFix.length} issues`);
    console.log("📋 All issues are now unassigned and open - ready for analysts to claim!");
    console.log("🔄 Refresh the Analyst Dashboard to see the incidents!");
    
  } catch (error) {
    console.error("❌ Migration failed:", error);
  }
})();

console.log("🔧 Quick Migration Script Loaded!");
console.log("📝 Run: quickMigration()");
console.log("💡 This will reset old staff assignments to unassigned/open status");

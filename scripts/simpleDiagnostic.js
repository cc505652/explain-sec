// Simple Console Diagnostic for Auto-Assignment
// Copy and paste this into browser console while on Admin Dashboard page

(async function simpleDiagnose() {
  try {
    console.log("🔍 Simple Auto-Assignment Diagnostic...");
    
    // Check if we're on the right page with Firebase available
    if (typeof firebase === 'undefined' && typeof window.firebase === 'undefined') {
      console.error("❌ Firebase not found. Make sure you're on the Admin Dashboard page.");
      console.log("💡 Navigate to Admin Dashboard first, then run this script");
      return;
    }
    
    // Try to get Firebase from the React app's scope
    let db, getDocs, collection;
    
    // Method 1: Check if Firebase is available globally
    if (typeof window !== 'undefined' && window.firebaseDb) {
      db = window.firebaseDb;
      getDocs = window.firebase.firestore.getDocs;
      collection = window.firebase.firestore.collection;
    }
    // Method 2: Try to access from React dev tools
    else if (typeof window !== 'undefined' && window.__REACT_DEVTOOLS_GLOBAL_HOOK__) {
      console.log("🔧 Trying React Dev Tools approach...");
      // This is a fallback - might not work
      console.log("❌ Cannot access Firebase from React Dev Tools");
      return;
    }
    // Method 3: Manual check using the app's Firebase instances
    else {
      console.log("🔧 Trying manual Firebase access...");
      // We'll need to access the Firebase instances used by your React app
      console.log("❌ Cannot access Firebase instances automatically");
      console.log("💡 Please use the Admin Dashboard UI to check assignments");
      return;
    }
    
    if (!db) {
      console.error("❌ Could not access Firebase database");
      return;
    }
    
    console.log("✅ Firebase connected, checking data...");
    
    // Check users
    const usersSnapshot = await getDocs(collection(db, "users"));
    const analysts = [];
    
    usersSnapshot.forEach(doc => {
      const userData = doc.data();
      if (userData.role === 'analyst') {
        analysts.push({
          uid: doc.id,
          email: userData.email,
          displayName: userData.displayName,
          analystLevel: userData.analystLevel,
          skills: userData.skills || []
        });
      }
    });
    
    console.log(`👥 Found ${analysts.length} analysts:`);
    analysts.forEach(analyst => {
      console.log(`   📧 ${analyst.email || 'No email'}`);
      console.log(`   🏷️ ${analyst.displayName || 'No name'} (${analyst.analystLevel || 'No level'})`);
      console.log(`   🛠️ Skills: [${analyst.skills.join(', ') || 'None'}]`);
    });
    
    // Check issues
    const issuesSnapshot = await getDocs(collection(db, "issues"));
    const unassignedIssues = [];
    
    issuesSnapshot.forEach(doc => {
      const issueData = doc.data();
      if (issueData.status === 'open' && !issueData.assignedTo && !issueData.isDeleted) {
        unassignedIssues.push({
          id: doc.id,
          title: issueData.title,
          category: issueData.category,
          urgency: issueData.urgency
        });
      }
    });
    
    console.log(`\n📋 Found ${unassignedIssues.length} unassigned issues:`);
    unassignedIssues.forEach(issue => {
      console.log(`   🔴 ${issue.title}`);
      console.log(`   🧠 Category: ${issue.category}`);
    });
    
    // Check for skill matches
    console.log(`\n🔄 Skill Matching Analysis:`);
    
    if (analysts.length === 0) {
      console.log(`   🚨 CRITICAL: No analysts found!`);
      console.log(`   🔧 Need to create analyst users`);
    } else if (unassignedIssues.length === 0) {
      console.log(`   ✅ No unassigned issues - system working!`);
    } else {
      const issuesWithMatches = [];
      const issuesWithoutMatches = [];
      
      unassignedIssues.forEach(issue => {
        const matchingAnalysts = analysts.filter(analyst => 
          analyst.skills.includes(issue.category)
        );
        
        if (matchingAnalysts.length > 0) {
          issuesWithMatches.push({
            issue: issue.title,
            category: issue.category,
            matches: matchingAnalysts.length
          });
        } else {
          issuesWithoutMatches.push({
            issue: issue.title,
            category: issue.category
          });
        }
      });
      
      console.log(`   ✅ Issues with skill matches: ${issuesWithMatches.length}`);
      issuesWithMatches.forEach(item => {
        console.log(`      📝 ${item.issue} (${item.category}) - ${item.matches} analysts available`);
      });
      
      console.log(`   ❌ Issues without skill matches: ${issuesWithoutMatches.length}`);
      issuesWithoutMatches.forEach(item => {
        console.log(`      📝 ${item.issue} (${item.category}) - no matching skills`);
      });
      
      // Check if analysts have skills at all
      const analystsWithSkills = analysts.filter(analyst => analyst.skills.length > 0);
      console.log(`   📊 Analysts with skills: ${analystsWithSkills.length}/${analysts.length}`);
      
      if (analystsWithSkills.length === 0) {
        console.log(`   🔧 CRITICAL: No analysts have skills!`);
        console.log(`   💡 All analysts need skills added to their profiles`);
      }
    }
    
  } catch (error) {
    console.error("❌ Diagnostic failed:", error);
    console.log("💡 Alternative: Check the Admin Dashboard UI manually");
    console.log("   1. Look at the assignment dropdown");
    console.log("   2. See if real users appear in the list");
    console.log("   3. Check if issues show as unassigned");
  }
})();

console.log("🔍 Simple Diagnostic Loaded!");
console.log("📝 Run: simpleDiagnose()");
console.log("💡 Make sure you're on the Admin Dashboard page first");

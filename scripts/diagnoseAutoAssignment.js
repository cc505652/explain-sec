// Auto-Assignment Diagnostic Script
import { getDocs, collection, doc, updateDoc } from "firebase/firestore";
import { db } from "./firebase";

// Diagnostic function to check auto-assignment
export async function diagnoseAutoAssignment() {
  try {
    console.log("🔍 Diagnosing Auto-Assignment System...");
    
    // 1. Check all users
    const usersSnapshot = await getDocs(collection(db, "users"));
    const users = {};
    const analysts = [];
    
    usersSnapshot.forEach(doc => {
      const userData = doc.data();
      users[doc.id] = userData;
      
      if (userData.role === 'analyst') {
        analysts.push({
          uid: doc.id,
          email: userData.email,
          displayName: userData.displayName,
          analystLevel: userData.analystLevel,
          team: userData.team,
          skills: userData.skills || []
        });
      }
    });
    
    console.log(`\n👥 Found ${analysts.length} analysts:`);
    analysts.forEach(analyst => {
      console.log(`   📧 ${analyst.email || 'No email'}`);
      console.log(`   🏷️ ${analyst.displayName || 'No name'} (${analyst.analystLevel || 'No level'})`);
      console.log(`   🛠️ Skills: [${analyst.skills.join(', ') || 'None'}]`);
      console.log(`   👥 Team: ${analyst.team || 'No team'}`);
      console.log('');
    });
    
    // 2. Check all unassigned issues
    const issuesSnapshot = await getDocs(collection(db, "issues"));
    const unassignedIssues = [];
    
    issuesSnapshot.forEach(doc => {
      const issueData = doc.data();
      if (issueData.status === 'open' && !issueData.assignedTo && !issueData.isDeleted) {
        unassignedIssues.push({
          id: doc.id,
          ...issueData
        });
      }
    });
    
    console.log(`\n📋 Found ${unassignedIssues.length} unassigned issues:`);
    unassignedIssues.forEach(issue => {
      console.log(`   🔴 ${issue.title}`);
      console.log(`   🧠 Category: ${issue.category}`);
      console.log(`   ⚡ Urgency: ${issue.urgency}`);
      console.log(`   📍 Location: ${issue.location}`);
      console.log('');
    });
    
    // 3. Simulate auto-assignment for each issue
    console.log(`\n🔄 Simulating Auto-Assignment:`);
    
    for (const issue of unassignedIssues) {
      console.log(`\n📝 Processing: "${issue.title}"`);
      console.log(`   🧠 Category: ${issue.category}`);
      
      // Find analysts with matching skills (same logic as auto-assignment engine)
      const availableAnalysts = analysts.filter(analyst => 
        analyst.skills.includes(issue.category)
      );
      
      console.log(`   👥 Analysts with matching skills: ${availableAnalysts.length}`);
      
      if (availableAnalysts.length > 0) {
        availableAnalysts.forEach(analyst => {
          console.log(`      ✅ ${analyst.displayName || analyst.email} (${analyst.analystLevel})`);
        });
        
        // Pick the first one (simplified - real engine uses workload)
        const bestAnalyst = availableAnalysts[0];
        console.log(`   🎯 Best match: ${bestAnalyst.displayName || bestAnalyst.email}`);
        console.log(`   🔗 Would assign to UID: ${bestAnalyst.uid}`);
      } else {
        console.log(`   ❌ No analysts found with skill: ${issue.category}`);
        
        // Check if any analysts exist at all
        if (analysts.length === 0) {
          console.log(`   🚫 No analysts found in system!`);
        } else {
          console.log(`   📊 Available analyst skills:`);
          const allSkills = new Set();
          analysts.forEach(analyst => {
            analyst.skills.forEach(skill => allSkills.add(skill));
          });
          console.log(`      Skills: [${Array.from(allSkills).join(', ')}]`);
        }
      }
    }
    
    // 4. Recommendations
    console.log(`\n💡 Recommendations:`);
    
    if (analysts.length === 0) {
      console.log(`   🚨 CRITICAL: No analysts found in system!`);
      console.log(`   🔧 Fix: Create analyst users with proper roles and skills`);
    } else if (unassignedIssues.length === 0) {
      console.log(`   ✅ No unassigned issues - auto-assignment working!`);
    } else {
      const skillsNeeded = new Set();
      unassignedIssues.forEach(issue => skillsNeeded.add(issue.category));
      
      console.log(`   📊 Skills needed for unassigned issues: [${Array.from(skillsNeeded).join(', ')}]`);
      
      const hasSkills = analysts.some(analyst => analyst.skills.length > 0);
      if (!hasSkills) {
        console.log(`   🔧 Fix: Add skills to analyst profiles`);
        console.log(`   💡 Example skills: ${Array.from(skillsNeeded).join(', ')}`);
      }
    }
    
    return {
      analysts: analysts.length,
      unassignedIssues: unassignedIssues.length,
      users: users
    };
    
  } catch (error) {
    console.error("❌ Diagnostic failed:", error);
    return null;
  }
}

// Quick fix function to add basic skills to all analysts
export async function addBasicSkillsToAnalysts() {
  try {
    console.log("🔧 Adding basic skills to all analysts...");
    
    const usersSnapshot = await getDocs(collection(db, "users"));
    const commonSkills = ["phishing", "malware", "network_attack", "account_compromise", "data_leak"];
    
    let updated = 0;
    
    for (const userDoc of usersSnapshot.docs) {
      const userData = userDoc.data();
      
      if (userData.role === 'analyst' && (!userData.skills || userData.skills.length === 0)) {
        console.log(`📝 Updating ${userData.email || userDoc.id}...`);
        
        await updateDoc(doc(db, "users", userDoc.id), {
          skills: commonSkills,
          updatedAt: new Date()
        }, { merge: true });
        
        updated++;
      }
    }
    
    console.log(`✅ Updated ${updated} analysts with basic skills`);
    console.log(`🛠️ Added skills: ${commonSkills.join(', ')}`);
    
  } catch (error) {
    console.error("❌ Failed to add skills:", error);
  }
}

console.log("🔍 Auto-Assignment Diagnostic Tools Loaded!");
console.log("📝 Available functions:");
console.log("  - diagnoseAutoAssignment() // Check auto-assignment system");
console.log("  - addBasicSkillsToAnalysts() // Add skills to analysts");
console.log("\n🚀 Quick usage:");
console.log("  await diagnoseAutoAssignment();");
console.log("  await addBasicSkillsToAnalysts();");

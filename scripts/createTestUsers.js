// Test User Creation Utility
// Run this once in browser console to create test users

import { createUserWithEmailAndPassword, updateProfile } from "firebase/auth";
import { doc, setDoc, serverTimestamp } from "firebase/firestore";
import { auth, db } from "./firebase";

async function createTestUsers() {
  console.log("Creating test users...");

  try {
    // Create Analyst User
    const analystCredential = await createUserWithEmailAndPassword(
      auth, 
      "admin@test.com", 
      "test1234"
    );
    
    await updateProfile(analystCredential.user, {
      displayName: "SOC Analyst"
    });

    await setDoc(doc(db, "users", analystCredential.user.uid), {
      role: "analyst",
      createdAt: serverTimestamp(),
      email: "admin@test.com",
      displayName: "SOC Analyst"
    });

    console.log("✅ Analyst user created: admin@test.com");

    // Create Admin User
    const adminCredential = await createUserWithEmailAndPassword(
      auth, 
      "analyst@test.com", 
      "Test@1234"
    );
    
    await updateProfile(adminCredential.user, {
      displayName: "SOC Manager"
    });

    await setDoc(doc(db, "users", adminCredential.user.uid), {
      role: "admin",
      createdAt: serverTimestamp(),
      email: "analyst@test.com",
      displayName: "SOC Manager"
    });

    console.log("✅ Admin user created: analyst@test.com");

    // Create a Student User for testing
    const studentCredential = await createUserWithEmailAndPassword(
      auth, 
      "student@test.com", 
      "student123"
    );
    
    await updateProfile(studentCredential.user, {
      displayName: "Test Student"
    });

    await setDoc(doc(db, "users", studentCredential.user.uid), {
      role: "student",
      createdAt: serverTimestamp(),
      email: "student@test.com",
      displayName: "Test Student"
    });

    console.log("✅ Student user created: student@test.com");

    console.log("🎉 All test users created successfully!");
    console.log("\nLogin Credentials:");
    console.log("Analyst: admin@test.com / test1234");
    console.log("Admin: analyst@test.com / Test@1234");
    console.log("Student: student@test.com / student123");

  } catch (error) {
    console.error("❌ Error creating users:", error);
    if (error.code === 'auth/email-already-in-use') {
      console.log("Users already exist. You can login with existing credentials.");
    }
  }
}

// Export for manual execution
window.createTestUsers = createTestUsers;

console.log("📝 To create test users, run: createTestUsers() in browser console");

// Debug script to check Admin user permissions
// Run this in the browser console when logged in as Admin

import { doc, getDoc, getFirestore } from 'firebase/firestore';
import { getAuth } from 'firebase/auth';

const debugAdminPermissions = async () => {
  const auth = getAuth();
  const db = getFirestore();
  const user = auth.currentUser;
  
  if (!user) {
    console.error('❌ No user logged in');
    return;
  }
  
  console.log('🔍 Debugging Admin Permissions...');
  console.log('User UID:', user.uid);
  console.log('User Email:', user.email);
  
  try {
    // Check user document
    const userDoc = await getDoc(doc(db, 'users', user.uid));
    if (userDoc.exists()) {
      const userData = userDoc.data();
      console.log('📋 User Profile:', userData);
      console.log('Role:', userData.role);
      console.log('Team:', userData.team);
      console.log('Is Admin:', userData.role === 'admin');
    } else {
      console.error('❌ User document not found in Firestore');
    }
    
    // Test a simple update to an incident
    console.log('🧪 Testing incident update permissions...');
    // This will show the exact error in the console
    
  } catch (error) {
    console.error('❌ Debug error:', error);
    console.error('Error code:', error.code);
    console.error('Error message:', error.message);
  }
};

// Run the debug function
debugAdminPermissions();

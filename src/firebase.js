import { initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";
import { getFirestore } from "firebase/firestore";
import { getStorage } from "firebase/storage";

const firebaseConfig = {
  apiKey: "AIzaSyAs-daZxmVmTxqf0qBOdLH0-YGogbl0_Qk",
  authDomain: "explain-sec.firebaseapp.com",
  databaseURL: "https://explain-sec-default-rtdb.asia-southeast1.firebasedatabase.app",
  projectId: "explain-sec",
  storageBucket: "explain-sec.firebasestorage.app",
  messagingSenderId: "603242318535",
  appId: "1:603242318535:web:6a38815887fadcdc200ce2",
  measurementId: "G-BH28D6C63M"
};

// ✅ One initialization
export const app = initializeApp(firebaseConfig);

// ✅ One declaration each
export const auth = getAuth(app);
export const db = getFirestore(app);
export const storage = getStorage(app);

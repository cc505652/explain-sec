// Import the functions you need from the SDKs you need
import { initializeApp } from "firebase/app";
import { getAuth, GoogleAuthProvider } from "firebase/auth";
import { getFirestore } from "firebase/firestore";
// TODO: Add SDKs for Firebase products that you want to use
// https://firebase.google.com/docs/web/setup#available-libraries

// Your web app's Firebase configuration
// For Firebase JS SDK v7.20.0 and later, measurementId is optional
const firebaseConfig = {
  apiKey: "AIzaSyAs-daZxmVmTxqf0qBOdLH0-YGogbl0_Qk",
  authDomain: "explain-sec.firebaseapp.com",
  projectId: "explain-sec",
  storageBucket: "explain-sec.firebasestorage.app",
  messagingSenderId: "603242318535",
  appId: "1:603242318535:web:6a38815887fadcdc200ce2",
  measurementId: "G-BH28D6C63M"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app);
export const googleProvider = new GoogleAuthProvider();

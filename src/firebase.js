import { initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";
import { getFirestore } from "firebase/firestore";
import { getStorage } from "firebase/storage";

const env = (typeof import.meta !== "undefined" && import.meta.env) ? import.meta.env : (typeof process !== "undefined" ? process.env : {});

const firebaseConfig = {
  apiKey: env.VITE_FIREBASE_API_KEY || "mock_api_key",
  authDomain: env.VITE_AUTH_DOMAIN || "mock_domain",
  projectId: env.VITE_PROJECT_ID || "mock_project",
  storageBucket: env.VITE_STORAGE_BUCKET || "mock_bucket",
  messagingSenderId: env.VITE_MESSAGING_SENDER_ID || "mock_sender",
  appId: env.VITE_APP_ID || "mock_app"
};

// ✅ One initialization
export const app = initializeApp(firebaseConfig);

// ✅ One declaration each
export const auth = getAuth(app);
export const db = getFirestore(app);
export const storage = getStorage(app);

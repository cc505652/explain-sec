import { useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import { auth, db } from "../firebase/config";
import { doc, getDoc } from "firebase/firestore";

export default function AdminRoute({ children }) {
  const [allowed, setAllowed] = useState(null);

  useEffect(() => {
    const checkRole = async () => {
      if (!auth.currentUser) return setAllowed(false);

      const snap = await getDoc(doc(db, "users", auth.currentUser.uid));
      setAllowed(snap.exists() && snap.data().role === "admin");
    };

    checkRole();
  }, []);

  if (allowed === null) return <div>Checking permissions...</div>;
  return allowed ? children : <Navigate to="/student" />;
}

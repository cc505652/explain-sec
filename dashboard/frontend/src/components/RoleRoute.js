import { Navigate } from "react-router-dom";
import { auth, db } from "../firebase/config";
import { useEffect, useState } from "react";
import { doc, getDoc } from "firebase/firestore";

export default function RoleRoute({ children, allowedRole }) {
  const [allowed, setAllowed] = useState(null);

  useEffect(() => {
    const check = async () => {
      if (!auth.currentUser) return setAllowed(false);
      const snap = await getDoc(doc(db, "users", auth.currentUser.uid));
      setAllowed(snap.exists() && snap.data().role === allowedRole);
    };
    check();
  }, []);

  if (allowed === null) return null;
  return allowed ? children : <Navigate to="/" />;
}

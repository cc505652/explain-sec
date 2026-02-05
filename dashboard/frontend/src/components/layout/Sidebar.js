import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { auth, db } from "../../firebase/config";
import { doc, getDoc } from "firebase/firestore";

export default function Sidebar() {
  const [role, setRole] = useState(null);

  useEffect(() => {
    const fetchRole = async () => {
      const snap = await getDoc(doc(db, "users", auth.currentUser.uid));
      setRole(snap.data().role);
    };
    fetchRole();
  }, []);

  return (
    <div className="sidebar">
      <h2>Explain-Sec</h2>

      {role === "student" && <Link to="/student">My Security</Link>}
      {role === "analyst" && <Link to="/analyst">Threat Queue</Link>}
      {role === "admin" && <Link to="/admin">Admin Console</Link>}
    </div>
  );
}

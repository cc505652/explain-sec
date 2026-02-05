import { useEffect, useState } from "react";
import { collection, query, where, orderBy, onSnapshot } from "firebase/firestore";
import { db, auth } from "../../firebase/config";

export default function MyReports() {
  const [reports, setReports] = useState([]);

  useEffect(() => {
  if (!auth.currentUser) return;

  const q = query(
    collection(db, "security_reports"),
    where("userId", "==", auth.currentUser.uid),
    orderBy("createdAt", "desc")
  );

  const unsub = onSnapshot(
    q,
    (snapshot) => {
      console.log("Reports snapshot:", snapshot.docs.length);
      setReports(snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() })));
    },
    (error) => {
      console.error("Firestore listener error:", error);
    }
  );

  return () => unsub();
}, []);

  return (
    <div className="card">
      <h3>My Security Reports</h3>

      {reports.length === 0 && <p>No reports yet</p>}

      {reports.map(r => (
        <div key={r.id} className="report-card">
          <div className={`risk-badge ${r.risk_level.toLowerCase()}`}>
            {r.risk_level}
          </div>
          <p><b>Status:</b> {r.status}</p>
          <p><b>Signals:</b> {r.signals.join(", ")}</p>
        </div>
      ))}
    </div>
  );
}

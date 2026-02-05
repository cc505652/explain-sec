import { useEffect, useState } from "react";
import { collection, query, orderBy, limit, onSnapshot } from "firebase/firestore";
import { db, auth } from "../../firebase/config";

export default function SecurityPostureCard() {
  const [latestScan, setLatestScan] = useState(null);
  const [recentScans, setRecentScans] = useState([]);

  useEffect(() => {
    if (!auth.currentUser) return;

    const scansRef = collection(
      db,
      "users",
      auth.currentUser.uid,
      "security_scans"
    );

    const q = query(scansRef, orderBy("created_at", "desc"), limit(15));

    const unsubscribe = onSnapshot(q, (snapshot) => {
      const scans = snapshot.docs.map(doc => doc.data());
      setRecentScans(scans);
      if (scans.length > 0) setLatestScan(scans[0]);
    });

    return () => unsubscribe();
  }, []);

  // 🔐 Determine overall level from most recent scan
  const getSecurityLevel = () => {
    if (!latestScan) return "Low";
    return latestScan.risk_level || "Low";
  };

  // 🎓 Gamified protection score
  const getProtectionScore = () => {
    if (!recentScans.length) return 100;

    let penalty = 0;
    recentScans.forEach(scan => {
      if (scan.risk_level === "Critical") penalty += 30;
      else if (scan.risk_level === "High") penalty += 20;
      else if (scan.risk_level === "Medium") penalty += 10;
    });

    return Math.max(100 - penalty, 5);
  };

  // ⚠️ Find latest high-risk message
  const getRecentHighRisk = () => {
    const risky = recentScans.find(
      s => s.risk_level === "High" || s.risk_level === "Critical"
    );
    return risky ? risky.message.slice(0, 70) + "..." : null;
  };

  const level = getSecurityLevel();
  const score = getProtectionScore();
  const lastRisk = getRecentHighRisk();

  return (
    <div className="security-card">
      <div className="security-card-header">
        <h2>🛡 Security Posture</h2>
      </div>

      <div className={`security-level ${level.toLowerCase()}`}>
        {level === "Low" && "🟢 Low Risk"}
        {level === "Medium" && "🟡 Medium Risk"}
        {level === "High" && "🔴 High Risk"}
        {level === "Critical" && "🚨 Critical Risk"}
      </div>

      <div className="security-score">
        🎓 Protection Score: <b>{score} / 100</b>
      </div>

      {lastRisk ? (
        <div className="recent-risk">
          ⚠️ Recent High-Risk Event: "{lastRisk}"
        </div>
      ) : (
        <div className="recent-risk safe">
          ✅ No high-risk events in recent scans
        </div>
      )}

      <div className="trend-note">
        📊 Live risk trend based on your recent activity
      </div>
    </div>
  );
}

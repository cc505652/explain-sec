import React, { useEffect, useState } from "react";
import { collection, query, where, onSnapshot } from "firebase/firestore";
import { auth, db } from "../../firebase/config";

export default function SecurityPostureCard() {
  const [avgRisk, setAvgRisk] = useState(0);
  const [protectionScore, setProtectionScore] = useState(100);
  const [recentHigh, setRecentHigh] = useState(null);
  const [level, setLevel] = useState("Safe");

  useEffect(() => {
    if (!auth.currentUser) return;

    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

    const q = query(
      collection(db, "security_reports"),
      where("userId", "==", auth.currentUser.uid)
    );

    const unsub = onSnapshot(q, (snapshot) => {
      let reports = [];
      snapshot.forEach(doc => reports.push(doc.data()));

      if (reports.length === 0) return;

      // Last 7 days filter
      const recentReports = reports.filter(r => {
        if (!r.createdAt?.seconds) return false;
        const reportDate = new Date(r.createdAt.seconds * 1000);
        return reportDate >= sevenDaysAgo;
      });

      if (recentReports.length === 0) return;

      // Average risk
      const avg =
        recentReports.reduce((sum, r) => sum + (r.risk_score || 0), 0) /
        recentReports.length;

      setAvgRisk(Math.round(avg));

      // Protection score calculation
      let score = 100;
      recentReports.forEach(r => {
        if (r.risk_level === "Medium") score -= 5;
        if (r.risk_level === "High") score -= 10;
        if (r.risk_level === "Critical") score -= 15;
      });
      setProtectionScore(Math.max(score, 0));

      // Security level color
      if (avg <= 20) setLevel("Safe");
      else if (avg <= 50) setLevel("Caution");
      else setLevel("At Risk");

      // Most recent high-risk event
      const highEvents = recentReports
        .filter(r => r.risk_score >= 70)
        .sort((a, b) => b.createdAt.seconds - a.createdAt.seconds);

      setRecentHigh(highEvents[0] || null);
    });

    return () => unsub();
  }, []);

  const levelColor = {
    Safe: "#22c55e",
    Caution: "#facc15",
    "At Risk": "#ef4444",
  }[level];

  return (
    <div className="card">
      <h2>🛡 Security Posture</h2>

      <div style={{ display: "flex", justifyContent: "space-between" }}>
        <div>
          <h3 style={{ color: levelColor }}>{level}</h3>
          <p>Average Risk (7d): {avgRisk}</p>
        </div>

        <div>
          <h3>🎓 Protection Score</h3>
          <p style={{ fontSize: "24px", fontWeight: "bold" }}>
            {protectionScore}/100
          </p>
        </div>
      </div>

      {recentHigh && (
        <div className="alert-box">
          ⚠️ Recent High Risk Event: "{recentHigh.message_text.slice(0, 60)}..."
        </div>
      )}
    </div>
  );
}

import React, { useState } from "react";
import axios from "axios";
import { auth, db } from "../../firebase/config";
import { collection, addDoc, serverTimestamp } from "firebase/firestore";

const API_URL = "http://127.0.0.1:8000/analyze/"; // backend endpoint

export default function ThreatScanner() {
  const [text, setText] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const analyzeText = async () => {
    if (!text.trim()) return alert("Please enter text to analyze");

    setLoading(true);
    setResult(null);

    try {
      // 🔍 Call AI threat detection backend
      const response = await axios.post(API_URL, {
        message_text: text  // MUST match FastAPI model
      });

      const data = response.data;
      setResult(data);

      // 💾 Save report to Firestore
      await addDoc(collection(db, "security_reports"), {
        userId: auth.currentUser.uid,
        message_text: text,
        risk_score: data.risk_score,
        risk_level: data.risk_level,
        signals: data.top_signals,
        status: "new",
        createdAt: serverTimestamp()
      });

    } catch (err) {
      console.error("Analysis error:", err.response?.data || err.message);
      alert("Analysis failed. Check console for details.");
    }

    setLoading(false);
  };

  return (
    <div className="card">
      <h2>🔍 AI Threat Scanner</h2>

      <textarea
        placeholder="Paste suspicious email, message, or link here..."
        value={text}
        onChange={(e) => setText(e.target.value)}
        rows={5}
      />

      <button onClick={analyzeText} disabled={loading}>
        {loading ? "Analyzing..." : "Analyze Threat"}
      </button>

      {result && (
        <div className="result-box">
          <h3>Risk Level: {result.risk_level}</h3>
          <p><strong>Score:</strong> {result.risk_score}/100</p>
          <p><strong>Top Signals:</strong> {result.top_signals.join(", ")}</p>
          <p><strong>Explanation:</strong> {result.explanation}</p>
        </div>
      )}
    </div>
  );
}

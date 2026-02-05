import React, { useEffect, useState } from "react";

export default function StudentDashboard() {
  const [alert, setAlert] = useState(null);

  useEffect(() => {
    // Simulated API response from /analyze
    setAlert({
      risk_score: 78,
      risk_level: "High",
      explanation:
        "This message appears suspicious because it came from a newly created website and uses urgent language to pressure you. Attackers often use these tactics to trick people into sharing login details.",
      top_signals: [
        "Recently created sender domain",
        "Urgency language",
        "Suspicious redirect chain"
      ]
    });
  }, []);

  const handleFeedback = (action) => {
    console.log("User feedback:", action);
    alert("Thank you for your feedback!");
  };

  if (!alert) return <div className="p-4">Loading security analysis...</div>;

  return (
    <div className="p-6 max-w-2xl mx-auto font-sans">
      <h1 className="text-2xl font-bold mb-4">Security Alert</h1>

      <div
        className={`p-4 rounded-xl shadow-md mb-4 ${
          alert.risk_level === "High" || alert.risk_level === "Critical"
            ? "bg-red-100 border border-red-400"
            : "bg-yellow-100 border border-yellow-400"
        }`}
      >
        <p className="text-lg font-semibold">Risk Level: {alert.risk_level}</p>
        <p className="mt-2 text-gray-800">{alert.explanation}</p>
      </div>

      <div className="mb-4">
        <h2 className="font-semibold mb-2">Why this was flagged:</h2>
        <ul className="list-disc list-inside text-gray-700">
          {alert.top_signals.map((signal, idx) => (
            <li key={idx}>{signal}</li>
          ))}
        </ul>
      </div>

      <div className="mb-4 p-4 bg-blue-50 border border-blue-300 rounded-xl">
        <h2 className="font-semibold mb-2">What you should do</h2>
        <p>
          Do not click links or download attachments. If this message claims to
          be from your institution, verify through official channels before
          taking action.
        </p>
      </div>

      <div className="flex gap-3">
        <button
          onClick={() => handleFeedback("phishing")}
          className="bg-red-600 text-white px-4 py-2 rounded-xl hover:bg-red-700"
        >
          Report as Phishing
        </button>

        <button
          onClick={() => handleFeedback("safe")}
          className="bg-green-600 text-white px-4 py-2 rounded-xl hover:bg-green-700"
        >
          Mark as Safe
        </button>

        <button
          onClick={() => handleFeedback("unsure")}
          className="bg-gray-500 text-white px-4 py-2 rounded-xl hover:bg-gray-600"
        >
          Not Sure
        </button>
      </div>
    </div>
  );
}

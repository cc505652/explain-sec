import React, { useEffect, useState } from "react";

export default function AdminDashboard() {
  const [overview, setOverview] = useState(null);

  useEffect(() => {
    // Simulated API response from /dashboard/overview
    setOverview({
      risk_trend: [
        { date: "2026-01-29", risk_index: 52 },
        { date: "2026-01-30", risk_index: 60 },
        { date: "2026-01-31", risk_index: 58 },
        { date: "2026-02-01", risk_index: 63 },
        { date: "2026-02-02", risk_index: 71 },
        { date: "2026-02-03", risk_index: 68 },
        { date: "2026-02-04", risk_index: 75 }
      ],
      risk_distribution: {
        low: 42,
        medium: 33,
        high: 18,
        critical: 7
      },
      top_signals: [
        { signal: "domain_age_new", frequency: 32 },
        { signal: "urgent_language", frequency: 27 },
        { signal: "redirect_chain", frequency: 19 }
      ],
      campaign_patterns: [
        {
          pattern: "Exam-related urgency phishing",
          common_signal: "urgent_language",
          estimated_volume: 14
        },
        {
          pattern: "Fake IT support credential harvesting",
          common_signal: "domain_mismatch",
          estimated_volume: 9
        }
      ]
    });
  }, []);

  if (!overview) return <div className="p-4">Loading institutional security overview...</div>;

  return (
    <div className="p-6 max-w-5xl mx-auto font-sans">
      <h1 className="text-2xl font-bold mb-6">Institutional Security Posture</h1>

      {/* Risk Trend */}
      <div className="mb-6 p-4 border rounded-xl bg-gray-50">
        <h2 className="font-semibold mb-2">Weekly Risk Trend</h2>
        <ul className="grid grid-cols-2 md:grid-cols-4 gap-2 text-sm">
          {overview.risk_trend.map((day, idx) => (
            <li key={idx} className="p-2 bg-white border rounded">
              <strong>{day.date}</strong>
              <div>Risk Index: {day.risk_index}</div>
            </li>
          ))}
        </ul>
      </div>

      {/* Risk Distribution */}
      <div className="mb-6 p-4 border rounded-xl bg-gray-50">
        <h2 className="font-semibold mb-2">Alert Severity Distribution</h2>
        <ul className="text-sm space-y-1">
          <li>Low Risk: {overview.risk_distribution.low}%</li>
          <li>Medium Risk: {overview.risk_distribution.medium}%</li>
          <li>High Risk: {overview.risk_distribution.high}%</li>
          <li>Critical Risk: {overview.risk_distribution.critical}%</li>
        </ul>
      </div>

      {/* Top Signals */}
      <div className="mb-6 p-4 border rounded-xl bg-gray-50">
        <h2 className="font-semibold mb-2">Top Threat Indicators</h2>
        <ul className="list-disc list-inside text-sm">
          {overview.top_signals.map((s, idx) => (
            <li key={idx}>
              {s.signal.replace("_", " ")} — {s.frequency} occurrences
            </li>
          ))}
        </ul>
      </div>

      {/* Campaign Patterns */}
      <div className="p-4 border rounded-xl bg-red-50 border-red-300">
        <h2 className="font-semibold mb-2">Active Threat Campaign Patterns</h2>
        <ul className="space-y-2 text-sm">
          {overview.campaign_patterns.map((c, idx) => (
            <li key={idx}>
              <strong>{c.pattern}</strong><br />
              Common Signal: {c.common_signal.replace("_", " ")}<br />
              Estimated Volume: {c.estimated_volume} messages
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

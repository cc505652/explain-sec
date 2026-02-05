import React, { useState } from "react";
import API from "../api/api";

import DashboardLayout from "../components/layout/DashboardLayout";

export default function AnalystDashboard() {
  return (
    <DashboardLayout>
      <div className="card">
        <h2>Threat Analysis Queue</h2>
        <p>Review flagged events and high-risk alerts.</p>
      </div>

      <div className="card" style={{ marginTop: "20px" }}>
        <h3>Recent Alerts</h3>
        <ul>
          <li>Phishing attempt — Risk Score 92</li>
          <li>Suspicious login pattern — Risk Score 75</li>
          <li>Malware link detected — Risk Score 88</li>
        </ul>
      </div>
    </DashboardLayout>
  );
}

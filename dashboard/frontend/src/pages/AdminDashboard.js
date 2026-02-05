import DashboardLayout from "../components/layout/DashboardLayout";

export default function AdminDashboard() {
  return (
    <DashboardLayout>
      <div className="card">
        <h2>Security Operations Overview</h2>
        <p>Platform-wide threat intelligence and system health.</p>
      </div>

      <div style={{ display: "flex", gap: "20px", marginTop: "20px" }}>
        <div className="card" style={{ flex: 1 }}>
          <h3>Active Threats</h3>
          <p>12 ongoing investigations</p>
        </div>

        <div className="card" style={{ flex: 1 }}>
          <h3>Resolved Today</h3>
          <p>34 incidents mitigated</p>
        </div>

        <div className="card" style={{ flex: 1 }}>
          <h3>System Status</h3>
          <p>All detection services operational</p>
        </div>
      </div>
    </DashboardLayout>
  );
}

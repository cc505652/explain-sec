import DashboardLayout from "../components/layout/DashboardLayout";
import SecurityPostureCard from "../components/student/SecurityPostureCard";
import ThreatScanner from "../components/student/ThreatScanner";
import MyReports from "../components/student/MyReports";

export default function StudentDashboard() {
  return (
    <DashboardLayout>

      {/* HERO POSTURE CARD */}
      <div className="section-full">
        <SecurityPostureCard />
      </div>

      {/* GRID SECTION */}
      <div className="section-grid">
        <ThreatScanner />
        <div className="tips-card">
          <h3>🛡 Protection Tips</h3>
          <ul>
            <li>Never click unknown links</li>
            <li>Check sender email carefully</li>
            <li>Use 2FA on all important accounts</li>
            <li>Report suspicious content immediately</li>
          </ul>
        </div>
      </div>

      {/* REPORTS */}
      <div className="section-full">
        <MyReports />
      </div>

    </DashboardLayout>
  );
}

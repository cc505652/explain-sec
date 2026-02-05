import Sidebar from "./Sidebar";
import Topbar from "./Topbar";

export default function DashboardLayout({ children }) {
  return (
    <div className="app-bg">
      <Sidebar />
      <div style={{ flex: 1 }}>
        <Topbar />
        <div className="content-area">{children}</div>
      </div>
    </div>
  );
}

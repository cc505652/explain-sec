import { Link } from "react-router-dom";

export default function Navbar() {
  return (
    <nav style={{ padding: 15, background: "#111", color: "#fff" }}>
      <Link to="/student" style={{ marginRight: 15, color: "#fff" }}>Student</Link>
      <Link to="/analyst" style={{ marginRight: 15, color: "#fff" }}>Analyst</Link>
      <Link to="/admin" style={{ color: "#fff" }}>Admin</Link>
    </nav>
  );
}

import { Link } from "react-router-dom";

export default function Sidebar() {
  return (
    <div className="sidebar">
      <h2>Explain-Sec</h2>
      <Link to="/student">Student</Link>
      <Link to="/analyst">Analyst</Link>
      <Link to="/admin">Admin</Link>
    </div>
  );
}

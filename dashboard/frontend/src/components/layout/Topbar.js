import { signOut } from "firebase/auth";
import { auth } from "../../firebase/config";
import { useNavigate } from "react-router-dom";

export default function Topbar() {
  const navigate = useNavigate();

  const handleLogout = async () => {
    await signOut(auth);
    localStorage.removeItem("role");
    navigate("/login");
  };

  return (
    <div className="topbar">
      <button className="logout-btn" onClick={handleLogout}>Logout</button>
    </div>
  );
}

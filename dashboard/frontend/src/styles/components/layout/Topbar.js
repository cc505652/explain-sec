import { auth } from "../../firebase/config";

export default function Topbar() {
  return (
    <div className="topbar">
      <span>Security Threat Intelligence Console</span>
      <button className="primary-btn" onClick={() => auth.signOut()}>
        Logout
      </button>
    </div>
  );
}

import { Navigate } from "react-router-dom";
import { auth } from "../firebase/config";

export default function ProtectedRoute({ children }) {
  return auth.currentUser ? children : <Navigate to="/" />;
}

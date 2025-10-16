// src/App.tsx
import { Routes, Route, Navigate } from "react-router-dom";
import Home from "./pages/Home";
import Login from "./pages/Login";
import NotePage from "./pages/Note";
import NoteCreate from "./pages/NoteCreate";
import Signup from "./pages/Signup";
import UserPage from "./pages/User";

export default function App() {
  return (
    <div className="container">
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<Signup />} />
        <Route path="/note" element={<NotePage />} />
        <Route path="/note/new" element={<NoteCreate />} />
        <Route path="/user" element={<UserPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </div>
  );
}

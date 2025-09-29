// src/components/Sidebar.tsx
import React from "react";
import { Link, useLocation } from "react-router-dom";
import { getCurrentUser } from "../session";

const Sidebar: React.FC = () => {
  const user = getCurrentUser();
  const loc = useLocation();

  return (
    <aside
      className="sidebar"
      style={{
        display: "grid",
        gridTemplateRows: "auto 1fr auto", // ヘッダ / ナビ(スクロール) / フッタ
        width: 240,
        borderRight: "1px solid #e5e7eb",
        position: "sticky",
        top: 0,
        height: "100vh", // 画面高にフィット
        insetInlineStart: 0,
        background: "#fff",
      }}
    >
      {/* Header */}
      <div style={{ padding: "16px 16px 8px", fontWeight: 700, fontSize: 18 }}>
        Prism
      </div>

      {/* Nav (only this section scrolls) */}
      <nav style={{ padding: 8, display: "grid", gap: 6, overflowY: "auto" }}>
        <NavItem to="/" label="Home" active={loc.pathname === "/"} />
        <NavItem to="/user" label="Users" active={loc.pathname.startsWith("/user")} />
        <NavItem to="/login" label="Login" active={loc.pathname.startsWith("/login")} />
        <NavItem to="/signup" label="Signup" active={loc.pathname.startsWith("/signup")} />
      </nav>

      {/* Footer (常に最下部に表示) */}
      <div style={{ padding: 12, borderTop: "1px solid #eee" }}>
        <div style={{ fontSize: 12, color: "#6b7280", marginBottom: 4 }}>Current User</div>
        <div
          title={user ? user.email : "未ログイン"}
          style={{
            fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
            fontSize: 12,
            wordBreak: "break-all",
            color: user ? "#111827" : "#9ca3af",
            background: "#f9fafb",
            border: "1px solid #e5e7eb",
            borderRadius: 6,
            padding: "6px 8px",
          }}
        >
          {user ? user.email : "未ログイン"}
        </div>
      </div>
    </aside>
  );
};

const NavItem: React.FC<{ to: string; label: string; active?: boolean }> = ({ to, label, active }) => (
  <Link
    to={to}
    className="nav-item"
    style={{
      display: "block",
      padding: "8px 10px",
      borderRadius: 8,
      textDecoration: "none",
      background: active ? "#eef2ff" : "transparent",
      border: active ? "1px solid #c7d2fe" : "1px solid transparent",
      color: active ? "#3730a3" : "#111827",
    }}
  >
    {label}
  </Link>
);

export default Sidebar;

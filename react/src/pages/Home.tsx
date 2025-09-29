// src/pages/Home.tsx
import React from "react";
import { Link } from "react-router-dom";
import Sidebar from "../components/Sidebar";

const Home: React.FC = () => {
  return (
    <div
      className="layout"
      style={{
        display: "grid",
        gridTemplateColumns: "240px 1fr",
        height: "100vh", // 画面高にフィット
      }}
    >
      <Sidebar />
      <main style={{ padding: 24, overflow: "auto" }}>
        <div className="card" style={{ maxWidth: 560 }}>
          <h1 className="title">Hello World</h1>
          <p className="lead">ログインまたはサインアップを選択してください。</p>
          <div className="links" style={{ display: "flex", gap: 8 }}>
            <Link to="/login" className="btn primary">ログイン</Link>
            <Link to="/signup" className="btn">サインアップ</Link>
          </div>
        </div>
      </main>
    </div>
  );
};

export default Home;

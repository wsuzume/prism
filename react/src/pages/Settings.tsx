// src/pages/Settings.tsx
import React, { useMemo } from "react";
import Sidebar from "../components/Sidebar";
import { getCurrentUser } from "../session";

const formatDate = (value: string) =>
  new Date(value).toLocaleString(undefined, {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

const Settings: React.FC = () => {
  const user = getCurrentUser();

  const details = useMemo(() => {
    if (!user) return null;
    return [
      { label: "ID", value: user.id },
      { label: "Email", value: user.email },
      {
        label: "Created",
        value: user.created_at ? formatDate(user.created_at) : "-",
      },
      {
        label: "Updated",
        value: user.updated_at ? formatDate(user.updated_at) : "-",
      },
      {
        label: "Access Token",
        value: user.accessToken ? user.accessToken : "-",
      },
      {
        label: "Access Token Payload",
        value: user.accessTokenPayload
          ? JSON.stringify(user.accessTokenPayload, null, 2) // 見やすく整形
          : "-",
      },
    ];
  }, [user]);

  return (
    <div
      className="layout"
      style={{
        display: "grid",
        gridTemplateColumns: "240px 1fr",
        height: "100vh",
      }}
    >
      <Sidebar />
      <main style={{ padding: 24, overflow: "auto" }}>
        <h1 className="title" style={{ marginBottom: 16 }}>
          Settings
        </h1>

        <section
          className="card"
          style={{
            maxWidth: 600,
            border: "1px solid #e5e7eb",
            borderRadius: 12,
            padding: 24,
            background: "#fff",
            boxShadow: "0 10px 25px -20px rgba(15, 23, 42, 0.45)",
          }}
        >
          <header style={{ marginBottom: 16 }}>
            <h2 style={{ fontSize: 20, fontWeight: 600, margin: 0 }}>Profile</h2>
            <p style={{ margin: "6px 0 0", color: "#6b7280" }}>
              ローカルに保持している現在のユーザー情報を表示します。
            </p>
          </header>

          {user ? (
            <dl
              style={{
                display: "grid",
                gridTemplateColumns: "120px 1fr",
                rowGap: 12,
                columnGap: 16,
                margin: 0,
              }}
            >
              {details!.map(({ label, value }) => (
                <React.Fragment key={label}>
                  <dt style={{ fontWeight: 600, color: "#374151" }}>{label}</dt>
                  <dd
                    style={{
                      margin: 0,
                      fontFamily:
                        label === "ID"
                          ? "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace"
                          : "inherit",
                      wordBreak: "break-word",
                    }}
                  >
                    {value}
                  </dd>
                </React.Fragment>
              ))}
            </dl>
          ) : (
            <p style={{ margin: 0, color: "#6b7280" }}>
              現在サインインしているユーザーはありません。
            </p>
          )}
        </section>
      </main>
    </div>
  );
};

export default Settings;

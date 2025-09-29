// src/pages/User.tsx
import React, { useEffect, useMemo, useState } from "react";
import Sidebar from "../components/Sidebar";

type User = {
  id: string;
  email: string;
  created_at: string;
  updated_at: string;
};

type ListResponse = {
  users: User[];
  limit: number;
  offset: number;
};

const fmt = (s: string) =>
  new Date(s).toLocaleString(undefined, {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

const clamp = (n: number, min: number) => (n < min ? min : n);

const UserPage: React.FC = () => {
  const [users, setUsers] = useState<User[]>([]);
  const [limit, setLimit] = useState<number>(20);
  const [offset, setOffset] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(false);
  const [err, setErr] = useState<string | null>(null);

  const hasPrev = offset > 0;
  const hasNext = users.length === limit; // 次ページ有無の簡易判定

  useEffect(() => {
    const ac = new AbortController();
    const run = async () => {
      setLoading(true);
      setErr(null);
      try {
        const res = await fetch(`/api/user?limit=${limit}&offset=${offset}`, {
          signal: ac.signal,
          headers: { Accept: "application/json" },
        });
        if (!res.ok) {
          const text = await res.text().catch(() => "");
          throw new Error(`HTTP ${res.status} ${res.statusText}${text ? ` - ${text}` : ""}`);
        }
        const data: ListResponse = await res.json();
        setUsers(data.users ?? []);
      } catch (e: any) {
        if (e?.name === "AbortError") return;
        setErr(e?.message ?? "failed to fetch");
      } finally {
        setLoading(false);
      }
    };
    run();
    return () => ac.abort();
  }, [limit, offset]);

  const onReload = () => setOffset((n) => n);
  const onPrev = () => setOffset((n) => clamp(n - limit, 0));
  const onNext = () => setOffset((n) => n + limit);
  const onChangeLimit: React.ChangeEventHandler<HTMLSelectElement> = (e) => {
    const v = Number(e.target.value) || 20;
    setLimit(v);
    setOffset(0);
  };

  const rangeLabel = useMemo(() => {
    const from = offset + 1;
    const to = offset + users.length;
    return users.length > 0 ? `${from}–${to}` : "0";
  }, [offset, users]);

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
        <h1 className="title">Users</h1>

        <div
          className="toolbar"
          style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 12 }}
        >
          <button className="btn" onClick={onReload} disabled={loading} title="Reload">
            Reload
          </button>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span>Limit</span>
            <select value={limit} onChange={onChangeLimit} disabled={loading}>
              {[10, 20, 50, 100, 200].map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </div>
          <div style={{ marginLeft: "auto" }}>
            <button
              className="btn"
              onClick={onPrev}
              disabled={!hasPrev || loading}
              style={{ marginRight: 8 }}
            >
              ← Prev
            </button>
            <button className="btn" onClick={onNext} disabled={!hasNext || loading}>
              Next →
            </button>
          </div>
        </div>

        {err && (
          <div className="error" style={{ color: "crimson", marginBottom: 12 }}>
            {err}
          </div>
        )}

        {loading ? (
          <p>Loading...</p>
        ) : users.length === 0 ? (
          <p>No users.</p>
        ) : (
          <div className="table-wrap" style={{ overflowX: "auto" }}>
            <table className="table" style={{ borderCollapse: "collapse", width: "100%" }}>
              <thead>
                <tr>
                  <th style={th}>ID</th>
                  <th style={th}>Email</th>
                  <th style={th}>Created</th>
                  <th style={th}>Updated</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id}>
                    <td style={tdMono}>{u.id}</td>
                    <td style={td}>{u.email}</td>
                    <td style={td}>{fmt(u.created_at)}</td>
                    <td style={td}>{fmt(u.updated_at)}</td>
                  </tr>
                ))}
              </tbody>
              <caption style={{ captionSide: "bottom", textAlign: "left", paddingTop: 8 }}>
                Showing {rangeLabel} (limit {limit})
              </caption>
            </table>
          </div>
        )}
      </main>
    </div>
  );
};

const th: React.CSSProperties = {
  textAlign: "left",
  borderBottom: "1px solid #ddd",
  padding: "8px 10px",
  fontWeight: 600,
};

const td: React.CSSProperties = {
  borderBottom: "1px solid #f0f0f0",
  padding: "8px 10px",
  verticalAlign: "top",
};

const tdMono: React.CSSProperties = {
  ...td,
  fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
};

export default UserPage;

// src/pages/Note.tsx
import React, { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import Sidebar from "../components/Sidebar";

type Note = {
  id: string;
  user_id: string;
  canonical_name: string;
  content: string;
  created_at: string;
  deleted_at: string;
};

type ListResponse = {
  notes: Note[];
  limit: number;
  offset: number;
  include_deleted?: boolean;
  user_id?: string;
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

const fmtMaybe = (s: string) => (s ? fmt(s) : "—");

const clamp = (n: number, min: number) => (n < min ? min : n);

const NotePage: React.FC = () => {
  const [notes, setNotes] = useState<Note[]>([]);
  const [limit, setLimit] = useState<number>(20);
  const [offset, setOffset] = useState<number>(0);
  const [includeDeleted, setIncludeDeleted] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [err, setErr] = useState<string | null>(null);

  const hasPrev = offset > 0;
  const hasNext = notes.length === limit;

  useEffect(() => {
    const ac = new AbortController();
    const run = async () => {
      setLoading(true);
      setErr(null);
      try {
        let url = `/api/note?limit=${limit}&offset=${offset}`;
        if (includeDeleted) {
          url += "&include_deleted=true";
        }
        const res = await fetch(url, {
          signal: ac.signal,
          headers: { Accept: "application/json" },
        });
        if (!res.ok) {
          const text = await res.text().catch(() => "");
          throw new Error(`HTTP ${res.status} ${res.statusText}${text ? ` - ${text}` : ""}`);
        }
        const data: ListResponse = await res.json();
        setNotes(data.notes ?? []);
      } catch (e: any) {
        if (e?.name === "AbortError") return;
        setErr(e?.message ?? "failed to fetch");
      } finally {
        setLoading(false);
      }
    };
    run();
    return () => ac.abort();
  }, [limit, offset, includeDeleted]);

  const onReload = () => setOffset((n) => n);
  const onPrev = () => setOffset((n) => clamp(n - limit, 0));
  const onNext = () => setOffset((n) => n + limit);
  const onChangeLimit: React.ChangeEventHandler<HTMLSelectElement> = (e) => {
    const v = Number(e.target.value) || 20;
    setLimit(v);
    setOffset(0);
  };
  const onToggleIncludeDeleted: React.ChangeEventHandler<HTMLInputElement> = (e) => {
    setIncludeDeleted(e.target.checked);
    setOffset(0);
  };

  const rangeLabel = useMemo(() => {
    const from = offset + 1;
    const to = offset + notes.length;
    return notes.length > 0 ? `${from}–${to}` : "0";
  }, [offset, notes]);

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
        <h1 className="title">Notes</h1>

        <div
          className="toolbar"
          style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 12 }}
        >
          <button className="btn" onClick={onReload} disabled={loading} title="Reload">
            Reload
          </button>
          <Link to="/note/new" className="btn">
            ＋ New Note
          </Link>
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
          <label style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <input
              type="checkbox"
              checked={includeDeleted}
              onChange={onToggleIncludeDeleted}
              disabled={loading}
            />
            Show deleted
          </label>
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
        ) : notes.length === 0 ? (
          <p>No notes.</p>
        ) : (
          <div className="table-wrap" style={{ overflowX: "auto" }}>
            <table className="table" style={{ borderCollapse: "collapse", width: "100%" }}>
              <thead>
                <tr>
                  <th style={th}>ID</th>
                  <th style={th}>User ID</th>
                  <th style={th}>Canonical Name</th>
                  <th style={th}>Content</th>
                  <th style={th}>Created</th>
                  <th style={th}>Deleted</th>
                </tr>
              </thead>
              <tbody>
                {notes.map((n) => (
                  <tr key={n.id} style={n.deleted_at ? rowDeleted : undefined}>
                    <td style={tdMono}>{n.id}</td>
                    <td style={tdMono}>{n.user_id}</td>
                    <td style={td}>{n.canonical_name}</td>
                    <td style={td}>{n.content}</td>
                    <td style={td}>{fmt(n.created_at)}</td>
                    <td style={td}>{fmtMaybe(n.deleted_at)}</td>
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
  wordBreak: "break-word",
};

const tdMono: React.CSSProperties = {
  ...td,
  fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
};

const rowDeleted: React.CSSProperties = {
  background: "#fef2f2",
  color: "#b91c1c",
};

export default NotePage;

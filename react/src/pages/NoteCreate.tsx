import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import Sidebar from "../components/Sidebar";

type PostPayload = {
  user_id: string;
  canonical_name: string;
  content: string;
};

type PostResponse = {
  id: string;
  user_id: string;
  canonical_name: string;
  content: string;
  created_at: string;
  deleted_at?: string;
};

const NoteCreate: React.FC = () => {
  const navigate = useNavigate();
  const [form, setForm] = useState<PostPayload>({
    user_id: "",
    canonical_name: "",
    content: "",
  });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<PostResponse | null>(null);

  const onChange: React.ChangeEventHandler<HTMLInputElement | HTMLTextAreaElement> = (e) => {
    const { name, value } = e.target;
    setForm((prev) => ({ ...prev, [name]: value }));
  };

  const onSubmit: React.FormEventHandler<HTMLFormElement> = async (e) => {
    e.preventDefault();
    if (!form.user_id.trim() || !form.canonical_name.trim() || !form.content.trim()) {
      setError("user_id と canonical_name と content は必須です");
      return;
    }
    setSubmitting(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch("/api/note", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({
          user_id: form.user_id.trim(),
          canonical_name: form.canonical_name.trim(),
          content: form.content.trim(),
        }),
        credentials: "same-origin",
      });
      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new Error(text || `HTTP ${res.status}`);
      }
      const data: PostResponse = await res.json();
      setResult(data);
      setForm({ user_id: "", canonical_name: "", content: "" });
    } catch (err: any) {
      setError(err?.message ?? "failed to post note");
    } finally {
      setSubmitting(false);
    }
  };

  const onGoList = () => navigate("/note");

  return (
    <div
      className="layout"
      style={{ display: "grid", gridTemplateColumns: "240px 1fr", height: "100vh" }}
    >
      <Sidebar />
      <main style={{ padding: 24, overflowY: "auto" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
          <h1 className="title" style={{ margin: 0 }}>
            New Note
          </h1>
          <Link to="/note" className="btn" style={{ marginLeft: "auto" }}>
            ← Back to list
          </Link>
        </div>

        <form
          onSubmit={onSubmit}
          style={{
            display: "grid",
            gap: 16,
            maxWidth: 480,
            background: "#fff",
            border: "1px solid #e5e7eb",
            borderRadius: 12,
            padding: 24,
            boxShadow: "0 10px 25px -15px rgba(15, 23, 42, 0.25)",
          }}
        >
          <div style={{ display: "grid", gap: 6 }}>
            <label htmlFor="user_id" style={labelStyle}>
              User ID
            </label>
            <input
              id="user_id"
              name="user_id"
              type="text"
              value={form.user_id}
              onChange={onChange}
              autoComplete="off"
              placeholder="user uuid"
              style={inputStyle}
              disabled={submitting}
              required
            />
          </div>
          <div style={{ display: "grid", gap: 6 }}>
            <label htmlFor="canonical_name" style={labelStyle}>
              Canonical Name
            </label>
            <input
              id="canonical_name"
              name="canonical_name"
              type="text"
              value={form.canonical_name}
              onChange={onChange}
              autoComplete="off"
              placeholder="note canonical name"
              style={inputStyle}
              disabled={submitting}
              required
            />
          </div>
          <div style={{ display: "grid", gap: 6 }}>
            <label htmlFor="content" style={labelStyle}>
              Content
            </label>
            <textarea
              id="content"
              name="content"
              value={form.content}
              onChange={onChange}
              placeholder="note content"
              style={{ ...inputStyle, minHeight: 120, resize: "vertical" }}
              disabled={submitting}
              required
            />
          </div>

          {error && (
            <div style={{ color: "crimson", fontSize: 14, lineHeight: 1.4 }}>{error}</div>
          )}
          {result && (
            <div
              style={{
                border: "1px solid #bbf7d0",
                background: "#dcfce7",
                padding: "12px 16px",
                borderRadius: 8,
                fontSize: 14,
              }}
            >
              <div style={{ fontWeight: 600, marginBottom: 4 }}>Note created!</div>
              <dl style={{ display: "grid", gap: 4, margin: 0 }}>
                <InfoRow label="ID" value={result.id} />
                <InfoRow label="User ID" value={result.user_id} />
                <InfoRow label="Canonical Name" value={result.canonical_name} />
                <InfoRow label="Content" value={result.content} />
                <InfoRow label="Created At" value={result.created_at} />
              </dl>
              <button
                type="button"
                onClick={onGoList}
                className="btn"
                style={{ marginTop: 12 }}
              >
                View all notes
              </button>
            </div>
          )}

          <button type="submit" className="btn" disabled={submitting}>
            {submitting ? "Posting..." : "Create Note"}
          </button>
        </form>
      </main>
    </div>
  );
};

const labelStyle: React.CSSProperties = {
  fontSize: 14,
  fontWeight: 600,
  color: "#1f2937",
};

const inputStyle: React.CSSProperties = {
  padding: "10px 12px",
  borderRadius: 8,
  border: "1px solid #d1d5db",
  fontSize: 14,
};

const InfoRow: React.FC<{ label: string; value?: string }> = ({ label, value }) => (
  <div style={{ display: "flex", gap: 8, alignItems: "baseline" }}>
    <dt style={{ width: 110, fontWeight: 600, color: "#065f46" }}>{label}</dt>
    <dd
      style={{
        margin: 0,
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
        wordBreak: "break-all",
      }}
    >
      {value ?? ""}
    </dd>
  </div>
);

export default NoteCreate;

// src/pages/Signup.tsx
import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";

const Signup: React.FC = () => {
  const [msg, setMsg] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const navigate = useNavigate();

  const onSubmit: React.FormEventHandler<HTMLFormElement> = async (e) => {
    e.preventDefault();
    setMsg("");
    setBusy(true);

    const form = e.currentTarget;
    const email = (form.elements.namedItem("email") as HTMLInputElement).value.trim();
    const password = (form.elements.namedItem("password") as HTMLInputElement).value;
    const confirm = (form.elements.namedItem("password_confirm") as HTMLInputElement).value;

    if (!email || !password || !confirm) {
      setMsg("未入力の項目があります。");
      setBusy(false);
      return;
    }
    if (password !== confirm) {
      setMsg("パスワードが一致しません。");
      setBusy(false);
      return;
    }

    try {
      const res = await fetch("/api/user", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ email, password }),
      });

      if (!res.ok) {
        let errText = `エラーが発生しました（${res.status}）`;
        try {
          const data = await res.json();
          if (data && (data.error || data.message)) errText = data.error || data.message;
        } catch {}
        setMsg(errText);
        setBusy(false);
        return;
      }

      navigate("/login", { replace: true });
    } catch {
      setMsg("ネットワークエラーが発生しました。時間をおいて再試行してください。");
      setBusy(false);
    }
  };

  return (
    <div className="auth">
      <div className="card">
        <h1 className="title">アカウント作成</h1>
        <p className="lead">メールアドレスとパスワードを入力してください。</p>

        <form className="form form-auth" onSubmit={onSubmit} noValidate>
          <div className="field">
            <label className="label" htmlFor="email">メールアドレス</label>
            <input className="input" id="email" type="email" name="email" autoComplete="email" required />
          </div>

          <div className="field">
            <label className="label" htmlFor="password">パスワード</label>
            <input className="input" id="password" type="password" name="password" autoComplete="new-password" required minLength={8} />
          </div>

          <div className="field">
            <label className="label" htmlFor="password_confirm">パスワード（確認）</label>
            <input className="input" id="password_confirm" type="password" name="password_confirm" autoComplete="new-password" required minLength={8} />
          </div>

          <button className="btn primary" type="submit" disabled={busy}>
            {busy ? "送信中..." : "アカウント作成"}
          </button>

          <div className="msg" aria-live="polite">{msg}</div>
        </form>

        <p className="muted">
          すでにアカウントをお持ちですか？ <Link to="/login" className="link">ログイン</Link>
        </p>

        <div className="footer-links">
          <Link to="/" className="back">← ホームへ戻る</Link>
        </div>
      </div>
    </div>
  );
};

export default Signup;

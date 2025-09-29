// src/pages/Login.tsx
import React, { useRef, useState } from "react";
import { Link } from "react-router-dom";
import { setCurrentUser } from "../session";

type LoginUser = {
  id: string;
  email: string;
  created_at: string;
  updated_at: string;
};

type ApiError = {
  error: string;
};

const Login: React.FC = () => {
  const [msg, setMsg] = useState<string>("");
  const [loading, setLoading] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const onSubmit: React.FormEventHandler<HTMLFormElement> = async (e) => {
    e.preventDefault();

    // 直前のリクエストがあれば中断
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;

    const form = e.currentTarget;
    const fd = new FormData(form);
    const email = String(fd.get("email") || "");
    const password = String(fd.get("password") || "");

    if (!email || !password) {
      setMsg("メールアドレスとパスワードを入力してください。");
      return;
    }

    setLoading(true);
    setMsg("ログイン中…");

    try {
      const res = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
        signal: ac.signal,
        credentials: "same-origin",
      });

      // レスポンス全体を確認
      console.log("Response object:", res);

      // ステータスやヘッダー
      console.log("Status:", res.status, res.statusText);
      console.log("Headers:");
      res.headers.forEach((value, key) => {
        console.log(`  ${key}: ${value}`);
      });

      // 本文を clone() してから表示（clone しないとこの後 res.json() で読めなくなる）
      const resClone = res.clone();
      const text = await resClone.text();
      console.log("Body text:", text);

      if (res.ok) {
        const user: LoginUser = await res.json();
        setCurrentUser(user); // ← 追加
        setMsg(`ログインしました：${user.email}`);
        form.reset();
      } else {
        let detail = "";
        try {
          const data: ApiError = await res.json();
          detail = data?.error || "";
        } catch {
          /* ignore json parse error */
        }
        if (res.status === 401) {
          setMsg(detail || "メールアドレスまたはパスワードが違います。");
        } else if (res.status === 400) {
          setMsg(detail || "入力内容に誤りがあります。");
        } else {
          setMsg(detail || `エラーが発生しました（${res.status}）`);
        }
      }
    } catch (err) {
      // 中断は無視
      if (err instanceof DOMException && err.name === "AbortError") return;
      setMsg("ネットワークエラーが発生しました。");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth">
      <div className="card">
        <h1 className="title">ログイン</h1>
        <p className="lead">メールアドレスとパスワードを入力してください。</p>

        <form className="form form-auth" onSubmit={onSubmit} noValidate>
          <div className="field">
            <label className="label" htmlFor="email">メールアドレス</label>
            <input
              className="input"
              id="email"
              type="email"
              name="email"
              autoComplete="email"
              required
              disabled={loading}
            />
          </div>

          <div className="field">
            <label className="label" htmlFor="password">パスワード</label>
            <input
              className="input"
              id="password"
              type="password"
              name="password"
              autoComplete="current-password"
              required
              disabled={loading}
            />
          </div>

          <button className="btn primary" type="submit" disabled={loading}>
            {loading ? "送信中…" : "ログイン"}
          </button>

          <div className="msg" aria-live="polite">{msg}</div>
        </form>

        <p className="muted">
          アカウントをお持ちでない場合は <Link to="/signup" className="link">サインアップ</Link>
        </p>

        <div className="footer-links">
          <Link to="/" className="back">← ホームへ戻る</Link>
        </div>
      </div>
    </div>
  );
};

export default Login;

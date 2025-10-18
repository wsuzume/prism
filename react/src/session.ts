// src/session.ts
export type StoredCurrentUser = {
  id: string;
  email: string;
  created_at: string;
  updated_at: string;
};

type TokenPayload = Record<string, unknown>;

export type CurrentUser = StoredCurrentUser & {
  accessToken: string | null;
  accessTokenPayload: TokenPayload | null;
};

const KEY = "app.currentUser";
const ACCESS_TOKEN_COOKIE = "PRISM-ACCESS-TOKEN";

function log(...args: any[]) {
  // 必要ならここでビルドタグ/環境変数に応じて無効化可能
  console.log("[session]", ...args);
}

function readCookie(name: string): string | null {
  if (typeof document === "undefined") {
    log("readCookie: document is undefined (SSR?)");
    return null;
  }

  const cookieString = document.cookie;
  if (!cookieString) {
    log("readCookie: document.cookie is empty");
    return null;
  }

  const cookies = cookieString.split(";");
  for (const cookie of cookies) {
    const [rawName, ...rest] = cookie.split("=");
    if (!rawName) continue;
    if (rawName.trim() !== name) continue;
    const v = decodeURIComponent(rest.join("=").trim());
    log("readCookie: found", name, "len=", v?.length ?? 0);
    return v;
  }

  log("readCookie: not found", name);
  return null;
}

function base64UrlToUtf8(b64url: string): string {
  // base64url → base64（-/_ → +/、パディング補完）
  let b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4;
  if (pad === 2) b64 += "==";
  else if (pad === 3) b64 += "=";
  else if (pad !== 0) {
    log("base64UrlToUtf8: invalid length", b64url.length);
    throw new Error("invalid base64url length");
  }
  try {
    const bin = atob(b64);
    const bytes = Uint8Array.from(bin, c => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch (e) {
    log("base64UrlToUtf8: decode error", e);
    throw e;
  }
}

function parseAccessTokenPayload(token: string | undefined | null): TokenPayload | null {
  log("parseAccessTokenPayload: start, token present?", Boolean(token));
  if (!token) return null;

  const i = token.indexOf(".");
  if (i < 0) {
    log('parseAccessTokenPayload: missing "." separator');
    return null; // "XXX.YYY" でない
  }

  const yyy = token.slice(i + 1); // 後段（YYY）
  log("parseAccessTokenPayload: payload segment length", yyy.length);

  try {
    const jsonStr = base64UrlToUtf8(yyy);
    log("parseAccessTokenPayload: decoded JSON string length", jsonStr.length);
    const obj = JSON.parse(jsonStr) as TokenPayload;
    log("parseAccessTokenPayload: JSON.parse ok, keys", Object.keys(obj));
    return obj;
  } catch (e) {
    log("parseAccessTokenPayload: parse failed", e);
    return null;
  }
}

export function setCurrentUser(u: StoredCurrentUser | null) {
  if (!u) {
    log("setCurrentUser: clearing current user");
    localStorage.removeItem(KEY);
    return;
  }
  log("setCurrentUser: storing user id", u.id);
  localStorage.setItem(KEY, JSON.stringify(u));
}

export function getCurrentUser(): CurrentUser | null {
  const s = localStorage.getItem(KEY);
  if (!s) {
    log("getCurrentUser: no stored user");
    return null;
  }
  try {
    const stored = JSON.parse(s) as StoredCurrentUser;
    log("getCurrentUser: loaded stored user", { id: stored.id, email: stored.email });

    const accessToken = readCookie(ACCESS_TOKEN_COOKIE) || null;
    log("getCurrentUser: accessToken present?", Boolean(accessToken));

    const accessTokenPayload = parseAccessTokenPayload(accessToken);
    log(
      "getCurrentUser: accessTokenPayload",
      accessTokenPayload ? { keys: Object.keys(accessTokenPayload) } : null
    );

    return {
      ...stored,
      accessToken,
      accessTokenPayload,
    };
  } catch (e) {
    log("getCurrentUser: error parsing stored user", e);
    return null;
  }
}

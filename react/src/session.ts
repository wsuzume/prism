// src/session.ts
export type StoredCurrentUser = {
  id: string;
  email: string;
  created_at: string;
  updated_at: string;
};

export type CurrentUser = StoredCurrentUser & {
  accessToken: string | null;
};

const KEY = "app.currentUser";
const ACCESS_TOKEN_COOKIE = "PRISM-ACCESS-TOKEN";

function readCookie(name: string): string | null {
  if (typeof document === "undefined") return null;

  const cookieString = document.cookie;
  if (!cookieString) return null;

  const cookies = cookieString.split(";");
  for (const cookie of cookies) {
    const [rawName, ...rest] = cookie.split("=");
    if (!rawName) continue;
    if (rawName.trim() !== name) continue;
    return decodeURIComponent(rest.join("=").trim());
  }

  return null;
}

export function setCurrentUser(u: StoredCurrentUser | null) {
  if (!u) {
    localStorage.removeItem(KEY);
    return;
  }
  localStorage.setItem(KEY, JSON.stringify(u));
}

export function getCurrentUser(): CurrentUser | null {
  const s = localStorage.getItem(KEY);
  if (!s) return null;
  try {
    const stored = JSON.parse(s) as StoredCurrentUser;
    return {
      ...stored,
      accessToken: readCookie(ACCESS_TOKEN_COOKIE),
    };
  } catch {
    return null;
  }
}

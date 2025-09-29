// src/session.ts
export type CurrentUser = {
  id: string;
  email: string;
  created_at: string;
  updated_at: string;
};

const KEY = "app.currentUser";

export function setCurrentUser(u: CurrentUser | null) {
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
    return JSON.parse(s) as CurrentUser;
  } catch {
    return null;
  }
}

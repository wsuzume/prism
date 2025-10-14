package schema

import "database/sql"

const ddl = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  canonical_name TEXT NOT NULL,
  content TEXT NOT NULL,
  created_at TEXT NOT NULL,
  deleted_at TEXT,
  UNIQUE(user_id, canonical_name),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_notes_user ON notes(user_id);
CREATE INDEX IF NOT EXISTS idx_notes_created_at ON notes(created_at);
`

func CreateSchema(db *sql.DB) error {
	_, err := db.Exec(ddl)
	return err
}

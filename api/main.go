package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"

	"prism/api/route"
)

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	// --- DB init ---
	dbFile := getenv("PRISM_DB", "/var/lib/prism/data/users.db")
	// URI 形式でオプション付与
	dsn := "file:" + dbFile + "?_foreign_keys=on&_busy_timeout=5000"

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	if err := createSchema(db); err != nil {
		log.Fatalf("create schema: %v", err)
	}

	d := &route.Database{DB: db}

	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) { c.String(http.StatusOK, "pong") })
	d.RegisterUserRoutes(r)

	if err := r.Run(":8080"); err != nil {
		log.Fatalf("run server: %v", err)
	}
}

// このスキーマは route パッケージ側の定義と同一です。
func createSchema(db *sql.DB) error {
	const schema = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);`
	_, err := db.Exec(schema)
	return err
}

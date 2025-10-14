package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"

	"github.com/wsuzume/prism/api/route"
	"github.com/wsuzume/prism/api/schema"
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

	if err := schema.CreateSchema(db); err != nil {
		log.Fatalf("create schema: %v", err)
	}

	d := &route.Database{DB: db}

	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) { c.String(http.StatusOK, "pong") })
	d.RegisterUserRoutes(r)
	d.RegisterNoteRoutes(r)

	if err := r.Run(":8080"); err != nil {
		log.Fatalf("run server: %v", err)
	}
}

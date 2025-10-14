package route

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Note struct {
	ID            string `json:"id"`
	UserID        string `json:"user_id"`
	CanonicalName string `json:"canonical_name"`
	CreatedAt     string `json:"created_at"`
	DeletedAt     string `json:"deleted_at"`
}

func (d *Database) RegisterNoteRoutes(r *gin.Engine) {
	r.POST("/note", d.PostNote)
	r.GET("/note/:id", d.GetNote)
	r.GET("/note", d.ListNotes)
	r.DELETE("/note/:id", d.DeleteNote)
}

// POST /note
func (d *Database) PostNote(c *gin.Context) {
	var req struct {
		UserID        string `json:"user_id" binding:"required"`
		CanonicalName string `json:"canonical_name" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	u, err := uuid.NewV7()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate id"})
		return
	}
	id := u.String()

	ctx := c.Request.Context()
	_, err = d.DB.ExecContext(ctx,
		`INSERT INTO notes (id, user_id, canonical_name, created_at, deleted_at)
                 VALUES (?, ?, ?, ?, NULL)`,
		id, req.UserID, req.CanonicalName, now,
	)
	if isSQLiteUniqueErr(err) {
		c.JSON(http.StatusConflict, gin.H{"error": "canonical name already exists"})
		return
	}
	if isSQLiteForeignKeyErr(err) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db insert failed"})
		return
	}

	n, err := d.getNoteByID(ctx, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db fetch failed"})
		return
	}
	c.JSON(http.StatusCreated, n)
}

// GET /note/:id
func (d *Database) GetNote(c *gin.Context) {
	id := c.Param("id")
	n, err := d.getNoteByID(c.Request.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db query failed"})
		return
	}
	c.JSON(http.StatusOK, n)
}

// GET /note
func (d *Database) ListNotes(c *gin.Context) {
	limit := 50
	offset := 0
	if s := c.Query("limit"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 && v <= 200 {
			limit = v
		}
	}
	if s := c.Query("offset"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v >= 0 {
			offset = v
		}
	}

	includeDeleted := parseBool(c.Query("include_deleted"))
	userID := strings.TrimSpace(c.Query("user_id"))

	clauses := make([]string, 0, 2)
	args := make([]any, 0, 4)
	if userID != "" {
		clauses = append(clauses, "user_id = ?")
		args = append(args, userID)
	}
	if !includeDeleted {
		clauses = append(clauses, "deleted_at IS NULL")
	}

	query := `SELECT id, user_id, canonical_name, created_at, deleted_at FROM notes`
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	ctx := c.Request.Context()
	rows, err := d.DB.QueryContext(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db query failed"})
		return
	}
	defer rows.Close()

	var out []Note
	for rows.Next() {
		var n Note
		var deleted sql.NullString
		if err := rows.Scan(&n.ID, &n.UserID, &n.CanonicalName, &n.CreatedAt, &deleted); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "scan failed"})
			return
		}
		if deleted.Valid {
			n.DeletedAt = deleted.String
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "row iteration failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"notes":           out,
		"limit":           limit,
		"offset":          offset,
		"include_deleted": includeDeleted,
		"user_id":         userID,
	})
}

// DELETE /note/:id
func (d *Database) DeleteNote(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()
	now := time.Now().UTC().Format(time.RFC3339Nano)

	res, err := d.DB.ExecContext(ctx,
		`UPDATE notes SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL`,
		now, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db update failed"})
		return
	}
	aff, _ := res.RowsAffected()
	if aff == 0 {
		// 既に削除済みか、レコードが存在しない
		n, err := d.getNoteByID(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db fetch failed"})
			return
		}
		c.JSON(http.StatusOK, n)
		return
	}

	n, err := d.getNoteByID(ctx, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db fetch failed"})
		return
	}
	c.JSON(http.StatusOK, n)
}

func (d *Database) getNoteByID(ctx context.Context, id string) (Note, error) {
	var n Note
	var deleted sql.NullString
	err := d.DB.QueryRowContext(ctx,
		`SELECT id, user_id, canonical_name, created_at, deleted_at FROM notes WHERE id = ?`,
		id,
	).Scan(&n.ID, &n.UserID, &n.CanonicalName, &n.CreatedAt, &deleted)
	if deleted.Valid {
		n.DeletedAt = deleted.String
	}
	return n, err
}

func parseBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func isSQLiteForeignKeyErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "FOREIGN KEY constraint failed")
}

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
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

func (d *Database) RegisterUserRoutes(r *gin.Engine) {
	r.POST("/user", d.PostUser)
	r.GET("/user/:id", d.GetUser)
	r.PUT("/user/:id", d.PutUser)
	r.DELETE("/user/:id", d.DeleteUser)
	r.GET("/user", d.ListUsers)
	r.POST("/login", d.LoginUser)
}

// POST /user
func (d *Database) PostUser(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=8"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	pwHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
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
		`INSERT INTO users (id, email, password_hash, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)`,
		id, req.Email, string(pwHash), now, now,
	)
	if isSQLiteUniqueErr(err) {
		c.JSON(http.StatusConflict, gin.H{"error": "email already exists"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db insert failed"})
		return
	}

	c.JSON(http.StatusCreated, User{
		ID:        id,
		Email:     req.Email,
		CreatedAt: now,
		UpdatedAt: now,
	})
}

// GET /user/:id
func (d *Database) GetUser(c *gin.Context) {
	id := c.Param("id")
	u, err := d.getUserByID(c.Request.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db query failed"})
		return
	}
	c.JSON(http.StatusOK, u)
}

// PUT /user/:id
func (d *Database) PutUser(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Email    *string `json:"email" binding:"omitempty,email"`
		Password *string `json:"password" binding:"omitempty,min=8"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	fields := make([]string, 0, 3)
	args := make([]any, 0, 3)

	if req.Email != nil {
		fields = append(fields, "email = ?")
		args = append(args, *req.Email)
	}
	if req.Password != nil {
		hash, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
			return
		}
		fields = append(fields, "password_hash = ?")
		args = append(args, string(hash))
	}
	if len(fields) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no fields to update"})
		return
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	fields = append(fields, "updated_at = ?")
	args = append(args, now, id)

	ctx := c.Request.Context()
	res, err := d.DB.ExecContext(ctx, "UPDATE users SET "+strings.Join(fields, ", ")+" WHERE id = ?", args...)
	if isSQLiteUniqueErr(err) {
		c.JSON(http.StatusConflict, gin.H{"error": "email already exists"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db update failed"})
		return
	}
	aff, _ := res.RowsAffected()
	if aff == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}

	u, err := d.getUserByID(ctx, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db fetch failed"})
		return
	}
	c.JSON(http.StatusOK, u)
}

// DELETE /user/:id
func (d *Database) DeleteUser(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()
	res, err := d.DB.ExecContext(ctx, "DELETE FROM users WHERE id = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db delete failed"})
		return
	}
	aff, _ := res.RowsAffected()
	if aff == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.Status(http.StatusNoContent)
}

// GET /user
func (d *Database) ListUsers(c *gin.Context) {
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

	ctx := c.Request.Context()
	rows, err := d.DB.QueryContext(ctx,
		`SELECT id, email, created_at, updated_at
		   FROM users
		  ORDER BY created_at DESC
		  LIMIT ? OFFSET ?`, limit, offset,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db query failed"})
		return
	}
	defer rows.Close()

	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Email, &u.CreatedAt, &u.UpdatedAt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "scan failed"})
			return
		}
		out = append(out, u)
	}
	c.JSON(http.StatusOK, gin.H{
		"users":  out,
		"limit":  limit,
		"offset": offset,
	})
}

// POST /login
func (d *Database) LoginUser(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()

	var u User
	var pwHash string
	err := d.DB.QueryRowContext(
		ctx,
		`SELECT id, email, password_hash, created_at, updated_at FROM users WHERE email = ?`,
		req.Email,
	).Scan(&u.ID, &u.Email, &pwHash, &u.CreatedAt, &u.UpdatedAt)

	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db query failed"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(pwHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})
		return
	}
	
	c.Header("PRISM-SECRET", "secret-token")
	c.Header("PRISM-ACCESS", "access-token")
	c.Header("PRISM-PUBLIC", "public-token")

	c.JSON(http.StatusOK, u)
}

// --- helpers ---

func createSchema(db *sql.DB) error {
	// TEXT (RFC3339) で時刻保存。email は UNIQUE。
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

func (d *Database) getUserByID(ctx context.Context, id string) (User, error) {
	var u User
	err := d.DB.QueryRowContext(
		ctx,
		`SELECT id, email, created_at, updated_at FROM users WHERE id = ?`,
		id,
	).Scan(&u.ID, &u.Email, &u.CreatedAt, &u.UpdatedAt)
	return u, err
}

func isSQLiteUniqueErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}

package main

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	r.Any("/*path", func(c *gin.Context) {
		body, _ := io.ReadAll(c.Request.Body)

		headers := make(map[string][]string)
		for k, v := range c.Request.Header {
			headers[k] = v
		}

		query := make(map[string][]string)
		for k, v := range c.Request.URL.Query() {
			query[k] = v
		}

		out, _ := json.MarshalIndent(gin.H{
			"method":  c.Request.Method,
			"path":    c.Param("path"),
			"query":   query,
			"headers": headers,
			"body":    string(body),
		}, "", "  ")
		c.Data(http.StatusOK, "application/json; charset=utf-8", out)
	})

	r.Run(":8080")
}

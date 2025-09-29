// 例: prism-client/main.go
package main

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	// Vite build の出力を配信
	r.Static("/assets", "./dist/assets")
	r.StaticFile("/favicon.ico", "./dist/favicon.ico") // あれば

	// ルート
	r.GET("/", func(c *gin.Context) {
		c.File("./dist/index.html")
	})

	// ★ SPA fallback: /api と /assets 以外は常に index.html を返す
	r.NoRoute(func(c *gin.Context) {
		p := c.Request.URL.Path
		if strings.HasPrefix(p, "/api") || strings.HasPrefix(p, "/assets") {
			c.Status(http.StatusNotFound)
			return
		}
		c.File("./dist/index.html")
	})

	_ = r.Run(":8080")
}

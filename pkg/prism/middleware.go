package prism

import (
	"log"

	"github.com/gin-gonic/gin"

	"github.com/wsuzume/prism/pkg/domain"
)

func headerLogMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		req := c.Request

		log.Printf(
			"[REQ] method=%s uri=%s host=%s remote=%s",
			req.Method,
			req.RequestURI,
			req.Host,
			req.RemoteAddr,
		)

		for k, v := range req.Header {
			log.Printf("[HDR] %s: %v", k, v)
		}

		c.Next()
	}
}

// tenantMiddleware はリクエストの Host ヘッダから tenant を抽出して
// gin コンテキストの "tenant" キーに格納するミドルウェア。
// baseDomain が空の場合はすべてのリクエストを tenant="" (main) として扱う。
func tenantMiddleware(baseDomain string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if baseDomain == "" {
			c.Set("tenant", "")
			c.Next()
			return
		}
		parts := domain.ParseDomain(c.Request.Host, baseDomain, "")
		c.Set("tenant", parts.Tenant)
		c.Next()
	}
}

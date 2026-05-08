package prism

import (
	"log"
	"net/url"

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

func originLogMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if origin := c.Request.Header.Get("Origin"); origin != "" {
			log.Printf("[ORI] source=origin origin=%s", origin)
		} else if referer := c.Request.Header.Get("Referer"); referer != "" {
			u, err := url.Parse(referer)
			if err == nil {
				log.Printf("[ORI] source=referer origin=%s://%s", u.Scheme, u.Host)
			}
		} else {
			log.Printf("[ORI] source=none origin=")
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

package prism

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

func echoHandler(c *gin.Context) {
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
}

func RunEchoServer(cfg *PrismConfig) {
	port := "8080"
	if !cfg.IsProxyConfigEmpty() && cfg.ProxyConfig.Port != "" {
		port = cfg.ProxyConfig.Port
	}

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(headerLogMiddleware())
	r.Use(originLogMiddleware())

	r.Any("/*path", echoHandler)

	log.Printf("starting echo server on :%s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatal(err)
	}
}

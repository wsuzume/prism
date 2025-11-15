package prism

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/wsuzume/prism/pkg/mode"
)

// redirect handles redirecting all HTTP traffic to HTTPS using 301 permanent redirect.
// w   - HTTP response writer
// req - Incoming user request
func redirect(w http.ResponseWriter, req *http.Request) {
	// Defensive: If req.Host is empty, fallback to req.URL.Host
	// This ensures the redirect URL always has a valid host.
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	// Note: Host may be an IPv6 literal (e.g., [::1]:8080); that's acceptable in URLs.
	target := "https://" + host + req.RequestURI               // Build the HTTPS target URL
	http.Redirect(w, req, target, http.StatusMovedPermanently) // 301 permanent redirect
}

func normalizeRoute(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "/") // 両端の "/" を除去
	if s == "" {
		return "/" // 空や "/" 相当はルート
	}
	return "/" + s // 先頭のみ "/" を付与
}

func newReverseProxyRouter(cfg *PrismConfig) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery(), gin.Logger())

	for name, backend := range cfg.Backends {
		// ループ変数のアドレス捕捉を避ける
		n := name
		b := backend

		target, err := url.Parse(b.TargetURL)
		if err != nil {
			log.Fatalf("parse %s url (%s): %v", n, b.TargetURL, err)
		}

		proxy := httputil.NewSingleHostReverseProxy(target)

		// 追加: エラーハンドラ（バックエンドが落ちている等）
		proxy.ErrorHandler = func(w http.ResponseWriter, req *http.Request, e error) {
			// 値は出さない（情報漏えい防止）／URI とリモートは記録
			log.Printf("proxy error: backend=%s target=%s remote=%s uri=%s err=%v",
				n, target.String(), req.RemoteAddr, req.URL.RequestURI(), e)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		}

		if n == "default" {
			// デフォルトバックエンド：どのルートにも一致しなかった場合
			r.NoRoute(func(c *gin.Context) {
				proxy.ServeHTTP(c.Writer, c.Request)
			})
			continue
		}

		// 個別バックエンド
		route := normalizeRoute(b.Route)

		handler := func(c *gin.Context) {
			if b.RemovePrefix {
				// Gin の /*proxyPath から残りを取り出す（先頭に "/" が付く）
				trimmed := c.Param("proxyPath")
				if trimmed == "" {
					trimmed = "/"
				}
				// リクエストを書き換えてバックエンドへ
				c.Request.URL.Path = trimmed
				c.Request.URL.RawPath = trimmed
			}
			proxy.ServeHTTP(c.Writer, c.Request)
		}

		// 例: "/api" にもマッチ
		r.Any(route, handler)
		// 例: "/api/foo" にマッチ
		r.Any(route+"/*proxyPath", handler)
	}

	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "Hello, World!")
	})

	return r
}

func Run() {
	if !mode.Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	path, err := GetTopPriorityConfigPath()
	if err != nil {
		log.Fatalf("failed to find config file: %v\n", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		log.Fatalf("failed to load config: %v\n", err)
	}

	cfg, err = cfg.Normalize()
	if err != nil {
		log.Fatalf("failed to normalize config: %v\n", err)
	}

	fmt.Printf("Config loaded from %s\n", path)
	fmt.Println("======")
	fmt.Print(cfg.String())
	fmt.Println("======")

	n := NewNotifier()

	// SIGINT / SIGTERM を受け取るチャネル
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	if cfg.AutoTLS {
		s80 := NewReloadableServer(":http", http.HandlerFunc(redirect), nil)
		s80.Start(nil, n)
	}

	r := newReverseProxyRouter(cfg)
	s := NewReloadableServer(":8080", r, nil)
	s.Start(nil, n)

	cmdRouter := gin.New()
	cmdRouter.Use(gin.Recovery(), gin.Logger())
	cmdRouter.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "Hello, World!")
	})
	cmdRouter.GET("/reload", func(c *gin.Context) {
		log.Println("Reloading the proxy server")

		new, err := LoadConfig(path)
		if err != nil {
			log.Fatalf("failed to load config: %v\n", err)
		}

		new, err = cfg.Normalize()
		if err != nil {
			log.Fatalf("failed to normalize config: %v\n", err)
		}

		cfg.Backends = new.Backends

		r := newReverseProxyRouter(cfg)

		s.Reload(r, n)
		c.String(http.StatusOK, "Reload")
	})

	cs := NewCommandServer(&cfg.CommandServerConfig, cmdRouter)

	go func() {
		if err := cs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("command server error: %v\n", err)
		}
	}()

	// Ctrl+C を待機
	select {
	case <-sigCh:
		log.Println("Received interrupt signal, shutting down...")

		// 両方のサーバーを優雅に停止
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Shutdown(ctx); err != nil {
			log.Printf("Error shutting down proxy server: %v", err)
		}
		if err := cs.Shutdown(ctx); err != nil {
			log.Printf("Error shutting down control server: %v", err)
		}

		log.Println("All servers stopped gracefully.")
	}
}

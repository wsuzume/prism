package server

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/autotls"
	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/acme/autocert"

	"prism/pkg/cipher"
	"prism/pkg/csrf"
	"prism/pkg/iprange"
	"prism/pkg/mode"
	"prism/pkg/session"
	"prism/proxy/internal/core"
)

// ──────────────────────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────────────────────-

func normalizeRoute(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "/") // 両端の "/" を除去
	if s == "" {
		return "/" // 空や "/" 相当はルート
	}
	return "/" + s // 先頭のみ "/" を付与
}

// 例: log.Printf("ts=%s message...", nowTS())
func nowTS() string {
	return time.Now().Format(time.RFC3339)
}

// ──────────────────────────────────────────────────────────────────────────────
//  Main
// ─────────────────────────────────────────────────────────────────────────────-

func RunReverseProxy(cmd *cobra.Command, args []string) {
	if mode.Debug {
		log.Println("[PRISM DEBUG MODE]")
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// 設定読込
	cfg, err := core.LoadConfig()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	if mode.Debug { log.Println(cfg.String()) }

	// 秘密鍵のロード（パスをログに含める）
	const secretDir = "/var/lib/prism/secrets"
	const hmacFile = "session-hmac-secret"
	hmacSecret, err := core.LoadOrCreateSecret(secretDir, hmacFile, 32)
	if err != nil {
		log.Fatalf("failed to load HMAC secret: dir=%s file=%s: %v", secretDir, hmacFile, err)
	}

	signer := cipher.NewSignerHS256(hmacSecret)
	sm := session.DefaultSessionManager(signer)

	const aeadFile = "double-submit-aead-secret"
	aeadSecret, err := core.LoadOrCreateAEADKey(secretDir, aeadFile, 32)
	if err != nil {
		log.Fatalf("failed to load AEAD secret: dir=%s file=%s: %v", secretDir, aeadFile, err)
	}
	encrypter, err := cipher.NewEncrypterAESGCM(aeadSecret)
	if err != nil {
		log.Fatalf("failed to create AES-GCM encrypter: %v", err)
	}

	// CSRF（Origin/Referer）基本保護
	// bp, err := csrf.NewBasicCSRFProtector(cfg.AllowedOrigins)
	// if err != nil {
	// 	log.Fatalf("failed to initialize BasicCSRFProtector: allowed_origins=%v: %v", cfg.AllowedOrigins, err)
	// }

	// Double-Submit Cookie（暗号化付き）
	dscp := csrf.DefaultDoubleSubmitCookieCSRFProtector(encrypter)
	dscp.IdentityCenterAddressPool, err = iprange.ParseRanges(cfg.IdentityCenterAddresses)
	if err != nil {
		log.Fatalf("failed to parse identity_center_addresses: %v", err)
	}

	// ── Gin router ────────────────────────────────────────────────────────────
	r := gin.New()

	// ログ／リカバリは最初に
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	// CSRF, セッション, Double-Submit の順に適用
	// r.Use(bp.Middleware())
	r.Use(sm.RequireSessionToken())
	r.Use(dscp.Middleware())

	// ── Backends の登録 ───────────────────────────────────────────────────────
	for name, backend := range cfg.Backends {
		// ループ変数のアドレス捕捉を避ける
		b := backend
		n := name

		target, err := url.Parse(b.TargetURL)
		if err != nil {
			log.Fatalf("parse %s url (%s): %v", n, b.TargetURL, err)
		}

		proxy := httputil.NewSingleHostReverseProxy(target)

		// ModifyResponse をラップ
		origModify := proxy.ModifyResponse
		proxy.ModifyResponse = dscp.ModifyResponse(origModify)

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

	// ── 起動モード ────────────────────────────────────────────────────────────
	switch cfg.Mode {
	case "DEVELOP":
		// 開発時は :80 で HTTP サーブ（プロキシ前段に TLS がある構成を想定）
		addr := ":80"
		log.Printf("listening on %s (DEVELOP)", addr)
		if err := r.Run(addr); err != nil {
			log.Fatal(err)
		}

	case "PRODUCT":
		// 本番は Let's Encrypt（autocert）で :80 と :443 を同時リッスン
		if len(cfg.TLS.Domains) == 0 {
			log.Fatal("PRODUCT mode requires tls.domains in config")
		}
		cacheDir := cfg.TLS.CacheDir
		if cacheDir == "" {
			cacheDir = "./certs"
		}

		m := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.TLS.Domains...),
			Cache:      autocert.DirCache(cacheDir),
		}

		log.Printf("listening on :80 and :443 (PRODUCT), domains=%v cache_dir=%s", cfg.TLS.Domains, cacheDir)

		// autotls は内部で :80（HTTP-01 用）と :443 を開く
		// （SIGTERM 等での終了ログが遅延しないよう、短いタイムアウト付きのラッパーなどは必要に応じて）
		if err := autotls.RunWithManager(r, &m); err != nil {
			log.Fatal(err)
		}

	default:
		log.Fatalf("unknown mode: %q", cfg.Mode)
	}
}

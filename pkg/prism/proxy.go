package prism

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/gin-gonic/gin"

	"github.com/wsuzume/prism/pkg/cipher"
	"github.com/wsuzume/prism/pkg/domain"
	"github.com/wsuzume/prism/pkg/session"
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

// upstreamの組み立て（Host単位で ReverseProxy を保持）
func buildProxy(targetStr string) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(targetStr)
	if err != nil {
		return nil, err
	}

	rp := httputil.NewSingleHostReverseProxy(target)

	orig := rp.Director
	rp.Director = func(req *http.Request) {
		// 元のクライアントホストを保存してから Director を呼ぶ
		originalHost := req.Host

		orig(req)

		// upstream 側が期待する Host に合わせる（重要）
		req.Host = target.Host

		// 典型的な forward ヘッダ
		// （Directorが一部入れることもありますが、明示しておくと挙動が読みやすいです）
		if req.Header.Get("X-Forwarded-Host") == "" {
			req.Header.Set("X-Forwarded-Host", originalHost)
		}
		if req.Header.Get("X-Forwarded-Proto") == "" {
			if req.TLS != nil {
				req.Header.Set("X-Forwarded-Proto", "https")
			} else {
				req.Header.Set("X-Forwarded-Proto", "http")
			}
		}
		// X-Forwarded-For は ReverseProxy が追記する実装ですが、
		// 要件が厳しいならここで制御してもOKです。
	}

	// エラー時ログ（必要ならレスポンスもカスタム）
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, e error) {
		log.Printf("[PROXY_ERR] host=%s uri=%s err=%v", r.Host, r.RequestURI, e)
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}

	return rp, nil
}

func Run() {
	path, err := GetTopPriorityConfigPath()
	if err != nil {
		log.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		log.Fatal(err)
	}

	// 例: example.com を基準に api.example.com / app.example.com を振り分ける
	baseDomain := "wsuzu.me"
	if cfg.ProxyConfig.BaseDomain != "" {
		baseDomain = cfg.ProxyConfig.BaseDomain
	}

	// subdomain -> upstream
	// "" はルート（example.com）扱い
	backends := cfg.NormalizedBackends()
	if backends == nil {
		backends = map[string]string{
			"":         "http://172.28.0.100:3000", // example.com
			"cardinal": "http://172.28.0.20:8080",  // cardinal.example.com
			"api":      "http://172.28.0.30:8080",  // api.example.com
		}
	}

	sm := session.NewSessionManager("PRISM", "FLITLEAP")
	// TODO: 鍵ファイルから読み込むようにする
	dummyKey := []byte("0123456789abcdef0123456789abcdef") // 32 bytes = AES-256
	e, err := cipher.NewEncrypterAESGCM(dummyKey)
	if err != nil {
		log.Fatal(err)
	}
	p := session.DefaultCookieSession(sm, e, cfg.CookieConfig.Domain, cfg.CookieConfig.Secure)

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(headerLogMiddleware())
	r.Use(p.Middleware())

	// subdomain -> handler (ReverseProxy.ServeHTTP)
	handlers := map[string]func(http.ResponseWriter, *http.Request){}

	for sub, target := range backends {
		rp, err := buildProxy(target)
		if err != nil {
			log.Fatalf("invalid backend: sub=%q target=%q err=%v", sub, target, err)
		}

		// ループ内クロージャの挙動対策
		// あとでリファクタリングする
		localRP := rp
		localP := p

		mr := localRP.ModifyResponse
		localRP.ModifyResponse = localP.ModifyResponse(mr)

		handlers[sub] = rp.ServeHTTP
	}

	r.NoRoute(func(c *gin.Context) {
		rawHost := c.Request.Host
		host := domain.NormalizeHost(rawHost)
		sub := domain.ExtractSubdomain(host, baseDomain)

		log.Printf("[ROUTE] rawHost=%q host=%q sub=%q", rawHost, host, sub)

		h, ok := handlers[sub]
		if !ok {
			// 想定外サブドメインは 404 or 502 など方針で
			log.Printf("[DBG]undefined subdomain")
			c.AbortWithStatus(http.StatusNotFound)
			return
		}

		h(c.Writer, c.Request)
	})

	log.Println("starting proxy server on :8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}

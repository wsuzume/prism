package prism

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/gin-gonic/gin"

	"github.com/wsuzume/prism/pkg/cipher"
	"github.com/wsuzume/prism/pkg/session"
)

// buildProxy は target URL に転送する ReverseProxy を組み立てる。
func buildProxy(targetStr string) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(targetStr)
	if err != nil {
		return nil, err
	}

	rp := httputil.NewSingleHostReverseProxy(target)

	orig := rp.Director
	rp.Director = func(req *http.Request) {
		originalHost := req.Host

		orig(req)

		req.Host = target.Host

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
	}

	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, e error) {
		log.Printf("[PROXY_ERR] host=%s uri=%s err=%v", r.Host, r.RequestURI, e)
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}

	return rp, nil
}

// buildReverseProxyMap は route → BackendConfig のマップから、
// route → ReverseProxy のマップを返す。
// route キーは正規化済みで "" がデフォルトルート。
// 現状は Targets の先頭要素のみ使用する（将来: ラウンドロビン）。
func buildReverseProxyMap(routes map[string]*BackendConfig) (map[string]*httputil.ReverseProxy, error) {
	proxies := map[string]*httputil.ReverseProxy{}
	for route, cfg := range routes {
		if len(cfg.Targets) == 0 {
			continue
		}
		rp, err := buildProxy(cfg.Targets[0])
		if err != nil {
			return nil, fmt.Errorf("route %q: %w", route, err)
		}
		proxies[route] = rp
	}
	return proxies, nil
}

// buildTenantEngine は route → ReverseProxy のマップから、
// パスプレフィックスでルーティングする gin.Engine を構築して返す。
func buildTenantEngine(proxies map[string]*httputil.ReverseProxy) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())

	var defaultProxy *httputil.ReverseProxy

	for route, rp := range proxies {
		if route == "" {
			defaultProxy = rp
			continue
		}
		localRP := rp
		r.Any("/"+route+"/*path", func(c *gin.Context) {
			localRP.ServeHTTP(c.Writer, c.Request)
		})
	}

	if defaultProxy != nil {
		localRP := defaultProxy
		r.NoRoute(func(c *gin.Context) {
			localRP.ServeHTTP(c.Writer, c.Request)
		})
	}

	return r
}

func RunReverseProxyServer(cfg *PrismConfig) {
	baseDomain := ""
	if !cfg.IsBaseDomainEmpty() {
		baseDomain = cfg.ProxyConfig.BaseDomain
	}

	// テナントごとの ReverseProxy マップを構築
	tenantProxies := map[string]map[string]*httputil.ReverseProxy{}
	for tenant, routes := range cfg.Backends {
		proxies, err := buildReverseProxyMap(routes)
		if err != nil {
			log.Fatalf("tenant %q: %v", tenant, err)
		}
		tenantProxies[tenant] = proxies
	}

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(headerLogMiddleware())

	if cfg.CookieConfig.IsValid() {
		log.Printf("cookie config: domain=%q secure=%v", cfg.CookieConfig.Domain, cfg.CookieConfig.Secure)

		sm := session.NewSessionManager("PRISM", "FLITLEAP")
		if cfg.CookieConfig.CryptoKeyPath == "" {
			log.Fatal("cookie_config.crypto_key_path is required when cookie_config is set")
		}
		cryptoKey, err := os.ReadFile(cfg.CookieConfig.CryptoKeyPath)
		if err != nil {
			log.Fatalf("failed to read crypto key: %v", err)
		}
		e, err := cipher.NewEncrypterAESGCM(cryptoKey)
		if err != nil {
			log.Fatal(err)
		}
		p := session.DefaultCookieSession(sm, e, cfg.CookieConfig.Domain, cfg.CookieConfig.Secure)

		r.Use(p.Middleware())

		for _, proxies := range tenantProxies {
			for _, rp := range proxies {
				rp.ModifyResponse = p.ModifyResponse(rp.ModifyResponse)
			}
		}
	}

	// テナントごとの Engine を構築
	tenantEngines := map[string]*gin.Engine{}
	for tenant, proxies := range tenantProxies {
		tenantEngines[tenant] = buildTenantEngine(proxies)
	}

	r.Use(tenantMiddleware(baseDomain))

	r.NoRoute(func(c *gin.Context) {
		tenant, _ := c.Get("tenant")
		tenantStr, _ := tenant.(string)

		engine, ok := tenantEngines[tenantStr]
		if !ok {
			// main テナント（""）へフォールバック
			engine, ok = tenantEngines[""]
			if !ok {
				log.Printf("[ROUTE] tenant=%q: no backend defined", tenantStr)
				c.AbortWithStatus(http.StatusNotFound)
				return
			}
		}

		engine.HandleContext(c)
	})

	port := "8080"
	if !cfg.IsProxyConfigEmpty() && cfg.ProxyConfig.Port != "" {
		port = cfg.ProxyConfig.Port
	}

	log.Printf("starting reverse proxy server on :%s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatal(err)
	}
}

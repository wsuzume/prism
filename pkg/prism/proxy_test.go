package prism

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// ---- buildProxy ----

// buildProxy: 不正な URL を渡したときにエラーが返ることを確認する。
func TestBuildProxy_InvalidURL(t *testing.T) {
	_, err := buildProxy("://invalid")
	if err == nil {
		t.Fatal("expected error for invalid URL, got nil")
	}
}

// buildProxy: Director が元の Host を X-Forwarded-Host に保存することを確認する。
func TestBuildProxy_Director_SetsXForwardedHost(t *testing.T) {
	rp, err := buildProxy("http://backend.example.com")
	if err != nil {
		t.Fatalf("buildProxy: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://frontend.example.com/path", nil)
	req.Host = "frontend.example.com"

	rp.Director(req)

	if got := req.Header.Get("X-Forwarded-Host"); got != "frontend.example.com" {
		t.Errorf("X-Forwarded-Host = %q, want %q", got, "frontend.example.com")
	}
}

// buildProxy: TLS なし (req.TLS == nil) のとき X-Forwarded-Proto が "http" になることを確認する。
func TestBuildProxy_Director_SetsXForwardedProto_HTTP(t *testing.T) {
	rp, err := buildProxy("http://backend.example.com")
	if err != nil {
		t.Fatalf("buildProxy: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://frontend.example.com/path", nil)
	// req.TLS == nil → "http"

	rp.Director(req)

	if got := req.Header.Get("X-Forwarded-Proto"); got != "http" {
		t.Errorf("X-Forwarded-Proto = %q, want %q", got, "http")
	}
}

// buildProxy: TLS あり (req.TLS != nil) のとき X-Forwarded-Proto が "https" になることを確認する。
func TestBuildProxy_Director_SetsXForwardedProto_HTTPS(t *testing.T) {
	rp, err := buildProxy("http://backend.example.com")
	if err != nil {
		t.Fatalf("buildProxy: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://frontend.example.com/path", nil)
	req.TLS = &tls.ConnectionState{} // non-nil → "https"

	rp.Director(req)

	if got := req.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Errorf("X-Forwarded-Proto = %q, want %q", got, "https")
	}
}

// buildProxy: 既存の X-Forwarded-Host / X-Forwarded-Proto が上書きされないことを確認する。
func TestBuildProxy_Director_PreservesExistingHeaders(t *testing.T) {
	rp, err := buildProxy("http://backend.example.com")
	if err != nil {
		t.Fatalf("buildProxy: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://frontend.example.com/path", nil)
	req.Header.Set("X-Forwarded-Host", "already-set.example.com")
	req.Header.Set("X-Forwarded-Proto", "https")

	rp.Director(req)

	if got := req.Header.Get("X-Forwarded-Host"); got != "already-set.example.com" {
		t.Errorf("X-Forwarded-Host = %q, want %q", got, "already-set.example.com")
	}
	if got := req.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Errorf("X-Forwarded-Proto = %q, want %q", got, "https")
	}
}

// buildProxy: Director がリクエストの Host ヘッダをバックエンドのホストに書き換えることを確認する。
func TestBuildProxy_Director_RewritesHostToTarget(t *testing.T) {
	rp, err := buildProxy("http://backend.example.com")
	if err != nil {
		t.Fatalf("buildProxy: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://frontend.example.com/path", nil)
	req.Host = "frontend.example.com"

	rp.Director(req)

	if req.Host != "backend.example.com" {
		t.Errorf("req.Host = %q, want %q", req.Host, "backend.example.com")
	}
}

// buildProxy: バックエンドへの接続に失敗したとき ErrorHandler が 502 を返すことを確認する。
func TestBuildProxy_ErrorHandler_ReturnsBadGateway(t *testing.T) {
	rp, err := buildProxy("http://backend.example.com")
	if err != nil {
		t.Fatalf("buildProxy: %v", err)
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/path", nil)
	rp.ErrorHandler(w, req, errors.New("connection refused"))

	if w.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadGateway)
	}
}

// ---- buildTenantEngine ----

// httptest.ResponseRecorder は http.CloseNotifier を実装していないため、
// gin + ReverseProxy の組み合わせでは engine.ServeHTTP(recorder, req) がパニックする。
// そのため buildTenantEngine のルーティングテストは httptest.NewServer(engine) で
// 実際の HTTP サーバを起動し、http.Get で叩く方式を使う。

// buildTenantEngine: 不正な Target URL を渡したときにエラーが返ることを確認する。
func TestBuildTenantEngine_InvalidTarget(t *testing.T) {
	routes := map[string]*BackendConfig{
		"api": {Targets: []string{"://invalid"}},
	}
	_, err := buildTenantEngine(routes)
	if err == nil {
		t.Fatal("expected error for invalid target URL, got nil")
	}
}

func TestBuildTenantEngine_EmptyTargetsSkipped(t *testing.T) {
	// buildTenantEngine: Targets が空のルートはスキップされ、エラーにならないことを確認する。
	routes := map[string]*BackendConfig{
		"api": {Targets: []string{}},
	}
	engine, err := buildTenantEngine(routes)
	if err != nil {
		t.Fatalf("buildTenantEngine: %v", err)
	}
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
}

// buildTenantEngine: パスプレフィックスで正しいバックエンドへルーティングされることを確認する。
// /api/* → api バックエンド、それ以外 → default バックエンド。
func TestBuildTenantEngine_RoutePrefix(t *testing.T) {
	apiBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "api")
		w.WriteHeader(http.StatusOK)
	}))
	defer apiBackend.Close()

	defaultBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "default")
		w.WriteHeader(http.StatusOK)
	}))
	defer defaultBackend.Close()

	routes := map[string]*BackendConfig{
		"api": {Targets: []string{apiBackend.URL}},
		"":    {Targets: []string{defaultBackend.URL}},
	}

	engine, err := buildTenantEngine(routes)
	if err != nil {
		t.Fatalf("buildTenantEngine: %v", err)
	}

	proxy := httptest.NewServer(engine)
	defer proxy.Close()

	tests := []struct {
		path        string
		wantBackend string
	}{
		{"/api/foo", "api"},
		{"/api/v1/users", "api"},
		{"/other/path", "default"},
		{"/", "default"},
	}

	for _, tc := range tests {
		resp, err := http.Get(proxy.URL + tc.path)
		if err != nil {
			t.Errorf("path=%q: GET error: %v", tc.path, err)
			continue
		}
		resp.Body.Close()

		got := resp.Header.Get("X-Backend")
		if got != tc.wantBackend {
			t.Errorf("path=%q: X-Backend = %q, want %q (status=%d)", tc.path, got, tc.wantBackend, resp.StatusCode)
		}
	}
}

// buildTenantEngine: デフォルトルート ("") のみのとき、任意のパスが NoRoute 経由で
// default バックエンドへ転送されることを確認する。
func TestBuildTenantEngine_DefaultRoute_NoRouteHandler(t *testing.T) {
	defaultBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "default")
		w.WriteHeader(http.StatusOK)
	}))
	defer defaultBackend.Close()

	// デフォルトルートのみ（名前付きルートなし）
	routes := map[string]*BackendConfig{
		"": {Targets: []string{defaultBackend.URL}},
	}

	engine, err := buildTenantEngine(routes)
	if err != nil {
		t.Fatalf("buildTenantEngine: %v", err)
	}

	proxy := httptest.NewServer(engine)
	defer proxy.Close()

	for _, path := range []string{"/", "/anything", "/deep/nested/path"} {
		resp, err := http.Get(proxy.URL + path)
		if err != nil {
			t.Errorf("path=%q: GET error: %v", path, err)
			continue
		}
		resp.Body.Close()

		if got := resp.Header.Get("X-Backend"); got != "default" {
			t.Errorf("path=%q: X-Backend = %q, want %q (status=%d)", path, got, "default", resp.StatusCode)
		}
	}
}

// buildTenantEngine: デフォルトルートなしのとき、未マッチのパスが 404 になることを確認する。
func TestBuildTenantEngine_NoDefaultRoute_Returns404(t *testing.T) {
	apiBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer apiBackend.Close()

	// デフォルトルートなし
	routes := map[string]*BackendConfig{
		"api": {Targets: []string{apiBackend.URL}},
	}

	engine, err := buildTenantEngine(routes)
	if err != nil {
		t.Fatalf("buildTenantEngine: %v", err)
	}

	proxy := httptest.NewServer(engine)
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/unknown")
	if err != nil {
		t.Fatalf("GET error: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

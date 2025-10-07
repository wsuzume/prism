package csrf

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/wsuzume/prism/pkg/cipher"
	"github.com/wsuzume/prism/pkg/jwt"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func performRequest(r http.Handler, method, path string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func parseBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to parse body: %v", err)
	}
	return body
}

func TestNewBasicCSRFProtectorInvalidOrigin(t *testing.T) {
	p, err := NewBasicCSRFProtector([]string{":://"})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if p != nil {
		t.Fatalf("expected protector to be nil, got %#v", p)
	}
}

func TestBasicCSRFProtectorAllowsAllowedOrigin(t *testing.T) {
	protector, err := NewBasicCSRFProtector([]string{"https://example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	r := gin.New()
	r.Use(protector.Middleware())
	r.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := performRequest(r, http.MethodGet, "/", map[string]string{"Origin": "https://example.com/foo"})

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestBasicCSRFProtectorFallsBackToReferer(t *testing.T) {
	protector, err := NewBasicCSRFProtector([]string{"https://example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	r := gin.New()
	r.Use(protector.Middleware())
	r.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := performRequest(r, http.MethodGet, "/", map[string]string{"Referer": "https://example.com/path"})

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestBasicCSRFProtectorRejectsMissingHeaders(t *testing.T) {
	protector, err := NewBasicCSRFProtector([]string{"https://example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	r := gin.New()
	r.Use(protector.Middleware())
	r.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := performRequest(r, http.MethodGet, "/", nil)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
	body := parseBody(t, w)
	if body["error"] != "MissingOriginAndRefererHeader" {
		t.Fatalf("unexpected error body: %#v", body)
	}
}

func TestBasicCSRFProtectorRejectsInvalidOrigin(t *testing.T) {
	protector, err := NewBasicCSRFProtector([]string{"https://example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	r := gin.New()
	r.Use(protector.Middleware())
	r.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := performRequest(r, http.MethodGet, "/", map[string]string{"Origin": "https://evil.com"})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
	body := parseBody(t, w)
	if body["error"] != "InvalidOrigin" {
		t.Fatalf("unexpected error body: %#v", body)
	}
}

func TestBasicCSRFProtectorRejectsMalformedOrigin(t *testing.T) {
	protector, err := NewBasicCSRFProtector([]string{"https://example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	r := gin.New()
	r.Use(protector.Middleware())
	r.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := performRequest(r, http.MethodGet, "/", map[string]string{"Origin": "://bad"})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
	body := parseBody(t, w)
	if body["error"] != "InvalidFormatOrigin" {
		t.Fatalf("unexpected error body: %#v", body)
	}
}

func TestBasicCSRFProtectorDebugSkipsValidation(t *testing.T) {
	protector, err := NewBasicCSRFProtector(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	protector.Debug = true

	r := gin.New()
	r.Use(protector.Middleware())
	r.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := performRequest(r, http.MethodGet, "/", nil)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestModifyResponseEncodesPayloads(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	encrypter, err := cipher.NewEncrypterAESGCM(key)
	if err != nil {
		t.Fatalf("failed to create encrypter: %v", err)
	}

	protector := DefaultDoubleSubmitCookieCSRFProtector(encrypter)

	now := time.Now().UTC()
	jti := "test-jti"

	hdrSecret := &jwt.JwtHeader{Alg: protector.JwtAlg, Cty: protector.JwtCty, Typ: protector.JwtTyp}
	hdrAccess := &jwt.JwtHeader{Alg: protector.JwtAlg, Cty: protector.JwtCty, Typ: protector.JwtTyp}

	encodedOldSecret := base64.RawURLEncoding.EncodeToString([]byte("secret-old"))
	encodedOldAccess := base64.RawURLEncoding.EncodeToString([]byte("access-old"))
	encodedOldPublic := base64.RawURLEncoding.EncodeToString([]byte("public-old"))

	clSecret := &jwt.JwtClaims{
		Jti: jti,
		Iat: now.Unix(),
		Nbf: now.Unix(),
		Exp: now.Add(protector.SessionTTL).Unix(),
		Usr: encodedOldSecret,
	}
	clAccess := &jwt.JwtClaims{
		Jti: jti,
		Iat: now.Unix(),
		Nbf: now.Unix(),
		Exp: now.Add(protector.RefreshTTL).Unix(),
		Usr: encodedOldAccess,
	}

	info := &renewedInfo{
		hdrSecret:     hdrSecret,
		hdrAccess:     hdrAccess,
		clSecret:      clSecret,
		clAccess:      clAccess,
		publicPayload: []byte(encodedOldPublic),
	}

	req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	ctx := context.WithValue(req.Context(), ctxKeyRenewed{}, info)
	req = req.WithContext(ctx)

	resp := &http.Response{
		Header:  make(http.Header),
		Request: req,
	}

	secretPayload := "secret-new"
	accessPayload := "access-new"
	publicPayload := "public-new"

	resp.Header.Set(protector.SecretHeaderName, secretPayload)
	resp.Header.Set(protector.AccessHeaderName, accessPayload)
	resp.Header.Set(protector.PublicHeaderName, publicPayload)

	err = protector.ModifyResponse(nil)(resp)
	if err != nil {
		t.Fatalf("ModifyResponse returned error: %v", err)
	}

	if got := resp.Header.Get(protector.SecretHeaderName); got != "" {
		t.Fatalf("Secret header not cleared, got %q", got)
	}
	if got := resp.Header.Get(protector.AccessHeaderName); got != "" {
		t.Fatalf("Access header not cleared, got %q", got)
	}
	if got := resp.Header.Get(protector.PublicHeaderName); got != "" {
		t.Fatalf("Public header not cleared, got %q", got)
	}

	cookies := resp.Cookies()
	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(cookies))
	}

	var secretCookie, accessCookie *http.Cookie
	for _, ck := range cookies {
		switch ck.Name {
		case protector.SecretCookieName:
			secretCookie = ck
		case protector.AccessCookieName:
			accessCookie = ck
		}
	}

	if secretCookie == nil {
		t.Fatal("secret cookie not issued")
	}
	if accessCookie == nil {
		t.Fatal("access cookie not issued")
	}

	encodedSecret := base64.RawURLEncoding.EncodeToString([]byte(secretPayload))
	encodedAccess := base64.RawURLEncoding.EncodeToString([]byte(accessPayload))
	encodedPublic := base64.RawURLEncoding.EncodeToString([]byte(publicPayload))

	hdrSecretJSON, clSecretJSON, _, err := jwt.DecryptWithAAD(encrypter, secretCookie.Value)
	if err != nil {
		t.Fatalf("failed to decrypt secret cookie: %v", err)
	}
	_, newSecretClaims, err := jwt.Unmarshal(hdrSecretJSON, clSecretJSON)
	if err != nil {
		t.Fatalf("failed to unmarshal secret claims: %v", err)
	}
	if newSecretClaims.Usr != encodedSecret {
		t.Fatalf("unexpected secret payload: got %q want %q", newSecretClaims.Usr, encodedSecret)
	}

	hdrAccessJSON, clAccessJSON, publicAAD, err := jwt.DecryptWithAAD(encrypter, accessCookie.Value)
	if err != nil {
		t.Fatalf("failed to decrypt access cookie: %v", err)
	}
	_, newAccessClaims, err := jwt.Unmarshal(hdrAccessJSON, clAccessJSON)
	if err != nil {
		t.Fatalf("failed to unmarshal access claims: %v", err)
	}
	if newAccessClaims.Usr != encodedAccess {
		t.Fatalf("unexpected access payload: got %q want %q", newAccessClaims.Usr, encodedAccess)
	}
	if string(publicAAD) != encodedPublic {
		t.Fatalf("unexpected public payload: got %q want %q", string(publicAAD), encodedPublic)
	}
}

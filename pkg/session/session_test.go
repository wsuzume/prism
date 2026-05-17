package session

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/wsuzume/prism/pkg/cipher"
	jwtpkg "github.com/wsuzume/prism/pkg/jwt"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// ========================================================
// Test helpers
// ========================================================

func newTestCookieSession() *CookieSession {
	sm := NewSessionManager("test-iss", "test-aud")
	enc := cipher.NewEncrypterDummy()
	return DefaultCookieSession(sm, enc, "localhost", false)
}

func newTestJtiCS(t *testing.T) uuid.UUID {
	t.Helper()
	jti, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuid.NewV7: %v", err)
	}
	return jti
}

func makeTestSecretToken(t *testing.T, cs *CookieSession, jti uuid.UUID, now time.Time) string {
	t.Helper()
	payload := json.RawMessage(`{"authorized":false,"authenticated":false,"agent_verified":false,"agent_type":"","session_id":"","user_id":"","user_name":""}`)
	token, err := cs.EncryptSecretToken(jti, now, payload)
	if err != nil {
		t.Fatalf("EncryptSecretToken: %v", err)
	}
	return token
}

func makeTestAccessToken(t *testing.T, cs *CookieSession, jti uuid.UUID, now time.Time) string {
	t.Helper()
	accessPayload := json.RawMessage(`{"session_id":""}`)
	publicPayload := json.RawMessage(`{"user_name":""}`)
	token, err := cs.EncryptAccessToken(jti, now, accessPayload, publicPayload)
	if err != nil {
		t.Fatalf("EncryptAccessToken: %v", err)
	}
	return token
}

func newGinContext(method, path string) (*gin.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(method, path, nil)
	return c, w
}

// ========================================================
// ValidateSecretToken
// ========================================================

func TestValidateSecretToken_OK(t *testing.T) {
	cs := newTestCookieSession()
	jti := newTestJtiCS(t)
	now := time.Now()
	secretToken := makeTestSecretToken(t, cs, jti, now)

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: cs.SecretTokenName, Value: secretToken})

	token, j, payload, err := cs.ValidateSecretToken(req)
	if err != nil {
		t.Fatalf("ValidateSecretToken returned error: %v", err)
	}
	if token == "" {
		t.Fatalf("expected non-empty token")
	}
	if j == nil {
		t.Fatalf("expected non-nil jwt")
	}
	if payload == nil {
		t.Fatalf("expected non-nil payload")
	}
	if j.Claims.Jti != jti.String() {
		t.Fatalf("Jti = %q, want %q", j.Claims.Jti, jti.String())
	}
}

func TestValidateSecretToken_NoCookie(t *testing.T) {
	cs := newTestCookieSession()
	req := httptest.NewRequest("GET", "/", nil)

	_, _, _, err := cs.ValidateSecretToken(req)
	if err == nil {
		t.Fatalf("expected error when secret cookie is absent")
	}
}

func TestValidateSecretToken_DecryptFail(t *testing.T) {
	cs := newTestCookieSession()
	req := httptest.NewRequest("GET", "/", nil)
	// invalid base64 characters cause decryption to fail
	req.AddCookie(&http.Cookie{Name: cs.SecretTokenName, Value: "!!!not-valid-base64!!!"})

	_, _, _, err := cs.ValidateSecretToken(req)
	if err == nil {
		t.Fatalf("expected error for undecodable token")
	}
}

func TestValidateSecretToken_PayloadParseFail(t *testing.T) {
	cs := newTestCookieSession()
	enc := cipher.NewEncrypterDummy()

	// Craft a JWT whose usr field is a JSON string, not an object.
	// SecretPayloadFromJson will fail to unmarshal a string into *SecretPayload.
	jti := newTestJtiCS(t)
	now := time.Now()
	j := &jwtpkg.Jwt{
		Header: &jwtpkg.JwtHeader{Alg: enc.Alg(), Cty: "JSON", Typ: "JWT"},
		Claims: &jwtpkg.JwtClaims{
			Iss: "test-iss", Sub: "secret", Aud: "test-aud",
			Exp: now.Add(time.Hour).Unix(),
			Nbf: now.Unix(),
			Iat: now.Unix(),
			Jti: jti.String(),
			Usr: json.RawMessage(`"not-an-object"`),
		},
	}
	token, err := jwtpkg.Encrypt(enc, j)
	if err != nil {
		t.Fatalf("jwt.Encrypt: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: cs.SecretTokenName, Value: token})

	_, _, _, err = cs.ValidateSecretToken(req)
	if err == nil {
		t.Fatalf("expected error when usr is not a valid SecretPayload object")
	}
}

// ========================================================
// ValidateAccessToken
// ========================================================

func TestValidateAccessToken_OK(t *testing.T) {
	cs := newTestCookieSession()
	jti := newTestJtiCS(t)
	now := time.Now()

	secretToken := makeTestSecretToken(t, cs, jti, now)
	accessToken := makeTestAccessToken(t, cs, jti, now)

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: cs.SecretTokenName, Value: secretToken})
	req.AddCookie(&http.Cookie{Name: cs.AccessTokenName, Value: accessToken})

	_, secretJwt, _, err := cs.ValidateSecretToken(req)
	if err != nil {
		t.Fatalf("ValidateSecretToken: %v", err)
	}

	token, j, err := cs.ValidateAccessToken(req, secretJwt)
	if err != nil {
		t.Fatalf("ValidateAccessToken returned error: %v", err)
	}
	if token == "" {
		t.Fatalf("expected non-empty access token")
	}
	if j == nil {
		t.Fatalf("expected non-nil access jwt")
	}
}

func TestValidateAccessToken_NoCookie(t *testing.T) {
	cs := newTestCookieSession()
	jti := newTestJtiCS(t)
	now := time.Now()

	secretToken := makeTestSecretToken(t, cs, jti, now)

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: cs.SecretTokenName, Value: secretToken})

	_, secretJwt, _, err := cs.ValidateSecretToken(req)
	if err != nil {
		t.Fatalf("ValidateSecretToken: %v", err)
	}

	_, _, err = cs.ValidateAccessToken(req, secretJwt)
	if err == nil {
		t.Fatalf("expected error when access cookie is absent")
	}
}

func TestValidateAccessToken_JtiMismatch(t *testing.T) {
	cs := newTestCookieSession()
	jti1 := newTestJtiCS(t)
	jti2 := newTestJtiCS(t)
	now := time.Now()

	// secretJwt was issued with jti1; access token was issued with jti2
	secretJwt := cs.Manager.NewSecretJwt(cs.Encrypter, jti1, now, json.RawMessage(`{}`))
	accessToken := makeTestAccessToken(t, cs, jti2, now)

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: cs.AccessTokenName, Value: accessToken})

	_, _, err := cs.ValidateAccessToken(req, secretJwt)
	if err == nil {
		t.Fatalf("expected error for jti mismatch (CSRF-equivalent)")
	}
}

// ========================================================
// ValidateSubmitToken
// ========================================================

func TestValidateSubmitToken_OK(t *testing.T) {
	cs := newTestCookieSession()
	accessToken := "some-access-token-value"

	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set(cs.SubmitTokenName, accessToken)

	submit, errMissing, errMismatch := cs.ValidateSubmitToken(req, accessToken)
	if errMissing != nil {
		t.Fatalf("unexpected missing-header error: %v", errMissing)
	}
	if errMismatch != nil {
		t.Fatalf("unexpected mismatch error: %v", errMismatch)
	}
	if submit != accessToken {
		t.Fatalf("submit = %q, want %q", submit, accessToken)
	}
}

func TestValidateSubmitToken_NoHeader(t *testing.T) {
	cs := newTestCookieSession()
	req := httptest.NewRequest("POST", "/", nil)

	_, errMissing, errMismatch := cs.ValidateSubmitToken(req, "some-token")
	if errMissing == nil {
		t.Fatalf("expected missing-header error")
	}
	if errMismatch != nil {
		t.Fatalf("unexpected mismatch error: %v", errMismatch)
	}
}

func TestValidateSubmitToken_Mismatch(t *testing.T) {
	cs := newTestCookieSession()
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set(cs.SubmitTokenName, "wrong-token")

	_, errMissing, errMismatch := cs.ValidateSubmitToken(req, "correct-token")
	if errMissing != nil {
		t.Fatalf("unexpected missing-header error: %v", errMissing)
	}
	if errMismatch == nil {
		t.Fatalf("expected mismatch error")
	}
}

// ========================================================
// handleUntrustedRequest
// ========================================================

func TestHandleUntrustedRequest_FirewallDisabled_GET(t *testing.T) {
	cs := newTestCookieSession()
	cs.Firewall = false
	c, w := newGinContext(http.MethodGet, "/")

	cs.handleUntrustedRequest(c)

	if w.Code == http.StatusForbidden {
		t.Fatalf("expected GET to pass through when firewall is disabled, got 403")
	}
}

func TestHandleUntrustedRequest_FirewallDisabled_POST(t *testing.T) {
	cs := newTestCookieSession()
	cs.Firewall = false
	c, w := newGinContext(http.MethodPost, "/")

	cs.handleUntrustedRequest(c)

	if w.Code == http.StatusForbidden {
		t.Fatalf("expected POST to pass through when firewall is disabled, got 403")
	}
}

func TestHandleUntrustedRequest_FirewallEnabled_POST_403(t *testing.T) {
	cs := newTestCookieSession()
	cs.Firewall = true
	c, w := newGinContext(http.MethodPost, "/")

	cs.handleUntrustedRequest(c)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unsafe method when firewall is enabled, got %d", w.Code)
	}
}

// ========================================================
// handleUntrustedRequestPassThrough
// ========================================================

func TestHandleUntrustedRequestPassThrough_FirewallDisabled_GET(t *testing.T) {
	cs := newTestCookieSession()
	cs.Firewall = false
	c, w := newGinContext(http.MethodGet, "/")

	cs.handleUntrustedRequestPassThrough(c, NewUnauthorizedSecretPayload())

	if w.Code == http.StatusForbidden {
		t.Fatalf("expected GET to pass through when firewall is disabled, got 403")
	}
}

func TestHandleUntrustedRequestPassThrough_FirewallDisabled_POST(t *testing.T) {
	cs := newTestCookieSession()
	cs.Firewall = false
	c, w := newGinContext(http.MethodPost, "/")

	cs.handleUntrustedRequestPassThrough(c, NewUnauthorizedSecretPayload())

	if w.Code == http.StatusForbidden {
		t.Fatalf("expected POST to pass through when firewall is disabled, got 403")
	}
}

func TestHandleUntrustedRequestPassThrough_FirewallEnabled_POST_403(t *testing.T) {
	cs := newTestCookieSession()
	cs.Firewall = true
	c, w := newGinContext(http.MethodPost, "/")

	cs.handleUntrustedRequestPassThrough(c, NewUnauthorizedSecretPayload())

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unsafe method when firewall is enabled, got %d", w.Code)
	}
}

// ========================================================
// ModifyResponse
// ========================================================

func TestModifyResponse_SecretHeader_SetsCookies(t *testing.T) {
	cs := newTestCookieSession()

	secretPayload := &SecretPayload{
		Authorized:    true,
		Authenticated: true,
		AgentVerified: false,
		AgentType:     "",
		SessionID:     "sess-abc",
		UserID:        "user-123",
		UserName:      "testuser",
	}
	secretPayloadJson, err := json.Marshal(secretPayload)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	resp := &http.Response{
		Header:  http.Header{},
		Request: req,
		Body:    http.NoBody,
	}
	resp.Header.Set(cs.SecretHeaderName, string(secretPayloadJson))

	fn := cs.ModifyResponse(nil)
	if err := fn(resp); err != nil {
		t.Fatalf("ModifyResponse returned error: %v", err)
	}

	cookies := resp.Header["Set-Cookie"]
	if len(cookies) != 2 {
		t.Fatalf("expected 2 Set-Cookie headers, got %d: %v", len(cookies), cookies)
	}

	foundSecret, foundAccess := false, false
	for _, c := range cookies {
		if strings.Contains(c, cs.SecretTokenName) {
			foundSecret = true
		}
		if strings.Contains(c, cs.AccessTokenName) {
			foundAccess = true
		}
	}
	if !foundSecret {
		t.Fatalf("Set-Cookie missing secret token cookie (%s)", cs.SecretTokenName)
	}
	if !foundAccess {
		t.Fatalf("Set-Cookie missing access token cookie (%s)", cs.AccessTokenName)
	}
}

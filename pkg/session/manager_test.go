package session

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/wsuzume/prism/pkg/cipher"
)

func newTestManager() *SessionManager {
	return NewSessionManager("test-issuer", "test-audience")
}

var testPayload = json.RawMessage(`{"user_id":"u-123","role":"admin"}`)

// ========================================================
// NewSessionManager
// ========================================================

func TestNewSessionManager(t *testing.T) {
	sm := NewSessionManager("iss", "aud")

	if sm.Iss != "iss" {
		t.Fatalf("Iss = %q, want %q", sm.Iss, "iss")
	}
	if sm.Aud != "aud" {
		t.Fatalf("Aud = %q, want %q", sm.Aud, "aud")
	}
	if sm.RefreshTTL == 0 {
		t.Fatalf("RefreshTTL should have a default value")
	}
	if sm.SessionTTL == 0 {
		t.Fatalf("SessionTTL should have a default value")
	}
}

// ========================================================
// NewSecretJwt
// ========================================================

func TestNewSecretJwt(t *testing.T) {
	sm := newTestManager()
	signer := &cipher.SignerDummy{}

	j, err := sm.NewSecretJwt(signer, testPayload)
	if err != nil {
		t.Fatalf("NewSecretJwt returned error: %v", err)
	}

	if j.Header.Alg != signer.Alg() {
		t.Fatalf("Alg = %q, want %q", j.Header.Alg, signer.Alg())
	}
	if j.Header.Typ != "JWT" {
		t.Fatalf("Typ = %q, want %q", j.Header.Typ, "JWT")
	}
	if j.Claims.Iss != sm.Iss {
		t.Fatalf("Iss = %q, want %q", j.Claims.Iss, sm.Iss)
	}
	if j.Claims.Sub != "secret" {
		t.Fatalf("Sub = %q, want %q", j.Claims.Sub, "secret")
	}
	if j.Claims.Aud != sm.Aud {
		t.Fatalf("Aud = %q, want %q", j.Claims.Aud, sm.Aud)
	}
	if j.Claims.Jti == "" {
		t.Fatalf("Jti should not be empty")
	}
	if j.Claims.Exp <= j.Claims.Iat {
		t.Fatalf("Exp (%d) should be after Iat (%d)", j.Claims.Exp, j.Claims.Iat)
	}
	if string(j.Claims.Usr) != string(testPayload) {
		t.Fatalf("Usr = %s, want %s", j.Claims.Usr, testPayload)
	}
}

// ========================================================
// NewAccessJwt
// ========================================================

func TestNewAccessJwt(t *testing.T) {
	sm := newTestManager()
	signer := &cipher.SignerDummy{}

	j, err := sm.NewAccessJwt(signer, testPayload)
	if err != nil {
		t.Fatalf("NewAccessJwt returned error: %v", err)
	}

	if j.Claims.Sub != "access" {
		t.Fatalf("Sub = %q, want %q", j.Claims.Sub, "access")
	}
	if j.Claims.Iss != sm.Iss {
		t.Fatalf("Iss = %q, want %q", j.Claims.Iss, sm.Iss)
	}
	if j.Claims.Jti == "" {
		t.Fatalf("Jti should not be empty")
	}
}

// ========================================================
// NewSecretJwt / NewAccessJwt generate unique JTIs
// ========================================================

func TestJtiUniqueness(t *testing.T) {
	sm := newTestManager()
	signer := &cipher.SignerDummy{}

	j1, err := sm.NewSecretJwt(signer, testPayload)
	if err != nil {
		t.Fatalf("NewSecretJwt returned error: %v", err)
	}
	j2, err := sm.NewSecretJwt(signer, testPayload)
	if err != nil {
		t.Fatalf("NewSecretJwt returned error: %v", err)
	}

	if j1.Claims.Jti == j2.Claims.Jti {
		t.Fatalf("two JWTs should have different Jti values, got %q", j1.Claims.Jti)
	}
}

// ========================================================
// Signed Secret Token: round-trip
// ========================================================

func TestSignedSecretToken_Roundtrip(t *testing.T) {
	sm := newTestManager()
	signer := &cipher.SignerDummy{}

	token, err := sm.NewSignedSecretToken(signer, testPayload)
	if err != nil {
		t.Fatalf("NewSignedSecretToken returned error: %v", err)
	}
	if token == "" {
		t.Fatalf("token should not be empty")
	}

	j, err := sm.VerifySignedSecretToken(signer, token)
	if err != nil {
		t.Fatalf("VerifySignedSecretToken returned error: %v", err)
	}

	if j.Claims.Sub != "secret" {
		t.Fatalf("Sub = %q, want %q", j.Claims.Sub, "secret")
	}
	if string(j.Claims.Usr) != string(testPayload) {
		t.Fatalf("Usr = %s, want %s", j.Claims.Usr, testPayload)
	}
}

// ========================================================
// Signed Access Token: round-trip
// ========================================================

func TestSignedAccessToken_Roundtrip(t *testing.T) {
	sm := newTestManager()
	signer := &cipher.SignerDummy{}

	accessPayload := json.RawMessage(`{"session_id":"s-1"}`)
	publicPayload := json.RawMessage(`{"display_name":"Josh"}`)

	token, err := sm.NewSignedAccessToken(signer, accessPayload, publicPayload)
	if err != nil {
		t.Fatalf("NewSignedAccessToken returned error: %v", err)
	}

	j, pub, err := sm.VerifySignedAccessToken(signer, token)
	if err != nil {
		t.Fatalf("VerifySignedAccessToken returned error: %v", err)
	}

	if j.Claims.Sub != "access" {
		t.Fatalf("Sub = %q, want %q", j.Claims.Sub, "access")
	}
	if string(j.Claims.Usr) != string(accessPayload) {
		t.Fatalf("Usr = %s, want %s", j.Claims.Usr, accessPayload)
	}
	if string(pub) != string(publicPayload) {
		t.Fatalf("public payload = %s, want %s", pub, publicPayload)
	}
}

// ========================================================
// VerifySignedSecretToken: edge cases
// ========================================================

func TestVerifySignedSecretToken_EmptyToken(t *testing.T) {
	sm := newTestManager()
	signer := &cipher.SignerDummy{}

	if _, err := sm.VerifySignedSecretToken(signer, ""); err == nil {
		t.Fatalf("expected error for empty token")
	}
}

func TestVerifySignedSecretToken_TooLong(t *testing.T) {
	sm := newTestManager()
	signer := &cipher.SignerDummy{}

	longToken := strings.Repeat("a", 4097)
	if _, err := sm.VerifySignedSecretToken(signer, longToken); err == nil {
		t.Fatalf("expected error for token exceeding max length")
	}
}

// ========================================================
// VerifySignedAccessToken: edge cases
// ========================================================

func TestVerifySignedAccessToken_EmptyToken(t *testing.T) {
	sm := newTestManager()
	signer := &cipher.SignerDummy{}

	if _, _, err := sm.VerifySignedAccessToken(signer, ""); err == nil {
		t.Fatalf("expected error for empty token")
	}
}

func TestVerifySignedAccessToken_TooLong(t *testing.T) {
	sm := newTestManager()
	signer := &cipher.SignerDummy{}

	longToken := strings.Repeat("a", 4097)
	if _, _, err := sm.VerifySignedAccessToken(signer, longToken); err == nil {
		t.Fatalf("expected error for token exceeding max length")
	}
}

func TestVerifySignedAccessToken_InsufficientSeparators(t *testing.T) {
	sm := newTestManager()
	signer := &cipher.SignerDummy{}

	// 3つ未満のドットしかないトークン
	if _, _, err := sm.VerifySignedAccessToken(signer, "a.b"); err == nil {
		t.Fatalf("expected error for insufficient separators")
	}
}

// ========================================================
// Encrypted Secret Token: round-trip
// ========================================================

func TestEncryptedSecretToken_Roundtrip(t *testing.T) {
	sm := newTestManager()
	enc := &cipher.EncrypterDummy{}

	token, err := sm.EncryptSecretToken(enc, testPayload)
	if err != nil {
		t.Fatalf("EncryptSecretToken returned error: %v", err)
	}
	if token == "" {
		t.Fatalf("token should not be empty")
	}

	j, err := sm.DecryptSecretToken(enc, token)
	if err != nil {
		t.Fatalf("DecryptSecretToken returned error: %v", err)
	}

	if j.Claims.Sub != "secret" {
		t.Fatalf("Sub = %q, want %q", j.Claims.Sub, "secret")
	}
	if string(j.Claims.Usr) != string(testPayload) {
		t.Fatalf("Usr = %s, want %s", j.Claims.Usr, testPayload)
	}
}

// ========================================================
// Encrypted Access Token: round-trip
// ========================================================

func TestEncryptedAccessToken_Roundtrip(t *testing.T) {
	sm := newTestManager()
	enc := &cipher.EncrypterDummy{}

	accessPayload := json.RawMessage(`{"session_id":"s-2"}`)
	publicPayload := json.RawMessage(`{"display_name":"Alice"}`)

	token, err := sm.EncryptAccessToken(enc, accessPayload, publicPayload)
	if err != nil {
		t.Fatalf("EncryptAccessToken returned error: %v", err)
	}

	j, pub, err := sm.DecryptAccessToken(enc, token)
	if err != nil {
		t.Fatalf("DecryptAccessToken returned error: %v", err)
	}

	if j.Claims.Sub != "access" {
		t.Fatalf("Sub = %q, want %q", j.Claims.Sub, "access")
	}
	if string(j.Claims.Usr) != string(accessPayload) {
		t.Fatalf("Usr = %s, want %s", j.Claims.Usr, accessPayload)
	}
	if string(pub) != string(publicPayload) {
		t.Fatalf("public payload = %s, want %s", pub, publicPayload)
	}
}

// ========================================================
// DecryptSecretToken: edge cases
// ========================================================

func TestDecryptSecretToken_EmptyToken(t *testing.T) {
	sm := newTestManager()
	enc := &cipher.EncrypterDummy{}

	if _, err := sm.DecryptSecretToken(enc, ""); err == nil {
		t.Fatalf("expected error for empty token")
	}
}

func TestDecryptSecretToken_TooLong(t *testing.T) {
	sm := newTestManager()
	enc := &cipher.EncrypterDummy{}

	longToken := strings.Repeat("a", 4097)
	if _, err := sm.DecryptSecretToken(enc, longToken); err == nil {
		t.Fatalf("expected error for token exceeding max length")
	}
}

// ========================================================
// DecryptAccessToken: edge cases
// ========================================================

func TestDecryptAccessToken_EmptyToken(t *testing.T) {
	sm := newTestManager()
	enc := &cipher.EncrypterDummy{}

	if _, _, err := sm.DecryptAccessToken(enc, ""); err == nil {
		t.Fatalf("expected error for empty token")
	}
}

func TestDecryptAccessToken_TooLong(t *testing.T) {
	sm := newTestManager()
	enc := &cipher.EncrypterDummy{}

	longToken := strings.Repeat("a", 4097)
	if _, _, err := sm.DecryptAccessToken(enc, longToken); err == nil {
		t.Fatalf("expected error for token exceeding max length")
	}
}

func TestDecryptAccessToken_NoSeparator(t *testing.T) {
	sm := newTestManager()
	enc := &cipher.EncrypterDummy{}

	// ドットを含まないトークン
	token := base64.RawURLEncoding.EncodeToString([]byte("noseparator"))
	if _, _, err := sm.DecryptAccessToken(enc, token); err == nil {
		t.Fatalf("expected error for token without separator")
	}
}

func TestDecryptAccessToken_EmptyEncryptedPortion(t *testing.T) {
	sm := newTestManager()
	enc := &cipher.EncrypterDummy{}

	// publicパートの後に空のencryptedパート
	pub := base64.RawURLEncoding.EncodeToString([]byte(`{"x":1}`))
	if _, _, err := sm.DecryptAccessToken(enc, pub+"."); err == nil {
		t.Fatalf("expected error for empty encrypted portion")
	}
}

// ========================================================
// Signed Access Token: public payload with dots
// ========================================================

func TestSignedAccessToken_PublicPayloadWithDots(t *testing.T) {
	sm := newTestManager()
	signer := &cipher.SignerDummy{}

	// base64エンコード結果にドットは含まれないが、
	// 末尾からのドット探索ロジックが正しいことを確認する
	accessPayload := json.RawMessage(`{"id":"a"}`)
	publicPayload := json.RawMessage(`{"url":"https://example.com/path","nested":{"key":"value"}}`)

	token, err := sm.NewSignedAccessToken(signer, accessPayload, publicPayload)
	if err != nil {
		t.Fatalf("NewSignedAccessToken returned error: %v", err)
	}

	j, pub, err := sm.VerifySignedAccessToken(signer, token)
	if err != nil {
		t.Fatalf("VerifySignedAccessToken returned error: %v", err)
	}

	if string(pub) != string(publicPayload) {
		t.Fatalf("public payload = %s, want %s", pub, publicPayload)
	}
	if string(j.Claims.Usr) != string(accessPayload) {
		t.Fatalf("Usr = %s, want %s", j.Claims.Usr, accessPayload)
	}
}

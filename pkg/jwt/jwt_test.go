package jwt

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wsuzume/prism/pkg/cipher"
)

func sampleHeader() *JwtHeader {
	return &JwtHeader{Alg: DefaultAlg, Typ: DefaultTyp}
}

func sampleClaims() *JwtClaims {
	return &JwtClaims{
		Iss: "issuer",
		Sub: "subject",
		Aud: "audience",
		Exp: time.Now().Add(time.Hour).Unix(),
		Nbf: time.Now().Add(-time.Minute).Unix(),
		Iat: time.Now().Unix(),
		Jti: "id-123",
		Usr: json.RawMessage(`{"role":"admin"}`),
	}
}

func sampleJwt() *Jwt {
	return &Jwt{Header: sampleHeader(), Claims: sampleClaims()}
}

// ========================================================
// Marshal / Unmarshal
// ========================================================

func TestMarshalAndUnmarshal(t *testing.T) {
	hdr := sampleHeader()
	cl := sampleClaims()

	hJSON, err := MarshalJwtHeader(hdr)
	if err != nil {
		t.Fatalf("MarshalJwtHeader returned error: %v", err)
	}
	cJSON, err := MarshalJwtClaims(cl)
	if err != nil {
		t.Fatalf("MarshalJwtClaims returned error: %v", err)
	}

	hdr2, err := UnmarshalJwtHeader(hJSON)
	if err != nil {
		t.Fatalf("UnmarshalJwtHeader returned error: %v", err)
	}
	cl2, err := UnmarshalJwtClaims(cJSON)
	if err != nil {
		t.Fatalf("UnmarshalJwtClaims returned error: %v", err)
	}

	if !reflect.DeepEqual(hdr, hdr2) {
		t.Fatalf("header mismatch: %#v != %#v", hdr, hdr2)
	}
	if !reflect.DeepEqual(cl, cl2) {
		t.Fatalf("claims mismatch: %#v != %#v", cl, cl2)
	}
}

func TestUnmarshalErrors(t *testing.T) {
	if _, err := UnmarshalJwtHeader([]byte("not-json")); err == nil {
		t.Fatalf("UnmarshalJwtHeader expected error for invalid JSON")
	}
	if _, err := UnmarshalJwtClaims([]byte("not-json")); err == nil {
		t.Fatalf("UnmarshalJwtClaims expected error for invalid JSON")
	}
}

// ========================================================
// HasValidLifetime
// ========================================================

func TestHasValidLifetime(t *testing.T) {
	base := time.Unix(1700000000, 0)
	originalNow := nowFunc
	defer func() { nowFunc = originalNow }()
	nowFunc = func() time.Time { return base }

	tests := map[string]struct {
		claims    JwtClaims
		clockSkew time.Duration
		want      bool
	}{
		"no limits":           {claims: JwtClaims{}, want: true},
		"nbf future":          {claims: JwtClaims{Nbf: base.Add(time.Minute).Unix()}, want: false},
		"nbf within skew":     {claims: JwtClaims{Nbf: base.Add(30 * time.Second).Unix()}, clockSkew: time.Minute, want: true},
		"exp past":            {claims: JwtClaims{Exp: base.Add(-time.Second).Unix()}, want: false},
		"exp within skew":     {claims: JwtClaims{Exp: base.Add(-30 * time.Second).Unix()}, clockSkew: time.Minute, want: true},
		"exp and nbf valid":   {claims: JwtClaims{Nbf: base.Add(-time.Hour).Unix(), Exp: base.Add(time.Hour).Unix()}, want: true},
		"exp and nbf invalid": {claims: JwtClaims{Nbf: base.Add(time.Hour).Unix(), Exp: base.Add(-time.Hour).Unix()}, want: false},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := tt.claims.HasValidLifetime(tt.clockSkew)
			if got != tt.want {
				t.Fatalf("HasValidLifetime() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJwtHasValidLifetimeMethod(t *testing.T) {
	base := time.Unix(1700000000, 0)
	originalNow := nowFunc
	defer func() { nowFunc = originalNow }()
	nowFunc = func() time.Time { return base }

	j := sampleJwt()
	j.Claims.Exp = base.Add(time.Minute).Unix()
	j.Claims.Nbf = base.Add(-time.Minute).Unix()

	if !j.HasValidLifetime(0) {
		t.Fatalf("HasValidLifetime expected true")
	}
}

// ========================================================
// Sign
// ========================================================

func TestSign(t *testing.T) {
	signer := &cipher.SignerDummy{}
	jwt := sampleJwt()

	token, err := Sign(signer, jwt)
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("expected 3 dot-separated parts, got %d", len(parts))
	}
	if parts[0] == "" || parts[1] == "" || parts[2] == "" {
		t.Fatalf("token parts must not be empty: %q", token)
	}
}

// ========================================================
// Verify
// ========================================================

func TestVerify(t *testing.T) {
	signer := &cipher.SignerDummy{}
	jwt := sampleJwt()

	token, err := Sign(signer, jwt)
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	verified, err := Verify(signer, token)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}

	if !reflect.DeepEqual(jwt.Header, verified.Header) {
		t.Fatalf("header mismatch")
	}
	if !reflect.DeepEqual(jwt.Claims, verified.Claims) {
		t.Fatalf("claims mismatch")
	}
}

func TestVerify_InvalidFormat(t *testing.T) {
	signer := &cipher.SignerDummy{}

	if _, err := Verify(signer, "invalid"); err == nil {
		t.Fatalf("Verify expected error for malformed token")
	}
}

func TestVerify_TamperedSignature(t *testing.T) {
	signer := &cipher.SignerDummy{}
	jwt := sampleJwt()

	token, err := Sign(signer, jwt)
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	tampered := token + "extra"
	if _, err := Verify(signer, tampered); err == nil {
		t.Fatalf("Verify expected error for tampered token")
	}
}

// ========================================================
// Encrypt
// ========================================================

func TestEncrypt(t *testing.T) {
	encrypter := &cipher.EncrypterDummy{}
	jwt := sampleJwt()

	token, err := Encrypt(encrypter, jwt)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}
	if token == "" {
		t.Fatalf("Encrypt returned empty token")
	}
}

// ========================================================
// Decrypt
// ========================================================

func TestDecrypt(t *testing.T) {
	encrypter := &cipher.EncrypterDummy{}
	jwt := sampleJwt()

	token, err := Encrypt(encrypter, jwt)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}

	decrypted, err := Decrypt(encrypter, token)
	if err != nil {
		t.Fatalf("Decrypt returned error: %v", err)
	}

	if !reflect.DeepEqual(jwt.Header, decrypted.Header) {
		t.Fatalf("header mismatch")
	}
	if !reflect.DeepEqual(jwt.Claims, decrypted.Claims) {
		t.Fatalf("claims mismatch")
	}
}

func TestDecrypt_InvalidToken(t *testing.T) {
	encrypter := &cipher.EncrypterDummy{}

	// EncrypterDummy はそのまま返すので、ドットを含まない base64url 文字列は
	// Decrypt 内の SplitN で 2 パートにならずエラーになる
	if _, err := Decrypt(encrypter, b64urlEncode([]byte("nodot"))); err == nil {
		t.Fatalf("Decrypt expected error for invalid token format")
	}
}

// ========================================================
// EncryptWithAAD
// ========================================================

func TestEncryptWithAAD(t *testing.T) {
	encrypter := &cipher.EncrypterDummy{}
	jwt := sampleJwt()
	aad := []byte(`{"scope":"read"}`)

	token, err := EncryptWithAAD(encrypter, jwt, aad)
	if err != nil {
		t.Fatalf("EncryptWithAAD returned error: %v", err)
	}
	if token == "" {
		t.Fatalf("EncryptWithAAD returned empty token")
	}
}

// ========================================================
// DecryptWithAAD
// ========================================================

func TestDecryptWithAAD(t *testing.T) {
	encrypter := &cipher.EncrypterDummy{}
	jwt := sampleJwt()
	aad := []byte(`{"scope":"read"}`)

	token, err := EncryptWithAAD(encrypter, jwt, aad)
	if err != nil {
		t.Fatalf("EncryptWithAAD returned error: %v", err)
	}

	decrypted, err := DecryptWithAAD(encrypter, token, aad)
	if err != nil {
		t.Fatalf("DecryptWithAAD returned error: %v", err)
	}

	if !reflect.DeepEqual(jwt.Header, decrypted.Header) {
		t.Fatalf("header mismatch")
	}
	if !reflect.DeepEqual(jwt.Claims, decrypted.Claims) {
		t.Fatalf("claims mismatch")
	}
}

func TestDecryptWithAAD_InvalidToken(t *testing.T) {
	encrypter := &cipher.EncrypterDummy{}
	aad := []byte(`{"scope":"read"}`)

	if _, err := DecryptWithAAD(encrypter, b64urlEncode([]byte("nodot")), aad); err == nil {
		t.Fatalf("DecryptWithAAD expected error for invalid token format")
	}
}

// ========================================================
// Round-trip: Sign → Verify
// ========================================================

func TestSignVerifyRoundtrip(t *testing.T) {
	signer := &cipher.SignerDummy{}
	original := sampleJwt()

	token, err := Sign(signer, original)
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	restored, err := Verify(signer, token)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}

	if !reflect.DeepEqual(original.Header, restored.Header) {
		t.Fatalf("header mismatch after round-trip")
	}
	if !reflect.DeepEqual(original.Claims, restored.Claims) {
		t.Fatalf("claims mismatch after round-trip")
	}
}

// ========================================================
// Round-trip: Encrypt → Decrypt
// ========================================================

func TestEncryptDecryptRoundtrip(t *testing.T) {
	encrypter := &cipher.EncrypterDummy{}
	original := sampleJwt()

	token, err := Encrypt(encrypter, original)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}

	restored, err := Decrypt(encrypter, token)
	if err != nil {
		t.Fatalf("Decrypt returned error: %v", err)
	}

	if !reflect.DeepEqual(original.Header, restored.Header) {
		t.Fatalf("header mismatch after round-trip")
	}
	if !reflect.DeepEqual(original.Claims, restored.Claims) {
		t.Fatalf("claims mismatch after round-trip")
	}
}

// ========================================================
// Round-trip: EncryptWithAAD → DecryptWithAAD
// ========================================================

func TestEncryptDecryptWithAADRoundtrip(t *testing.T) {
	encrypter := &cipher.EncrypterDummy{}
	original := sampleJwt()
	aad := []byte(`{"scope":"write"}`)

	token, err := EncryptWithAAD(encrypter, original, aad)
	if err != nil {
		t.Fatalf("EncryptWithAAD returned error: %v", err)
	}

	restored, err := DecryptWithAAD(encrypter, token, aad)
	if err != nil {
		t.Fatalf("DecryptWithAAD returned error: %v", err)
	}

	if !reflect.DeepEqual(original.Header, restored.Header) {
		t.Fatalf("header mismatch after round-trip")
	}
	if !reflect.DeepEqual(original.Claims, restored.Claims) {
		t.Fatalf("claims mismatch after round-trip")
	}
}

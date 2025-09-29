package jwt

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"prism/pkg/cipher"
)

// ヘルパー
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	return b
}

func newAESGCM(t *testing.T) cipher.EncrypterInterface {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	enc, err := cipher.NewEncrypterAESGCM(key)
	if err != nil {
		t.Fatalf("NewEncrypterAESGCM: %v", err)
	}
	return enc
}

func TestDefaultJwtHeader(t *testing.T) {
	h := DefaultJwtHeader()
	if h.Alg != DefaultAlg {
		t.Fatalf("Alg want %q got %q", DefaultAlg, h.Alg)
	}
	if h.Typ != DefaultTyp {
		t.Fatalf("Typ want %q got %q", DefaultTyp, h.Typ)
	}
	if h.Cty != "" { // omitempty のゼロ値
		t.Fatalf("Cty want empty got %q", h.Cty)
	}
}

func TestSignAndVerifyHS256_Success(t *testing.T) {
	secret := []byte("topsecret")
	s := cipher.NewSignerHS256(secret)

	now := time.Now().Unix()

	h := DefaultJwtHeader()
	c := JwtClaims{
		Iss: "prism",
		Sub: "session",
		Aud: "browser",
		Iat: now,
		Nbf: now,
		Exp: now + 60, // 60秒有効
		Jti: "jti-123",
		Usr: "user",
	}

	token := Sign(s, mustJSON(t, h), mustJSON(t, c))

	headerJSON, claimsJSON, err := Verify(s, token)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}

	hd, err := UnmarshalJwtHeader(headerJSON)
	if err != nil {
		t.Fatalf("UnmarshalJwtHeader: %v", err)
	}
	cd, err := UnmarshalJwtClaims(claimsJSON)
	if err != nil {
		t.Fatalf("UnmarshalJwtClaims: %v", err)
	}

	// ヘッダー検証
	if hd.Alg != h.Alg || hd.Typ != h.Typ || hd.Cty != h.Cty {
		t.Fatalf("header mismatch: want=%+v got=%+v", h, hd)
	}

	// クレーム主要フィールド検証
	if cd.Iss != c.Iss || cd.Sub != c.Sub || cd.Aud != c.Aud || cd.Jti != c.Jti ||
		cd.Iat != c.Iat || cd.Nbf != c.Nbf || cd.Exp != c.Exp || cd.Usr != c.Usr {
		t.Fatalf("claims mismatch: want=%+v got=%+v", c, cd)
	}

	// 期間内判定
	clockSkew := 2 * time.Minute // 許容クロックスキュー
	if !HasValidLifetime(cd, clockSkew) {
		t.Fatalf("HasValidLifetime should be true")
	}
}

func TestVerifyHS256_FailsOnTamperSignature(t *testing.T) {
	secret := []byte("topsecret")
	s := cipher.NewSignerHS256(secret)

	now := time.Now().Unix()

	h := DefaultJwtHeader()
	c := JwtClaims{
		Iss: "prism", Sub: "session", Aud: "browser",
		Iat: now, Nbf: now, Exp: now + 60, Jti: "jti-123",
	}

	token := Sign(s, mustJSON(t, h), mustJSON(t, c))

	// 署名部分の末尾を差し替えて改ざん
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected token parts")
	}
	sig := parts[2]
	if sig[len(sig)-1] == 'A' {
		parts[2] = sig[:len(sig)-1] + "B"
	} else {
		parts[2] = sig[:len(sig)-1] + "A"
	}
	tampered := strings.Join(parts, ".")

	if _, _, err := Verify(s, tampered); err == nil {
		t.Fatalf("verify should fail on tampered signature")
	}
}

func TestVerifyHS256_InvalidParts(t *testing.T) {
	secret := []byte("topsecret")
	s := cipher.NewSignerHS256(secret)

	// パーツ数が3でない
	if _, _, err := Verify(s, "only.two.parts"); err == nil {
		t.Fatalf("verify should fail on invalid parts count")
	}
	if _, _, err := Verify(s, "abc"); err == nil {
		t.Fatalf("verify should fail when no dots")
	}
}

func TestVerifyHS256_InvalidBase64(t *testing.T) {
	secret := []byte("topsecret")
	s := cipher.NewSignerHS256(secret)

	// Base64URL 不正文字 '!' を使う
	if _, _, err := Verify(s, "!.!.!"); err == nil {
		t.Fatalf("verify should fail on invalid base64")
	}
}

func TestHasValidLifetime(t *testing.T) {
	now := time.Now()
	clockSkew := 2 * time.Minute // 許容クロックスキュー

	// 有効な期間（十分なバッファを持たせ、time.Add に合わせる）
	valid := JwtClaims{
		Nbf: now.Add(-clockSkew - 2*time.Second).Unix(),
		Exp: now.Add(clockSkew + 2*time.Second).Unix(),
	}
	if !HasValidLifetime(&valid, clockSkew) {
		t.Fatalf("expected valid period")
	}

	// nbf が未来（許容スキューを超えて未来）
	nbfTooFuture := JwtClaims{
		Nbf: now.Add(clockSkew + 2*time.Second).Unix(),
		Exp: now.Add(1000 * time.Second).Unix(),
	}
	if HasValidLifetime(&nbfTooFuture, clockSkew) {
		t.Fatalf("expected invalid due to nbf > now + skew")
	}

	// exp が過去（許容スキューを超えて過去）
	expTooPast := JwtClaims{
		Nbf: now.Add(-1000 * time.Second).Unix(),
		Exp: now.Add(-clockSkew - 2*time.Second).Unix(),
	}
	if HasValidLifetime(&expTooPast, clockSkew) {
		t.Fatalf("expected invalid due to exp <= now - skew")
	}
}

// ===== ここから追加テスト: Encrypt/Decrypt 系 =====

func TestEncryptDecrypt_NoAAD(t *testing.T) {
	e := newAESGCM(t)

	h := DefaultJwtHeader()
	now := time.Now().Unix()
	c := JwtClaims{
		Iss: "prism", Sub: "session", Aud: "browser",
		Iat: now, Nbf: now, Exp: now + 60, Jti: "jti-123",
		Usr: "role:user",
	}

	token, err := Encrypt(e, mustJSON(t, h), mustJSON(t, c))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// AAD なしトークンは 1 パート
	if strings.Count(token, ".") != 0 {
		t.Fatalf("expected 1-part token, got %q", token)
	}

	headerJSON, claimsJSON, err := Decrypt(e, token)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	hd, err := UnmarshalJwtHeader(headerJSON)
	if err != nil {
		t.Fatalf("UnmarshalJwtHeader: %v", err)
	}
	cd, err := UnmarshalJwtClaims(claimsJSON)
	if err != nil {
		t.Fatalf("UnmarshalJwtClaims: %v", err)
	}
	if hd.Alg != h.Alg || hd.Typ != h.Typ || hd.Cty != h.Cty {
		t.Fatalf("header mismatch: want=%+v got=%+v", h, hd)
	}
	if cd.Iss != c.Iss || cd.Sub != c.Sub || cd.Aud != c.Aud ||
		cd.Iat != c.Iat || cd.Nbf != c.Nbf || cd.Exp != c.Exp || cd.Jti != c.Jti {
		t.Fatalf("claims mismatch: want=%+v got=%+v", c, cd)
	}
}

func TestEncryptDecrypt_WithAAD(t *testing.T) {
	e := newAESGCM(t)

	h := DefaultJwtHeader()
	now := time.Now().Unix()
	c := JwtClaims{
		Iss: "prism", Sub: "session", Aud: "browser",
		Iat: now, Nbf: now, Exp: now + 60, Jti: "jti-456",
		Usr: "role:admin",
	}
	protected := []byte(`{"kid":"key-1","typ":"session"}`)

	token, err := EncryptWithAAD(e, mustJSON(t, h), mustJSON(t, c), protected)
	if err != nil {
		t.Fatalf("EncryptWithAAD: %v", err)
	}
	// AAD ありトークンは 2 パート
	if strings.Count(token, ".") != 1 {
		t.Fatalf("expected 2-part token, got %q", token)
	}

	headerJSON, claimsJSON, pj, err := DecryptWithAAD(e, token)
	if err != nil {
		t.Fatalf("DecryptWithAAD failed: %v", err)
	}
	if !bytes.Equal(pj, protected) {
		t.Fatalf("protected JSON mismatch: want=%s got=%s", protected, pj)
	}
	hd, err := UnmarshalJwtHeader(headerJSON)
	if err != nil {
		t.Fatalf("UnmarshalJwtHeader: %v", err)
	}
	cd, err := UnmarshalJwtClaims(claimsJSON)
	if err != nil {
		t.Fatalf("UnmarshalJwtClaims: %v", err)
	}
	if hd.Alg != h.Alg || hd.Typ != h.Typ || hd.Cty != h.Cty {
		t.Fatalf("header mismatch: want=%+v got=%+v", h, hd)
	}
	if cd.Iss != c.Iss || cd.Sub != c.Sub || cd.Aud != c.Aud ||
		cd.Iat != c.Iat || cd.Nbf != c.Nbf || cd.Exp != c.Exp || cd.Jti != c.Jti {
		t.Fatalf("claims mismatch: want=%+v got=%+v", c, cd)
	}
}

func TestDecryptWithAAD_FailsOnAADMismatch(t *testing.T) {
	e := newAESGCM(t)

	h := DefaultJwtHeader()
	now := time.Now().Unix()
	c := JwtClaims{Iss: "prism", Sub: "session", Aud: "browser", Iat: now, Nbf: now, Exp: now + 60}
	protected := []byte(`{"kid":"key-1"}`)

	token, err := EncryptWithAAD(e, mustJSON(t, h), mustJSON(t, c), protected)
	if err != nil {
		t.Fatalf("EncryptWithAAD: %v", err)
	}

	// AAD 部分（2 パート目）を1文字だけ改変
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		t.Fatalf("expected 2-part token")
	}
	aad := parts[1]
	if aad[len(aad)-1] == 'A' {
		parts[1] = aad[:len(aad)-1] + "B"
	} else {
		parts[1] = aad[:len(aad)-1] + "A"
	}
	tampered := strings.Join(parts, ".")

	if _, _, _, err := DecryptWithAAD(e, tampered); err == nil {
		t.Fatalf("DecryptWithAAD should fail on AAD mismatch")
	}
}

func TestDecrypt_FailsOnTamperedCiphertext(t *testing.T) {
	e := newAESGCM(t)

	h := DefaultJwtHeader()
	now := time.Now().Unix()
	c := JwtClaims{Iss: "prism", Sub: "session", Aud: "browser", Iat: now, Nbf: now, Exp: now + 60}

	token, err := Encrypt(e, mustJSON(t, h), mustJSON(t, c))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// 1 パート目（base64url(nonce||ct)）を改変（1 文字入れ替え）
	runes := []rune(token)
	runes[len(runes)/2] ^= 1
	tampered := string(runes)

	if _, _, err := Decrypt(e, tampered); err == nil {
		t.Fatalf("Decrypt should fail for tampered ciphertext")
	}
}

func TestDecryptWithAAD_InvalidFormats(t *testing.T) {
	e := newAESGCM(t)

	// 3 パート（不正）
	if _, _, _, err := DecryptWithAAD(e, "a.b.c"); err == nil {
		t.Fatalf("DecryptWithAAD should fail on 3-part token")
	}
	// 2 パート目が空（不正）
	if _, _, _, err := DecryptWithAAD(e, "a."); err == nil {
		t.Fatalf("DecryptWithAAD should fail on empty AAD part")
	}
}

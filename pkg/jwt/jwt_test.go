package jwt

import (
	"encoding/json"
	"reflect"
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

func TestMarshalAndUnmarshal(t *testing.T) {
	hdr := sampleHeader()
	cl := sampleClaims()

	hJSON, cJSON, err := Marshal(hdr, cl)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}

	hdr2, cl2, err := Unmarshal(hJSON, cJSON)
	if err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}

	if !reflect.DeepEqual(hdr, hdr2) {
		t.Fatalf("header mismatch: %#v != %#v", hdr, hdr2)
	}
	if !reflect.DeepEqual(cl, cl2) {
		t.Fatalf("claims mismatch: %#v != %#v", cl, cl2)
	}
}

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
			got := HasValidLifetime(&tt.claims, tt.clockSkew)
			if got != tt.want {
				t.Fatalf("HasValidLifetime() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSignAndVerify(t *testing.T) {
	signer := cipher.NewSignerHS256([]byte("secret"))
	hdr := sampleHeader()
	cl := sampleClaims()

	hJSON, cJSON, err := Marshal(hdr, cl)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}

	token := Sign(signer, hJSON, cJSON)
	hOut, cOut, err := Verify(signer, token)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}

	if !reflect.DeepEqual(hJSON, hOut) {
		t.Fatalf("header bytes mismatch")
	}
	if !reflect.DeepEqual(cJSON, cOut) {
		t.Fatalf("claims bytes mismatch")
	}

	tampered := token + "extra"
	if _, _, err := Verify(signer, tampered); err == nil {
		t.Fatalf("Verify expected error for tampered token")
	}

	if _, _, err := Verify(signer, "invalid"); err == nil {
		t.Fatalf("Verify expected error for malformed token")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	encrypter, err := cipher.NewEncrypterAESGCM(key)
	if err != nil {
		t.Fatalf("NewEncrypterAESGCM failed: %v", err)
	}

	hdr := sampleHeader()
	cl := sampleClaims()

	hJSON, cJSON, err := Marshal(hdr, cl)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}

	token, err := Encrypt(encrypter, hJSON, cJSON)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	hOut, cOut, err := Decrypt(encrypter, token)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !reflect.DeepEqual(hJSON, hOut) {
		t.Fatalf("header bytes mismatch")
	}
	if !reflect.DeepEqual(cJSON, cOut) {
		t.Fatalf("claims bytes mismatch")
	}

	aad := json.RawMessage(`{"scope":"read"}`)
	tokenAAD, err := EncryptWithAAD(encrypter, hJSON, cJSON, aad)
	if err != nil {
		t.Fatalf("EncryptWithAAD failed: %v", err)
	}

	hOut, cOut, aadOut, err := DecryptWithAAD(encrypter, tokenAAD)
	if err != nil {
		t.Fatalf("DecryptWithAAD failed: %v", err)
	}

	if !reflect.DeepEqual(hJSON, hOut) || !reflect.DeepEqual(cJSON, cOut) {
		t.Fatalf("decrypt with AAD mismatch")
	}
	if !reflect.DeepEqual([]byte(aad), aadOut) {
		t.Fatalf("AAD mismatch: got %s, want %s", string(aadOut), string(aad))
	}

	if _, _, _, err := DecryptWithAAD(encrypter, "invalid..token"); err == nil {
		t.Fatalf("DecryptWithAAD expected error on malformed token")
	}
}

func TestJwtStruct(t *testing.T) {
	signer := cipher.NewSignerHS256([]byte("secret"))
	key := []byte("0123456789abcdef0123456789abcdef")
	encrypter, err := cipher.NewEncrypterAESGCM(key)
	if err != nil {
		t.Fatalf("NewEncrypterAESGCM failed: %v", err)
	}

	original := &Jwt{}
	original.JwtHeader = *sampleHeader()
	original.JwtClaims = *sampleClaims()

	token, err := original.Sign(signer)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	var verified Jwt
	if err := verified.Verify(signer, token); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !reflect.DeepEqual(original.JwtHeader, verified.JwtHeader) {
		t.Fatalf("verified header mismatch")
	}
	if !reflect.DeepEqual(original.JwtClaims, verified.JwtClaims) {
		t.Fatalf("verified claims mismatch")
	}

	tokenEnc, err := original.Encrypt(encrypter)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	var decrypted Jwt
	if err := decrypted.Decrypt(encrypter, tokenEnc); err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !reflect.DeepEqual(original.JwtHeader, decrypted.JwtHeader) {
		t.Fatalf("decrypted header mismatch")
	}
	if !reflect.DeepEqual(original.JwtClaims, decrypted.JwtClaims) {
		t.Fatalf("decrypted claims mismatch")
	}

	aad := json.RawMessage(`{"tenant":"a"}`)
	tokenAAD, err := original.EncryptWithAAD(encrypter, aad)
	if err != nil {
		t.Fatalf("EncryptWithAAD failed: %v", err)
	}

	var decryptedAAD Jwt
	aadOut, err := decryptedAAD.DecryptWithAAD(encrypter, tokenAAD)
	if err != nil {
		t.Fatalf("DecryptWithAAD failed: %v", err)
	}
	if !reflect.DeepEqual(original.JwtHeader, decryptedAAD.JwtHeader) {
		t.Fatalf("DecryptWithAAD header mismatch")
	}
	if !reflect.DeepEqual(original.JwtClaims, decryptedAAD.JwtClaims) {
		t.Fatalf("DecryptWithAAD claims mismatch")
	}
	if !reflect.DeepEqual([]byte(aad), aadOut) {
		t.Fatalf("DecryptWithAAD AAD mismatch")
	}

	invalid := &Jwt{}
	if err := invalid.Unmarshal([]byte("not-json"), []byte("{}")); err == nil {
		t.Fatalf("Unmarshal expected error for invalid header JSON")
	}

	if err := invalid.Unmarshal([]byte("{}"), []byte("not-json")); err == nil {
		t.Fatalf("Unmarshal expected error for invalid claims JSON")
	}

	base := time.Unix(1700000000, 0)
	originalNow := nowFunc
	defer func() { nowFunc = originalNow }()
	nowFunc = func() time.Time { return base }

	claims := original.JwtClaims
	claims.Exp = base.Add(time.Minute).Unix()
	claims.Nbf = base.Add(-time.Minute).Unix()
	if !HasValidLifetime(&claims, 0) {
		t.Fatalf("HasValidLifetime expected true")
	}
}

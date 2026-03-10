package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/wsuzume/prism/pkg/cipher"
)

const (
	DefaultAlg = "HS256"
	DefaultCty = ""
	DefaultTyp = "JWT"
)

// ========================================================
// JWT (HS256) ユーティリティ
// ========================================================

func b64urlEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b) // padding なし
}

func b64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

type JwtHeader struct {
	Alg string `json:"alg"`           // 使用した署名アルゴリズム
	Cty string `json:"cty,omitempty"` // JWT を入れ子にする場合は "JWT" を指定、そうでない場合は空でよい
	Typ string `json:"typ"`           // "JWT" とすることが推奨されている
}

type JwtClaims struct {
	Iss string          `json:"iss"`           // トークン発行者の識別子
	Sub string          `json:"sub"`           // トークンの主題の識別子
	Aud string          `json:"aud"`           // トークンが意図している受信者の識別子
	Exp int64           `json:"exp"`           // トークンの有効期限。秒（UNIX time）。
	Nbf int64           `json:"nbf"`           // トークンの開始日時。秒。
	Iat int64           `json:"iat"`           // トークンの発行日時。秒。
	Jti string          `json:"jti"`           // 発行者ごとトークンごとに一意な識別子。
	Usr json.RawMessage `json:"usr,omitempty"` // ユーザー定義フィールド
}

func MarshalJwtHeader(header *JwtHeader) ([]byte, error) {
	h, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	return h, nil
}

func MarshalJwtClaims(claims *JwtClaims) ([]byte, error) {
	c, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func UnmarshalJwtHeader(headerJSON []byte) (*JwtHeader, error) {
	var header JwtHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, err
	}
	return &header, nil
}

func UnmarshalJwtClaims(claimsJSON []byte) (*JwtClaims, error) {
	var claims JwtClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, err
	}
	return &claims, nil
}

// テストを書きやすくするために差し替え可能にしてある
var nowFunc = time.Now

func (c *JwtClaims) HasValidLifetime(clockSkew time.Duration) bool {
	// time.Time 演算でクロックスキュー考慮（Seconds の丸め誤差回避）
	now := nowFunc()
	nowPlusSkew := now.Add(clockSkew).Unix()
	nowMinusSkew := now.Add(-clockSkew).Unix()

	// nbf: now+skew >= nbf
	if c.Nbf != 0 && nowPlusSkew < c.Nbf {
		return false
	}
	// exp: now-skew < exp
	if c.Exp != 0 && nowMinusSkew >= c.Exp {
		return false
	}
	return true
}

type Jwt struct {
	Header *JwtHeader
	Claims *JwtClaims
}

func (j *Jwt) HasValidLifetime(clockSkew time.Duration) bool {
	return j.Claims.HasValidLifetime(clockSkew)
}

func Sign(s cipher.Signer, jwt *Jwt) (string, error) {
	headerJSON, err := MarshalJwtHeader(jwt.Header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := MarshalJwtClaims(jwt.Claims)
	if err != nil {
		return "", err
	}

	headerB64 := b64urlEncode(headerJSON)
	claimsB64 := b64urlEncode(claimsJSON)
	unsignedToken := headerB64 + "." + claimsB64

	sig, err := s.Sign([]byte(unsignedToken))
	if err != nil {
		return "", err
	}
	sigB64 := b64urlEncode(sig)

	signedToken := unsignedToken + "." + sigB64
	return signedToken, nil
}

func Verify(s cipher.Signer, token string) (*Jwt, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	headerB64 := parts[0]
	claimsB64 := parts[1]
	sigB64 := parts[2]

	unsignedToken := headerB64 + "." + claimsB64

	sig, err := b64urlDecode(sigB64)
	if err != nil {
		return nil, err
	}

	ok, err := s.Verify([]byte(unsignedToken), sig)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("invalid token signature")
	}

	headerJSON, err := b64urlDecode(headerB64)
	if err != nil {
		return nil, err
	}
	claimsJSON, err := b64urlDecode(claimsB64)
	if err != nil {
		return nil, err
	}

	header, err := UnmarshalJwtHeader(headerJSON)
	if err != nil {
		return nil, err
	}
	claims, err := UnmarshalJwtClaims(claimsJSON)
	if err != nil {
		return nil, err
	}

	jwt := &Jwt{
		Header: header,
		Claims: claims,
	}
	return jwt, nil
}

func Encrypt(e cipher.Encrypter, jwt *Jwt) (string, error) {
	headerJSON, err := MarshalJwtHeader(jwt.Header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := MarshalJwtClaims(jwt.Claims)
	if err != nil {
		return "", err
	}

	headerB64 := b64urlEncode(headerJSON)
	claimsB64 := b64urlEncode(claimsJSON)
	plainToken := headerB64 + "." + claimsB64

	ciphertext, err := e.Encrypt([]byte(plainToken))
	if err != nil {
		return "", err
	}

	ciphertextB64 := b64urlEncode(ciphertext)
	return ciphertextB64, nil
}

func Decrypt(e cipher.Encrypter, token string) (*Jwt, error) {
	ciphertext, err := b64urlDecode(token)
	if err != nil {
		return nil, err
	}

	plainToken, err := e.Decrypt(ciphertext)
	if err != nil {
		return nil, err
	}

	parts := strings.SplitN(string(plainToken), ".", 2)
	if len(parts) != 2 {
		return nil, errors.New("invalid token format")
	}

	headerB64 := parts[0]
	claimsB64 := parts[1]

	headerJSON, err := b64urlDecode(headerB64)
	if err != nil {
		return nil, err
	}
	claimsJSON, err := b64urlDecode(claimsB64)
	if err != nil {
		return nil, err
	}

	header, err := UnmarshalJwtHeader(headerJSON)
	if err != nil {
		return nil, err
	}
	claims, err := UnmarshalJwtClaims(claimsJSON)
	if err != nil {
		return nil, err
	}

	jwt := &Jwt{
		Header: header,
		Claims: claims,
	}
	return jwt, nil
}

func EncryptWithAAD(e cipher.EncrypterAAD, jwt *Jwt, aad []byte) (string, error) {
	headerJSON, err := MarshalJwtHeader(jwt.Header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := MarshalJwtClaims(jwt.Claims)
	if err != nil {
		return "", err
	}

	headerB64 := b64urlEncode(headerJSON)
	claimsB64 := b64urlEncode(claimsJSON)
	plainToken := headerB64 + "." + claimsB64

	ciphertext, err := e.EncryptWithAAD([]byte(plainToken), aad)
	if err != nil {
		return "", err
	}

	ciphertextB64 := b64urlEncode(ciphertext)
	return ciphertextB64, nil
}

func DecryptWithAAD(e cipher.EncrypterAAD, token string, aad []byte) (*Jwt, error) {
	ciphertext, err := b64urlDecode(token)
	if err != nil {
		return nil, err
	}

	plainToken, err := e.DecryptWithAAD(ciphertext, aad)
	if err != nil {
		return nil, err
	}

	parts := strings.SplitN(string(plainToken), ".", 2)
	if len(parts) != 2 {
		return nil, errors.New("invalid token format")
	}

	headerB64 := parts[0]
	claimsB64 := parts[1]

	headerJSON, err := b64urlDecode(headerB64)
	if err != nil {
		return nil, err
	}
	claimsJSON, err := b64urlDecode(claimsB64)
	if err != nil {
		return nil, err
	}

	header, err := UnmarshalJwtHeader(headerJSON)
	if err != nil {
		return nil, err
	}
	claims, err := UnmarshalJwtClaims(claimsJSON)
	if err != nil {
		return nil, err
	}

	jwt := &Jwt{
		Header: header,
		Claims: claims,
	}
	return jwt, nil
}

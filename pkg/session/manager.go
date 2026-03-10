package session

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/wsuzume/prism/pkg/cipher"
	"github.com/wsuzume/prism/pkg/jwt"
)

type SessionManager struct {
	Iss string
	Aud string

	RefreshTTL time.Duration
	SessionTTL time.Duration
}

func NewSessionManager(iss string, aud string) *SessionManager {
	return &SessionManager{
		Iss: iss,
		Aud: aud,

		RefreshTTL: 24 * time.Hour,
		SessionTTL: 7 * 24 * time.Hour,
	}
}

func (sm *SessionManager) NewSecretJwt(s cipher.Algorithm, payload json.RawMessage) (*jwt.Jwt, error) {
	jti, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()

	header := &jwt.JwtHeader{
		Alg: s.Alg(),
		Cty: "JSON",
		Typ: "JWT",
	}
	claims := &jwt.JwtClaims{
		Iss: sm.Iss,
		Sub: "secret",
		Aud: sm.Aud,
		Exp: now + int64(sm.RefreshTTL.Seconds()),
		Nbf: now,
		Iat: now,
		Jti: jti.String(),
		Usr: payload,
	}
	return &jwt.Jwt{
		Header: header,
		Claims: claims,
	}, nil
}

func (sm *SessionManager) NewAccessJwt(s cipher.Algorithm, payload json.RawMessage) (*jwt.Jwt, error) {
	jti, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()

	header := &jwt.JwtHeader{
		Alg: s.Alg(),
		Cty: "JSON",
		Typ: "JWT",
	}
	claims := &jwt.JwtClaims{
		Iss: sm.Iss,
		Sub: "access",
		Aud: sm.Aud,
		Exp: now + int64(sm.RefreshTTL.Seconds()),
		Nbf: now,
		Iat: now,
		Jti: jti.String(),
		Usr: payload,
	}
	return &jwt.Jwt{
		Header: header,
		Claims: claims,
	}, nil
}

func (sm *SessionManager) NewSignedSecretToken(s cipher.Signer, secretPayload json.RawMessage) (string, error) {
	j, err := sm.NewSecretJwt(s, secretPayload)
	if err != nil {
		return "", err
	}

	return jwt.Sign(s, j)
}

// NewSignedAccessToken は署名付きアクセストークンを生成する。
// publicPayload は署名対象に含まれない。サーバー側はこの値を信頼せず、
// クライアントへの情報伝達のみに使用する。
func (sm *SessionManager) NewSignedAccessToken(s cipher.Signer, accessPayload, publicPayload json.RawMessage) (string, error) {
	j, err := sm.NewAccessJwt(s, accessPayload)
	if err != nil {
		return "", err
	}

	token, err := jwt.Sign(s, j)
	if err != nil {
		return "", err
	}

	pub := base64.RawURLEncoding.EncodeToString(publicPayload)

	return pub + "." + token, nil
}

func (sm *SessionManager) VerifySignedSecretToken(s cipher.Signer, token string) (*jwt.Jwt, error) {
	// Cookie想定の安全上限（必要なら調整）
	const maxTokenLen = 4096
	if token == "" || len(token) > maxTokenLen {
		return nil, errors.New("invalid token format")
	}

	return jwt.Verify(s, token)
}

func (sm *SessionManager) VerifySignedAccessToken(s cipher.Signer, token string) (*jwt.Jwt, json.RawMessage, error) {
	// Cookie想定の安全上限
	const maxTokenLen = 4096
	if token == "" {
		return nil, nil, errors.New("token is empty")
	}
	if len(token) > maxTokenLen {
		return nil, nil, errors.New("token exceeds maximum length")
	}

	// 末尾から3つ目のドット位置を探す
	// フォーマット: [public].[header].[claims].[signature]
	// 末尾から数えることで、publicパートに含まれる '.' による改ざんを防ぐ
	p := len(token)
	for range 3 {
		p = strings.LastIndex(token[:p], ".")
		if p < 0 {
			return nil, nil, errors.New("invalid token structure: insufficient separators")
		}
	}

	pub, err := base64.RawURLEncoding.DecodeString(token[:p])
	if err != nil {
		return nil, nil, err
	}

	// 署名されていないpublicパートを除去
	signed := token[p+1:]
	if signed == "" {
		return nil, nil, errors.New("signed portion is empty")
	}

	// 標準JWTとして検証 ([header].[claims].[signature])
	j, err := jwt.Verify(s, signed)
	if err != nil {
		return nil, nil, err
	}
	return j, pub, nil
}

func (sm *SessionManager) EncryptSecretToken(e cipher.Encrypter, secretPayload json.RawMessage) (string, error) {
	j, err := sm.NewSecretJwt(e, secretPayload)
	if err != nil {
		return "", err
	}

	return jwt.Encrypt(e, j)
}

func (sm *SessionManager) EncryptAccessToken(e cipher.EncrypterAAD, accessPayload, publicPayload json.RawMessage) (string, error) {
	j, err := sm.NewAccessJwt(e, accessPayload)
	if err != nil {
		return "", err
	}

	encrypted, err := jwt.EncryptWithAAD(e, j, publicPayload)
	if err != nil {
		return "", err
	}

	pub := base64.RawURLEncoding.EncodeToString(publicPayload)

	return pub + "." + encrypted, nil
}
func (sm *SessionManager) DecryptSecretToken(e cipher.Encrypter, token string) (*jwt.Jwt, error) {
	const maxTokenLen = 4096
	if token == "" || len(token) > maxTokenLen {
		return nil, errors.New("invalid token format")
	}

	return jwt.Decrypt(e, token)
}

func (sm *SessionManager) DecryptAccessToken(e cipher.EncrypterAAD, token string) (*jwt.Jwt, json.RawMessage, error) {
	const maxTokenLen = 4096
	if token == "" {
		return nil, nil, errors.New("token is empty")
	}
	if len(token) > maxTokenLen {
		return nil, nil, errors.New("token exceeds maximum length")
	}

	// 末尾からドット位置を探す
	// フォーマット: [public].[encrypted]
	// 末尾から数えることで、publicパートに含まれる '.' による改ざんを防ぐ
	p := strings.LastIndex(token, ".")
	if p < 0 {
		return nil, nil, errors.New("invalid token structure: insufficient separators")
	}

	publicPayload, err := base64.RawURLEncoding.DecodeString(token[:p])
	if err != nil {
		return nil, nil, err
	}

	encrypted := token[p+1:]
	if encrypted == "" {
		return nil, nil, errors.New("encrypted portion is empty")
	}

	j, err := jwt.DecryptWithAAD(e, encrypted, publicPayload)
	if err != nil {
		return nil, nil, err
	}

	return j, publicPayload, nil
}

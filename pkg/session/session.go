package session

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"prism/pkg/cipher"
	"prism/pkg/jwt"
)

const (
	//DefaultSecretDir  = "/var/lib/prism/secrets"
	//DefaultSecretFile = "session-hmac-secret" // Base64 テキスト（拡張子なし）

	jwtAlg      = "HS256"
	jwtCty      = ""
	jwtTyp      = "JWT"
	jwtIssuer   = "prism"
	jwtSubject  = "session"
	jwtAudience = "browser"

	sessionTTL    = 7 * 24 * time.Hour // 一般的な Web セッション相当（7日）
	clockSkew     = 2 * time.Minute    // 許容クロックスキュー
	notBeforeSkew = 0 * time.Second    // nbf = iat（スキューは検証側で吸収）

	sessionCookieName = "PRISM-SESSION-TOKEN"
	sessionHeaderName = "PRISM-SESSION"
)

type SessionManager struct {
	// Config
	SessionCookieName string
	SessionHeaderName string
	Signer            cipher.SignerInterface

	// Header
	JwtAlg string
	JwtCty string
	JwtTyp string

	// Claims
	JwtIssuer   string
	JwtSubject  string
	JwtAudience string

	SessionTTL    time.Duration
	ClockSkew     time.Duration
	NotBeforeSkew time.Duration
}

func DefaultSessionManager(s cipher.SignerInterface) *SessionManager {
	return &SessionManager{
		// Config
		SessionCookieName: sessionCookieName,
		SessionHeaderName: sessionHeaderName,
		Signer:            s,

		// Header
		JwtAlg: jwtAlg,
		JwtCty: jwtCty,
		JwtTyp: jwtTyp,

		// Claims
		JwtIssuer:   jwtIssuer,
		JwtSubject:  jwtSubject,
		JwtAudience: jwtAudience,

		SessionTTL:    sessionTTL,
		ClockSkew:     clockSkew,
		NotBeforeSkew: notBeforeSkew,
	}
}

func (sm *SessionManager) SignSessionToken(header jwt.JwtHeader, claims jwt.JwtClaims) (string, error) {
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return jwt.Sign(sm.Signer, hb, cb), nil
}

func (sm *SessionManager) NewSessionToken(usr string) (string, error) {
	now := time.Now()
	iat := now.Unix()
	nbf := now.Add(-sm.NotBeforeSkew).Unix()
	exp := now.Add(sm.SessionTTL).Unix()

	jtiV7, err := uuid.NewV7()
	if err != nil {
		return "", nil
	}

	hdr := jwt.JwtHeader{
		Alg: sm.JwtAlg,
		Typ: sm.JwtTyp,
	}

	cl := jwt.JwtClaims{
		Iss: sm.JwtIssuer,
		Sub: sm.JwtSubject,
		Aud: sm.JwtAudience,
		Exp: exp,
		Nbf: nbf,
		Iat: iat,
		Jti: jtiV7.String(),
		Usr: usr,
	}

	return sm.SignSessionToken(hdr, cl)
}

func (sm *SessionManager) VerifySessionToken(token string) (header, claims []byte, err error) {
	return jwt.Verify(sm.Signer, token)
}

// ========================================================
// ミドルウェア
// ========================================================

// RequireSessionToken は、PRISM-SESSION-TOKEN を JWT(HS256) で配布・検証します。
// - 既存が無い/壊れている/期限切れの場合は再発行（自己修復）
// - OPTIONS と ACME HTTP-01 は Set-Cookie しない（副作用なし）
// - Cookie 属性: Path=/, SameSite=Lax, Secure は HTTPS 時のみ, HttpOnly=false
func (sm *SessionManager) RequireSessionToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 攻撃用に送られてきた内部ヘッダーは記録する
		bh := c.Request.Header.Values(sm.SessionHeaderName) // []string
		if len(bh) > 0 {
			log.Printf(
				"session token spoofing detected: remote=%s uri=%s path=%s key=%s tokens=%s",
				c.ClientIP(),
				c.Request.RequestURI,
				c.FullPath(),
				sm.SessionHeaderName,
				strings.Join(bh, ","), // 全文をそのまま出力
			)
		}
		// 攻撃を検知したことがバレても困るので単に削除する
		c.Request.Header.Del(sm.SessionHeaderName)

		// CORS プリフライトは素通し（Set-Cookie なし）
		if c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}
		// ACME HTTP-01 は素通し（Set-Cookie なし）
		if strings.HasPrefix(c.Request.URL.Path, "/.well-known/acme-challenge/") {
			c.Next()
			return
		}

		// 既存トークン検証
		if existing, err := c.Cookie(sm.SessionCookieName); err == nil {
			if _, _, err := sm.VerifySessionToken(existing); err == nil {
				// キャッシュ分岐の安全策
				// これを設定しておくと CDN は Cookie が異なるリクエストを別物として扱うので
				// セッショントークンをキャッシュして複数のユーザーに同じ値を返してしまうことを防ぎ、
				// 逆に既にセッショントークンが設定されているユーザーに初回アクセスのキャッシュが返って
				// 再設定するようなレスポンスになってしまうことを防ぐ。
				c.Writer.Header().Add("Vary", "Cookie")
				c.Request.Header.Set(sm.SessionHeaderName, existing)
				c.Next()
				return
			}
			// 検証失敗/期限切れ時は再発行
		}

		// 新規発行
		token, err := sm.NewSessionToken("")
		if err != nil {
			// 生成失敗時は 500 を返して明示（必要に応じて挙動調整可）
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to issue session token"})
			return
		}

		c.Writer.Header().Add("Vary", "Cookie")
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     sm.SessionCookieName,
			Value:    token,
			Path:     "/",
			HttpOnly: false,                // JS から参照する想定
			Secure:   c.Request.TLS != nil, // HTTPS 時のみ Secure
			SameSite: http.SameSiteLaxMode,
		})

		c.Request.Header.Set(sm.SessionHeaderName, token)
		c.Next()
		return
	}
}

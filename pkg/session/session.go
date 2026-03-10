package session

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/wsuzume/prism/pkg/cipher"
	"github.com/wsuzume/prism/pkg/jwt"
	"github.com/wsuzume/prism/pkg/mode"
	//"github.com/wsuzume/prism/pkg/msg"
)

const (
	// tokens
	SecretTokenName = "PRISM-SECRET-TOKEN" // SecretCookie
	AccessTokenName = "PRISM-ACCESS-TOKEN" // AccessCookie
	SubmitTokenName = "PRISM-SUBMIT-TOKEN" // SubmitHeader

	// payloads
	SecretHeaderName = "PRISM-SECRET-HEADER" // secretPayload
	AccessHeaderName = "PRISM-ACCESS-HEADER" // accessPayload
	PublicHeaderName = "PRISM-PUBLIC-HEADER" // publicPayload
	NotifyHeaderName = "PRISM-NOTIFY-HEADER" // notifyPayload

	defaultClockSkew     = 1 * time.Minute
	defaultNotBeforeSkew = 0 * time.Second

	defaultRefreshTTL = 30 * 24 * time.Hour
	defaultSessionTTL = 7 * 24 * time.Hour

	defaultMaxAgeMargin = 24 * time.Hour
)

type CookieSession struct {
	// Cookie encryption
	Manager   *SessionManager
	Encrypter cipher.EncrypterAAD

	// tokens
	SecretTokenName string // SecretCookie
	AccessTokenName string // AccessCookie
	SubmitTokenName string // SubmitHeader

	// payloads
	SecretHeaderName string // secretPayload
	AccessHeaderName string // accessPayload
	PublicHeaderName string // publicPayload
	NotifyHeaderName string // notifyPayload

	Domain string

	// JwtClaims
	//ClockSkew     time.Duration
	//NotBeforeSkew time.Duration
	RefreshTTL time.Duration
	SessionTTL time.Duration

	// Cookie
	SecureCookie bool // デバッグ時は false にしてもよい
	MaxAgeMargin time.Duration
}

func DefaultCookieSession(sm *SessionManager, encrypter cipher.EncrypterAAD, domain string, secure bool) *CookieSession {
	return &CookieSession{
		Manager:         sm,
		Encrypter:       encrypter,
		SecretTokenName: SecretTokenName,
		AccessTokenName: AccessTokenName,
		SubmitTokenName: SubmitTokenName,

		SecretHeaderName: SecretHeaderName,
		AccessHeaderName: AccessHeaderName,
		PublicHeaderName: PublicHeaderName,
		NotifyHeaderName: NotifyHeaderName,

		Domain: domain,

		RefreshTTL: defaultRefreshTTL,
		SessionTTL: defaultSessionTTL,

		SecureCookie: secure,
		MaxAgeMargin: defaultMaxAgeMargin,
	}
}

func (s *CookieSession) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 安全のため Spoofing に使われうるヘッダーを削除する
		c.Request.Header.Del(s.SecretHeaderName)
		c.Request.Header.Del(s.AccessHeaderName)
		c.Request.Header.Del(s.PublicHeaderName)
		c.Request.Header.Del(s.NotifyHeaderName)

		// Cookie を読み取る
		// secretCookie, hasSecret := s.cookieValue(c.Request, s.SecretTokenName)
		// accessCookie, hasAccess := s.cookieValue(c.Request, s.AccessTokenName)

		c.Request.Header.Set(s.SecretHeaderName, "Secret")
		c.Request.Header.Set(s.AccessHeaderName, "Access")

		c.Next()
	}
}

func (s *CookieSession) newSecretCookie(value string) *http.Cookie {
	return &http.Cookie{
		Name:     s.SecretTokenName,
		Value:    value,
		MaxAge:   int((s.RefreshTTL + s.MaxAgeMargin).Seconds()),
		Path:     "/",
		Domain:   s.Domain, // e.g. ".wsuzu.me"
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		Secure:   s.SecureCookie,
	}
}

func (s *CookieSession) newAccessCookie(value string) *http.Cookie {
	return &http.Cookie{
		Name:     s.AccessTokenName,
		Value:    value,
		MaxAge:   int((s.SessionTTL + s.MaxAgeMargin).Seconds()),
		Path:     "/",
		Domain:   s.Domain, // e.g. ".wsuzu.me"
		SameSite: http.SameSiteLaxMode,
		HttpOnly: false,
		Secure:   s.SecureCookie,
	}
}

func (s *CookieSession) deleteSecretCookie() *http.Cookie {
	return &http.Cookie{
		Name:     s.SecretTokenName,
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Domain:   s.Domain, // e.g. ".wsuzu.me"
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		Secure:   s.SecureCookie,
	}
}

func (s *CookieSession) deleteAccessCookie() *http.Cookie {
	return &http.Cookie{
		Name:     s.AccessTokenName,
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Domain:   s.Domain, // e.g. ".wsuzu.me"
		SameSite: http.SameSiteLaxMode,
		HttpOnly: false,
		Secure:   s.SecureCookie,
	}
}

func cookieValue(req *http.Request, name string) (string, bool) {
	ck, err := req.Cookie(name)
	if err != nil || ck == nil || ck.Value == "" {
		return "", false
	}
	return ck.Value, true
}

func (s *CookieSession) tokensFromCookies(req *http.Request) (string, string, error) {
	if req == nil {
		return "", "", errors.New("request is nil")
	}

	secretValue, hasSecret := cookieValue(req, s.SecretTokenName)
	accessValue, hasAccess := cookieValue(req, s.AccessTokenName)

	if hasSecret != hasAccess {
		return "", "", errors.New("cookie is broken")
	}
	if !hasSecret {
		return "", "", errors.New("no cookies in the context")
	}

	// secretToken, err := p.decryptToken(secretValue)
	// if err != nil {
	// 	return nil, nil, err
	// }
	// accessToken, err := p.decryptToken(accessValue)
	// if err != nil {
	// 	return nil, nil, err
	// }
	return secretValue, accessValue, nil
}

func (s *CookieSession) NewSecretJwt() *jwt.Jwt {
	return &jwt.Jwt{}
}

func (s *CookieSession) ModifyResponse(orig func(*http.Response) error) func(*http.Response) error {
	return func(resp *http.Response) error {
		if orig != nil {
			if err := orig(resp); err != nil {
				return err
			}
		}

		// レスポンスから Cookie にセットしたい内容を取得する（JSON形式を想定）
		secretPayload := json.RawMessage(resp.Header.Get(s.SecretHeaderName))
		accessPayload := json.RawMessage(resp.Header.Get(s.AccessHeaderName))
		publicPayload := json.RawMessage(resp.Header.Get(s.PublicHeaderName))

		// レスポンスヘッダからペイロードを削除（消し忘れがないよう読み取ったらすぐに削除）
		resp.Header.Del(s.SecretHeaderName)
		resp.Header.Del(s.AccessHeaderName)
		resp.Header.Del(s.PublicHeaderName)
		resp.Header.Del(s.NotifyHeaderName)

		if len(secretPayload) != 0 && len(accessPayload) != 0 {
			// 古い Cookie を削除
			// deleteSecretCookie := s.deleteSecretCookie().String()
			// deleteAccessCookie := s.deleteAccessCookie().String()
			// resp.Header.Add("Set-Cookie", deleteSecretCookie)
			// resp.Header.Add("Set-Cookie", deleteAccessCookie)

			// TODO: JWT を構築する
			sm := NewSessionManager("PRISM", "FLITLEAP")

			secretToken, err := sm.EncryptSecretToken(s.Encrypter, secretPayload)
			if err != nil {
				return err
			}

			accessToken, err := sm.EncryptAccessToken(s.Encrypter, accessPayload, publicPayload)
			if err != nil {
				return err
			}

			secretCookie := s.newSecretCookie(secretToken).String()
			accessCookie := s.newAccessCookie(accessToken).String()

			// デバッグログを追加
			log.Printf("SecretCookie String: %s", secretCookie)
			log.Printf("AccessCookie String: %s", accessCookie)

			resp.Header.Add("Set-Cookie", secretCookie)
			resp.Header.Add("Set-Cookie", accessCookie)

			if mode.Debug {
				log.Printf("UpdateSecretCookie: %s\n", secretCookie)
				log.Printf("UpdateAccessCookie: %s\n", accessCookie)
			}

			return nil
		}

		secretToken, accessToken, err := s.tokensFromCookies(resp.Request)
		if err == nil {
			log.Printf("SecretCookieInContext: %s\n", secretToken)
			log.Printf("AccessCookieInContext: %s\n", accessToken)
			return nil
		}

		secretCookie := s.newSecretCookie("SecretNotLoggedIn").String()
		accessCookie := s.newAccessCookie("AccessNotLoggedIn").String()

		resp.Header.Add("Set-Cookie", secretCookie)
		resp.Header.Add("Set-Cookie", accessCookie)

		if mode.Debug {
			log.Printf("SecretCookie: %s\n", secretCookie)
			log.Printf("AccessCookie: %s\n", accessCookie)
		}

		return nil
	}
}

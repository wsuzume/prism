package session

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/wsuzume/prism/pkg/cipher"
	"github.com/wsuzume/prism/pkg/jwt"
	"github.com/wsuzume/prism/pkg/mode"
	//"github.com/wsuzume/prism/pkg/msg"
)

// Prism のセッション管理においては、リクエストの認証状態は以下のように分類される。
// 【1. 状態】
//   シークレットトークンを持たないか、シークレットトークンが破損している状態。
//   アクセストークンの正当性を検証することができないため、持っていたとしても破棄して再発行すべきである。
//   CSRF攻撃などのリスクがあるため、基本的な方針としては、ごく限られた安全なエンドポイント以外へのアクセスは拒否すべきである。
//     - Firewall オプションが無効な場合、すべてのリクエストをバックエンドへ通過させる（正当性の識別のみを行う）。
//     - Firewall オプションが有効な場合、GET, HEAD, OPTIONS といった安全なエンドポイント以外へのアクセスは拒否する。
//     - Firewall オプションが有効で、AllowAPIKey オプションも有効な場合、APIキーを検査して有効ならばアクセスを許可する。
// 【2. 状態】
//   シークレットトークンは持っているが、アクセストークンを持たないか、アクセストークンが破損している状態。
//   アクセストークンとサブミットトークンを用いたダブルサブミットクッキーによるCSRF防御ができないため、CSRF攻撃などのリスクがある。
//   基本的な方針として、Prism はシークレットトークンをリフレッシュトークンとして使用し、アクセストークンの復旧を試みる。
//     - AutoRefresh オプションが無効な場合、Prism はシークレットトークンとアクセストークンの両方を未認証状態で再発行する。
//     - AutoRefresh オプションが有効な場合、Prism はシークレットトークンからアクセストークンの復旧を試みる。
//     - Firewall オプションが無効な場合、すべてのリクエストをバックエンドへ通過させる（正当性の識別のみを行う）。
//     - Firewall オプションが有効な場合、GET, HEAD, OPTIONS といった安全なエンドポイント以外へのアクセスは拒否する。
//     - Firewall オプションが有効で、AllowAPIKey オプションも有効な場合、APIキーを検査して有効ならばアクセスを許可する。
// 【3. 状態】
//   シークレットトークンとアクセストークンの両方を持っていて、どちらのトークンも有効である状態。
//   認証されたセッションであるとみなすことができるが、CSRF攻撃の場合でもこの状態になる可能性があるため、
//   安全なエンドポイント以外へのアクセスは拒否すべきである。
//   基本的な方針として、どの程度のアクセスを許容するかの判断はバックエンドに委ねる。
//     - Firewall オプションが無効な場合、すべてのリクエストをバックエンドへ通過させる（正当性の識別のみを行う）。
//     - Firewall オプションが有効な場合、GET, HEAD, OPTIONS といった安全なエンドポイント以外へのアクセスは拒否する。
//     - Firewall オプションが有効で、AllowAPIKey オプションも有効な場合、APIキーを検査して有効ならばアクセスを許可する。
// 【4. 状態】
//   シークレットトークンとアクセストークンの両方を持っていて、どちらのトークンも有効であり、
//   さらにサブミットトークンもアクセストークンと一致している状態。
//   CSRF攻撃の可能性が排除された、認証されたセッションであるとみなすことができる。
//   基本的な方針として、どの程度のアクセスを許容するかの判断はバックエンドに委ねる。
//     - Firewall オプションの有効・無効に関わらず、すべてのリクエストをバックエンドへ通過させる（正当性の識別は行う）。
//     - Firewall オプションが有効で、AllowAPIKey オプションも有効な場合、APIキーを検査して有効ならばアクセスを許可する。
// 
// 上記は以下の処理にまとめられる。
//   - シークレットトークンとアクセストークンの有効性を検証する。
//     - シークレットトークンが無効である場合は、シークレットトークンとアクセストークンを再発行する
//     - シークレットトークンが有効で、アクセストークンが不正である場合は、AutoRefresh オプションに応じてアクセストークンを再発行する
//     - どちらも有効である場合は、アクセストークンとサブミットトークンの一致も確認する
//   - Firewall オプションに応じて、アクセスを許可するかどうか判断する
//     - Firewall が拒否した場合でも、APIキーを許可する設定でAPIキーが有効であればアクセスを許可する

type pendingCookiesKey struct{}

type pendingCookies struct {
	SecretToken string // 空の場合はセットしない
	AccessToken string // 空の場合はセットしない
}

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

	// Block requests without valid cookies (e.g. API clients, CSRF attacks, etc.)
	Firewall bool
	AllowAPIKey bool // ignored if Firewall is false
	AutoRefresh bool // ignored if Firewall is false, as a result, sessions are not automatically refreshed by default

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

		Firewall: false,
		AllowAPIKey: true, // ignored if Firewall is false, as a result, API clients are allowed by default

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

func (s *CookieSession) EncryptSecretToken(jti uuid.UUID, now time.Time, secretPayload json.RawMessage) (string, error) {
	return s.Manager.EncryptSecretToken(s.Encrypter, jti, now, secretPayload)
}

func (s *CookieSession) EncryptAccessToken(jti uuid.UUID, now time.Time, accessPayload, publicPayload json.RawMessage) (string, error) {
	return s.Manager.EncryptAccessToken(s.Encrypter, jti, now, accessPayload, publicPayload)
}

func (s *CookieSession) DecryptSecretToken(secretCookie string) (*jwt.Jwt, error) {
	return s.Manager.DecryptSecretToken(s.Encrypter, secretCookie)
}

func (s *CookieSession) DecryptAccessToken(accessCookie string) (*jwt.Jwt, json.RawMessage, error) {
	return s.Manager.DecryptAccessToken(s.Encrypter, accessCookie)
}

func cookieValue(req *http.Request, name string) (string, bool) {
	ck, err := req.Cookie(name)
	if err != nil || ck == nil || ck.Value == "" {
		return "", false
	}
	return ck.Value, true
}

func (s *CookieSession) ValidateSecretToken(req *http.Request) (string, *jwt.Jwt, *SecretPayload, error) {
	secret, hasSecret := cookieValue(req, s.SecretTokenName)
	if !hasSecret {
		return "", nil, nil, errors.New("secret token not found in cookies")
	}
	jwt, err := s.DecryptSecretToken(secret)
	if err != nil {
		return "", nil, nil, err
	}
	secretPayload, err := SecretPayloadFromJson([]byte(jwt.Claims.Usr))
	if err != nil {
		return "", nil, nil, err
	}
	return secret, jwt, secretPayload, nil
}

func (s *CookieSession) ValidateAccessToken(req *http.Request, secretJwt *jwt.Jwt) (string, *jwt.Jwt, error) {
	access, hasAccess := cookieValue(req, s.AccessTokenName)
	if !hasAccess {
		return "", nil, errors.New("access token not found in cookies")
	}
	jwt, _, err := s.DecryptAccessToken(access)
	if err != nil {
		return "", nil, err
	}
	if secretJwt == nil || jwt == nil {
		return "", nil, errors.New("secret JWT or access JWT is nil")
	}
	if subtle.ConstantTimeCompare([]byte(secretJwt.Claims.Jti), []byte(jwt.Claims.Jti)) != 1 {
		return "", nil, errors.New("JWT ID (SessionID) does not match between secret JWT and access JWT")
	}
	return access, jwt, nil
}

func (s *CookieSession) ValidateSubmitToken(req *http.Request, accessToken string) (string, error, error) {
	submit := req.Header.Get(s.SubmitTokenName)
	if submit == "" {
		return "", errors.New("submit token not found in headers"), nil
	}
	if subtle.ConstantTimeCompare([]byte(submit), []byte(accessToken)) != 1 {
		return "", nil, errors.New("submit token does not match access token")
	}
	return submit, nil, nil
}

func (s *CookieSession) NewSecretJwt(jti uuid.UUID, now time.Time, secretPayload json.RawMessage) (string, error) {
	secretJwt := s.Manager.NewSecretJwt(s.Encrypter, jti, now, secretPayload)
	return jwt.Encrypt(s.Encrypter, secretJwt)
}

func (s *CookieSession) NewAccessJwt(jti uuid.UUID, now time.Time, accessPayload, publicPayload json.RawMessage) (string, error) {
	return s.Manager.EncryptAccessToken(s.Encrypter, jti, now, accessPayload, publicPayload)
}

func (s *CookieSession) SetSecretCookie(c *gin.Context, value string) {
	c.SetCookie(
		s.SecretTokenName, // name
		value,             // value
		int((s.RefreshTTL + s.MaxAgeMargin).Seconds()), // maxAge
		"/",            // path
		s.Domain,       // domain
		s.SecureCookie, // secure
		true,           // httpOnly
	)
}

func (s *CookieSession) SetAccessCookie(c *gin.Context, value string) {
	c.SetCookie(
		s.AccessTokenName,
		value,
		int((s.SessionTTL + s.MaxAgeMargin).Seconds()),
		"/",
		s.Domain,
		s.SecureCookie,
		false,
	)
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

func isSafeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

func NewUnauthorizedSecretPayload() *SecretPayload {
	return &SecretPayload{
		Authorized:    false,
		Authenticated: false,
		AgentVerified: false,
		AgentType:     "",
		SessionID:     "",
		UserID:        "",
	}
}

func (s *CookieSession) handleUntrustedRequest(c *gin.Context) {
	// シークレットトークンが無効である場合
	if s.Firewall && !isSafeMethod(c.Request.Method) {
		// ファイアウォールが有効なら安全でないエンドポイントへのアクセスは拒否する
		if !s.AllowAPIKey {
			c.AbortWithStatus(http.StatusForbidden)
			return
		} else {
			// TODO: APIキーを検査して許可するかどうか決めるロジックを実装する
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
	}
	
	// ファイアウォールが無効か、安全なエンドポイントの場合は、
	// 有効なシークレットトークンとアクセストークンを発行する
	now := time.Now()
	jti, err := uuid.NewV7()
	if err != nil {
		log.Printf("Failed to generate new UUID for session: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	secretPayload := NewUnauthorizedSecretPayload()
	accessPayload := BuildAccessPayload(secretPayload)
	publicPayload := BuildPublicPayload(secretPayload)
	notifyPayload := BuildNotifyPayload(secretPayload)

	secretPayloadJson, errS := json.Marshal(secretPayload)
	accessPayloadJson, errA := json.Marshal(accessPayload)
	publicPayloadJson, errP := json.Marshal(publicPayload)
	notifyPayloadJson, errN := json.Marshal(notifyPayload)
	if errS != nil || errA != nil || errP != nil || errN != nil {
		log.Printf("Failed to marshal unauthorized payloads: %v, %v, %v, %v", errS, errA, errP, errN)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	newSecret, errS := s.NewSecretJwt(jti, now, secretPayloadJson)
	newAccess, errA := s.NewAccessJwt(jti, now, accessPayloadJson, publicPayloadJson)
	if errS != nil || errA != nil {
		log.Printf("Failed to generate new tokens for session: %v, %v", errS, errA)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// ModifyResponse でクッキーをセットするためにコンテキストへ渡す
	ctx := context.WithValue(c.Request.Context(), pendingCookiesKey{}, &pendingCookies{
		SecretToken: newSecret,
		AccessToken: newAccess,
	})
	c.Request = c.Request.WithContext(ctx)

	// レスポンスヘッダにペイロードをセットする
	c.Request.Header.Set(s.SecretHeaderName, string(secretPayloadJson))
	c.Request.Header.Set(s.AccessHeaderName, string(accessPayloadJson))
	c.Request.Header.Set(s.PublicHeaderName, string(publicPayloadJson))
	c.Request.Header.Set(s.NotifyHeaderName, string(notifyPayloadJson))

	c.Next()
}

func (s *CookieSession) handleUntrustedRequestAutoRefresh(c *gin.Context, secretJwt *jwt.Jwt, secretPayload *SecretPayload) {
	// シークレットトークンが無効である場合
	if s.Firewall && !isSafeMethod(c.Request.Method) {
		// ファイアウォールが有効なら安全でないエンドポイントへのアクセスは拒否する
		if !s.AllowAPIKey {
			c.AbortWithStatus(http.StatusForbidden)
			return
		} else {
			// TODO: APIキーを検査して許可するかどうか決めるロジックを実装する
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
	}
	
	// ファイアウォールが無効か、安全なエンドポイントの場合は、
	// 有効なシークレットトークンからアクセストークンの再発行を試みる
	// TODO: 有効期限を確認して更新する
	now := secretJwt.Claims.Iat
	jti := secretJwt.Claims.Jti

	accessPayload := BuildAccessPayload(secretPayload)
	publicPayload := BuildPublicPayload(secretPayload)
	notifyPayload := BuildNotifyPayload(secretPayload)

	secretPayloadJson, errS := json.Marshal(secretPayload)
	accessPayloadJson, errA := json.Marshal(accessPayload)
	publicPayloadJson, errP := json.Marshal(publicPayload)
	notifyPayloadJson, errN := json.Marshal(notifyPayload)
	if errS != nil || errA != nil || errP != nil || errN != nil {
		log.Printf("Failed to marshal unauthorized payloads: %v, %v, %v, %v", errS, errA, errP, errN)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	jtiUUID, errJ := uuid.Parse(jti)
	if errJ != nil {
		log.Printf("Failed to parse jti as UUID: %v", errJ)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	newAccess, errA := s.NewAccessJwt(jtiUUID, time.Unix(now, 0), accessPayloadJson, publicPayloadJson)
	if errA != nil {
		log.Printf("Failed to generate new tokens for session: %v", errA)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// ModifyResponse でクッキーをセットするためにコンテキストへ渡す
	ctx := context.WithValue(c.Request.Context(), pendingCookiesKey{}, &pendingCookies{
		AccessToken: newAccess,
	})
	c.Request = c.Request.WithContext(ctx)

	// レスポンスヘッダにペイロードをセットする
	c.Request.Header.Set(s.SecretHeaderName, string(secretPayloadJson))
	c.Request.Header.Set(s.AccessHeaderName, string(accessPayloadJson))
	c.Request.Header.Set(s.PublicHeaderName, string(publicPayloadJson))
	c.Request.Header.Set(s.NotifyHeaderName, string(notifyPayloadJson))

	c.Next()
}

func (s *CookieSession) handleUntrustedRequestPassThrough(c *gin.Context, secretPayload *SecretPayload) {
	// シークレットトークンが無効である場合
	if s.Firewall && !isSafeMethod(c.Request.Method) {
		// ファイアウォールが有効なら安全でないエンドポイントへのアクセスは拒否する
		if !s.AllowAPIKey {
			c.AbortWithStatus(http.StatusForbidden)
			return
		} else {
			// TODO: APIキーを検査して許可するかどうか決めるロジックを実装する
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
	}

	accessPayload := BuildAccessPayload(secretPayload)
	publicPayload := BuildPublicPayload(secretPayload)
	notifyPayload := BuildNotifyPayload(secretPayload)

	secretPayloadJson, errS := json.Marshal(secretPayload)
	accessPayloadJson, errA := json.Marshal(accessPayload)
	publicPayloadJson, errP := json.Marshal(publicPayload)
	notifyPayloadJson, errN := json.Marshal(notifyPayload)
	if errS != nil || errA != nil || errP != nil || errN != nil {
		log.Printf("Failed to marshal unauthorized payloads: %v, %v, %v, %v", errS, errA, errP, errN)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// レスポンスヘッダにペイロードをセットする
	c.Request.Header.Set(s.SecretHeaderName, string(secretPayloadJson))
	c.Request.Header.Set(s.AccessHeaderName, string(accessPayloadJson))
	c.Request.Header.Set(s.PublicHeaderName, string(publicPayloadJson))
	c.Request.Header.Set(s.NotifyHeaderName, string(notifyPayloadJson))

	c.Next()
}

func (s *CookieSession) handleTrustedRequest(c *gin.Context, secretPayload *SecretPayload) {
	accessPayload := BuildAccessPayload(secretPayload)
	publicPayload := BuildPublicPayload(secretPayload)
	notifyPayload := BuildNotifyPayload(secretPayload)

	secretPayloadJson, errS := json.Marshal(secretPayload)
	accessPayloadJson, errA := json.Marshal(accessPayload)
	publicPayloadJson, errP := json.Marshal(publicPayload)
	notifyPayloadJson, errN := json.Marshal(notifyPayload)
	if errS != nil || errA != nil || errP != nil || errN != nil {
		log.Printf("Failed to marshal unauthorized payloads: %v, %v, %v, %v", errS, errA, errP, errN)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// レスポンスヘッダにペイロードをセットする
	c.Request.Header.Set(s.SecretHeaderName, string(secretPayloadJson))
	c.Request.Header.Set(s.AccessHeaderName, string(accessPayloadJson))
	c.Request.Header.Set(s.PublicHeaderName, string(publicPayloadJson))
	c.Request.Header.Set(s.NotifyHeaderName, string(notifyPayloadJson))

	c.Next()
}

func (s *CookieSession) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 安全のため Spoofing に使われうるヘッダーを削除する
		c.Request.Header.Del(s.SecretHeaderName)
		c.Request.Header.Del(s.AccessHeaderName)
		c.Request.Header.Del(s.PublicHeaderName)
		c.Request.Header.Del(s.NotifyHeaderName)

		// チェックしたいのは以下の３つ
		//  1. シークレットトークンが存在して、正しく復号できること
		//  2. アクセストークンが存在して、正しく復号できること
		//  3. サブミットトークンが存在して、アクセストークンと一致すること

		// Cookie を読み取る
		_, secretJwt, secretPayload, errSecret := s.ValidateSecretToken(c.Request)
		if errSecret != nil {
			// シークレットトークンが無効である場合は、シークレットトークンとアクセストークンを再発行する
			s.handleUntrustedRequest(c)
			return
		}
		
		access, _, errAccess := s.ValidateAccessToken(c.Request, secretJwt)
		if errAccess != nil {
			// シークレットトークンが有効で、アクセストークンが不正である場合は、AutoRefresh オプションに応じてアクセストークンを再発行する
			if !s.AutoRefresh {
				// AutoRefresh が無効な場合は、シークレットトークンとアクセストークンの両方を未認証状態で再発行する
				s.handleUntrustedRequest(c)
				return
			} else {
				// AutoRefresh が有効な場合は、シークレットトークンからアクセストークンの復旧を試みる
				s.handleUntrustedRequestAutoRefresh(c, secretJwt, secretPayload)
				return
			}
		}
		
		_, errSubmit, errCompare := s.ValidateSubmitToken(c.Request, access)
		// どちらも有効であり、サブミットトークンが存在しない場合は安全なエンドポイントへのアクセスのみ許可する
		if errSubmit != nil {
			s.handleUntrustedRequestPassThrough(c, secretPayload)
			return
		}

		// どちらも有効であり、サブミットトークンが存在する場合は、アクセストークンとの一致も確認する
		if errCompare != nil {
			// サブミットトークンがアクセストークンと一致しない場合は、CSRF攻撃の可能性があるため、アクセスを拒否する
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		
		// どちらも有効であり、サブミットトークンも一致する場合は、CSRF攻撃の可能性が排除された、正規のリクエストとみなす
		s.handleTrustedRequest(c, secretPayload)
		return
	}
}

func (s *CookieSession) ModifyResponse(orig func(*http.Response) error) func(*http.Response) error {
	return func(resp *http.Response) error {
		// TODO: ログアウト機能の実装

		if orig != nil {
			if err := orig(resp); err != nil {
				return err
			}
		}

		// ペイロードヘッダを読み取ってから削除する（クライアントには返さない）
		secretPayloadJson := resp.Header.Get(s.SecretHeaderName)
		resp.Header.Del(s.SecretHeaderName)
		resp.Header.Del(s.AccessHeaderName)
		resp.Header.Del(s.PublicHeaderName)
		resp.Header.Del(s.NotifyHeaderName)

		if secretPayloadJson != "" {
			now := time.Now()
			jti, err := uuid.NewV7()
			if err != nil {
				log.Printf("Failed to generate new UUID for session: %v", err)
				return err
			}

			// バックエンド（ログイン認証サーバー）からのレスポンスを優先してクッキーを発行する
			secretPayload, err := SecretPayloadFromJson([]byte(secretPayloadJson))
			if err != nil {
				log.Printf("Failed to parse secret payload: %v", err)
				return err
			}
			accessPayload := BuildAccessPayload(secretPayload)
			publicPayload := BuildPublicPayload(secretPayload)

			accessPayloadJson, errA := json.Marshal(accessPayload)
			publicPayloadJson, errP := json.Marshal(publicPayload)
			if errA != nil || errP != nil {
				marshalErr := errors.Join(errA, errP)
 				log.Printf("Failed to marshal payloads for response modification: %v", marshalErr)
 				return marshalErr
			}

			secretToken, errS := s.NewSecretJwt(jti, now, []byte(secretPayloadJson))
			accessToken, errA := s.NewAccessJwt(jti, now, accessPayloadJson, publicPayloadJson)
			if errS != nil {
				log.Printf("Failed to generate new secret JWT: %v", errS)
				return errS
			}
			if errA != nil {
				log.Printf("Failed to generate new access JWT: %v", errA)
				return errA
			}

			secretCookie := s.newSecretCookie(secretToken).String()
			accessCookie := s.newAccessCookie(accessToken).String()

			resp.Header.Add("Set-Cookie", secretCookie)
			resp.Header.Add("Set-Cookie", accessCookie)

			if mode.Debug {
				log.Printf("SecretCookie: %s\n", secretCookie)
				log.Printf("AccessCookie: %s\n", accessCookie)
				log.Printf("accessPayloadJson: %s\n", accessPayloadJson)
				log.Printf("publicPayloadJson: %s\n", publicPayloadJson)
			}

			return nil
		}

		// バックエンドからの指示がない場合は、Middleware がコンテキストに詰めたトークンでクッキーを発行する
		pending, ok := resp.Request.Context().Value(pendingCookiesKey{}).(*pendingCookies)
		if !ok || pending == nil {
			return nil
		}

		if pending.SecretToken != "" {
			secretCookie := s.newSecretCookie(pending.SecretToken).String()
			resp.Header.Add("Set-Cookie", secretCookie)
			if mode.Debug {
				log.Printf("SecretCookie: %s\n", secretCookie)
			}
		}
		if pending.AccessToken != "" {
			accessCookie := s.newAccessCookie(pending.AccessToken).String()
			resp.Header.Add("Set-Cookie", accessCookie)
			if mode.Debug {
				log.Printf("AccessCookie: %s\n", accessCookie)
			}
		}

		return nil
	}
}

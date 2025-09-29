package csrf

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"prism/pkg/cipher"
	"prism/pkg/jwt"
	"prism/proxy/msg"
)

//
// ──────────────────────────────────────────────────────────────────────────────
//  Basic CSRF (Origin/Referer) Protection
// ──────────────────────────────────────────────────────────────────────────────
//

type BasicCSRFProtector struct {
	Debug          bool
	AllowedOrigins []*url.URL
}

func NewBasicCSRFProtector(allowedOrigins []string) (*BasicCSRFProtector, error) {
	// allowedOrigins を事前パースしてキャッシュ（無効値はエラー）
	parsed := make([]*url.URL, 0, len(allowedOrigins))
	for _, ao := range allowedOrigins {
		aou, err := url.Parse(ao)
		if err != nil {
			log.Printf("invalid allowed origin: %q: %v", ao, err)
			return nil, err
		}
		parsed = append(parsed, aou)
	}

	return &BasicCSRFProtector{
		AllowedOrigins: parsed,
	}, nil
}

// BasicCSRFProtection checks Origin/Referer headers against allowed origins.
// Skips validation if request is over plain HTTP (debug environment).
func (p *BasicCSRFProtector) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// デバッグ環境（HTTP公開）ならスキップ
		if p.Debug {
			c.Next()
			return
		}

		origin := c.Request.Header.Get("Origin")
		if origin == "" {
			// Fallback to Referer if Origin is not present
			origin = c.Request.Header.Get("Referer")
		}

		if origin == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": msg.MissingOriginAndRefererHeader,
			})
			return
		}

		// オリジンチェック
		allowed := false
		u, err := url.Parse(origin)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": msg.InvalidFormatOrigin,
			})
			return
		}
		for _, aou := range p.AllowedOrigins {
			if u.Scheme == aou.Scheme && u.Host == aou.Host {
				allowed = true
				break
			}
		}

		if !allowed {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": msg.InvalidOrigin,
			})
			return
		}

		c.Next()
	}
}

//
// ──────────────────────────────────────────────────────────────────────────────
//  Double-Submit Cookie (AES-GCM 暗号化付き)
// ──────────────────────────────────────────────────────────────────────────────
//

// PRISM の Double-Submit Cookie は独自に拡張した JWT である AES-GCM JWT を用いる。
// 将来的な拡張を見込んで暗号化アルゴリズムは AAD が使えるアルゴリズムであればなんでも使えるようになっている。
// クライアントには以下の２種類のトークンが保存される。
//   - SecretCookie ... HttpOnly: true
//   - AccessCookie ... HttpOnly: false
// クライアントはサーバーの状態を変更しうるリクエストを投げる場合、
// AccessCookie を JavaScript から読み取り、リクエストヘッダーに SubmitHeader として付与する。
// CSRF ではヘッダーを書き換えることができないため、PRISM は SecretCookie と SubmitHeader の中にある
// トークンIDを比較することで正規の処理であることを検証できる。
// XSS は防ぐことができないが、これは他の CSRF 対策と変わらない。
// PRISM の SecretCookie, AccessCookie に用いられる AES-GCM JWT のフォーマットは以下である。
//
// --- SecretCookie ---
//   base64url(AES-GCM([ base64url(json(JwtHeader)) ] . [ base64url(json(JwtClaims{base64url(secretPayload)})) ]))
//
// --- AccessCookie ---
//   base64url(AES-GCM([ base64url(json(JwtHeader)) ] . [ base64url(json(JwtClaims{base64url(accessPayload)})) ])) . [ base64url(publicPayload) ]
//
// 仕様の詳細は以下である。
//   - AES-GCM JWT の JwtHeader, JwtClaims は JSON -> base64url でエンコードされ、"." で結合されたのち全体が AES-GCM で暗号化され、base64url で再エンコードされる。
//   - AES-GCM JWT は全体が AES-GCM で暗号化される際、AAD を付加してよい。付加した AAD は AES-GCM -> base64url で暗号化された文字列に、"." で結合して付加する。
//   - secretPayload, accessPayload, publicPayload は PRISM によって base64url でエンコードされる。
//   - SecretCookie の JwtClaims は Usr という拡張フィールドを持ち、secretPayload を保存できる。
//   - AccessCookie の JwtClaims は Usr という拡張フィールドを持ち、accessPayload を保存できる。
//   - AccessCookie は publicPayload を AAD として付加できる。すなわち publicPayload は改ざんを検知できる。
//   - SecretCookie と AccessCookie の JwtClaims.Jti は常に同じ値を持つ。
//
// PRISM はクライアントから以下の３種類の経路でトークンを受け取ることができる。
// それぞれの経路と取得されたトークンの呼称の対応は以下である。
//   - SecretCookie -> SecretToken
//   - AccessCookie -> AccessToken
//   - SubmitHeader -> SubmitToken
// PRISM の Double-Submit Cookie の方式においては、
// 原理的に AccessToken と SubmitToken はまったく同じ文字列であることが期待される。
// また SecretToken と AccessToken は同じ Jti を持つため、SecretToken と SubmitToken の Jti を比較すると一致することが期待される。
// PRISM はそれぞれのトークンから以下の情報を取り出してリクエストヘッダに付与し、バックエンドに送信する。
//   - SecretToken -> secretPayload
//   - AccessToken -> accessPayload, publicPayload
// ただしユーザーが SubmitHeader をリクエストに付与しなかった場合、accessPayload だけはバックエンドに送信されない。
// また、オプションで SecretToken, AccessToken で共通の Jti をリクエストヘッダに付与することができ、
// バックエンドはこの Jti をセッション管理用の ID として扱ってもよい。
// バックエンド側はリクエストヘッダに accessPayload が付与されているか否かで Double-Submit Cookie が行われたかどうかを知ることができる。
// バックエンド側は以下のようにペイロードを使い分けることができる。
//   - secretPayload ... Cookie が存在する限り常にバックエンドに送信される情報で、クライアント側からは暗号化されていて読み取れない。
//   - accessPayload ... Double-Submit Cookie が行われた場合にのみバックエンドに送信される情報で、クライアント側からは暗号化されていて読み取れない。
//   - publicPayload ... Cookie が存在する限り常にバックエンドに送信される情報で、クライアント側から読み取れるが、改ざんはできない。
// たとえばユーザーIDは secretPayload、アプリに表示するユーザー名は publicPayload に保存しておくのがよいだろう。
//
// バックエンド側はレスポンスヘッダに secretPayload, accessPayload, publicPayload を付与することで、
// PRISM は自動的にそれらを読み取り、既に Cookie に保存されているペイロードと比較して変更がある場合に Cookie を更新する。
// バックエンド側にサーバーが複数存在する場合、複数のサーバーがペイロードを更新しようとすると競合することがある。
// すなわちサーバー１のレスポンスによって更新されたペイロードがサーバー２によって更新されることがあり、
// その次にサーバー１に対して送られたリクエストに付与された Cookie が、サーバー１がかつて想定したものとはならない可能性がある。
// これを防ぐために、PRISM は IdentityCenter として登録されたバックエンド以外からのペイロードを無視することができる。
// バックエンド側はブラウザに設定されている Cookie 更新のレートリミット及び Cookie の 4KB 制限にも留意すべきである。
//
// PRISM は SecretCookie と AccessCookie に異なる MaxAge を指定し、一般に AccessCookie の有効期間のほうが長い状態を想定する。
// 目安としてはおおよそ以下である。
//   - SecretCookie ... ７日ほど
//   - AccessCookie ... 30日ほど
// この措置により、PRISM は AccessCookie を SecretCookie 更新用のトークンとみなすことができる。
// すなわち SecretCookie 有効期限が切れていても、AccessCookie が有効であれば、
// その情報をもとに SecretCookie と AccessCookie を自動更新することができる。
// オプションで、自動更新されたかどうかを PRISM-PROXY-STATUS のような名前をキーとしてリクエストヘッダーに付与することができる。
//
// クライアントからの GET リクエスト時は、多くの場合ブラウザが自動送信するもので SubmitHeader が付加されない。
// したがって GET 時は SecretCookie さえ指定されていれば認証済みとみなしてよい。
// POST や PUT などのサーバーの状態を改変する重要な操作や、機密度の高い情報を取得するための一部の GET リクエスト時には、
// CSRF を防ぐためにクライアントは SubmitHeader をリクエストに付加することが推奨される。
// バックエンド側は SubmitHeader を解凍した accessPayload がリクエストヘッダに付加されているかどうかを
// 必要に応じて確認し、リクエストを許可するかどうかを判断すべきである。

const (
	// tokens
	secretCookieName = "PRISM-SECRET-TOKEN" // SecretCookie
	accessCookieName = "PRISM-ACCESS-TOKEN" // AccessCookie
	submitHeaderName = "PRISM-SUBMIT-TOKEN" // SubmitHeader

	// payloads
	secretHeaderName = "PRISM-SECRET" // secretPayload
	accessHeaderName = "PRISM-ACCESS" // accessPayload
	publicHeaderName = "PRISM-PUBLIC" // publicPayload

	// JwtHeader
	defaultAlg = "AES-GCM"
	defaultCty = ""
	defaultTyp = "JWT"

	defaultClockSkew     = 1 * time.Minute
	defaultNotBeforeSkew = 0 * time.Second

	defaultSessionTTL = 7 * 24 * time.Hour
	defaultRefreshTTL = 30 * 24 * time.Hour

	defaultMaxAgeMargin = 24 * time.Hour
)

// ミドルウェア側で Cookie を更新した場合に持ち回す
// コンテキストのキーとして登録する空の構造体
type ctxKeyRenewed struct{}

// ミドルウェア側で Cookie を更新した場合に持ち回す
// コンテキストの本体
type renewedInfo struct {
	hdrSecret     *jwt.JwtHeader
	hdrAccess     *jwt.JwtHeader
	clSecret      *jwt.JwtClaims
	clAccess      *jwt.JwtClaims
	publicPayload []byte
}

type DoubleSubmitCookieCSRFProtector struct {
	// tokens
	SecretCookieName string // SecretCookie
	AccessCookieName string // AccessCookie
	SubmitHeaderName string // SubmitHeader

	// payloads
	SecretHeaderName string // secretPayload
	AccessHeaderName string // accessPayload
	PublicHeaderName string // publicPayload

	// Encryption Algorithm
	Encrypter cipher.EncrypterInterface

	// JwtHeader
	JwtAlg string
	JwtCty string
	JwtTyp string

	// JwtClaims
	ClockSkew     time.Duration
	NotBeforeSkew time.Duration
	SessionTTL    time.Duration
	RefreshTTL    time.Duration

	// Cookie
	SecureCookie bool // デバッグ時は false にしてもよい
	MaxAgeMargin time.Duration

	// Config
	DetectTokenSpoofing bool

	// 中央集権的なID管理機能がある場合
	IdentityCenterAddress []string
}

type decryptedToken struct {
	header     *jwt.JwtHeader
	claims     *jwt.JwtClaims
	headerJSON []byte
	claimsJSON []byte
	aad        []byte
}

func (t *decryptedToken) marshal() ([]byte, []byte, error) {
	hdrJSON, clJSON, err := jwt.Marshal(t.header, t.claims)
	if err != nil {
		return nil, nil, err
	}
	t.headerJSON = hdrJSON
	t.claimsJSON = clJSON
	return hdrJSON, clJSON, nil
}

func DefaultDoubleSubmitCookieCSRFProtector(e cipher.EncrypterInterface) *DoubleSubmitCookieCSRFProtector {
	return &DoubleSubmitCookieCSRFProtector{
		SecretCookieName: secretCookieName,
		AccessCookieName: accessCookieName,
		SubmitHeaderName: submitHeaderName,

		SecretHeaderName: secretHeaderName,
		AccessHeaderName: accessHeaderName,
		PublicHeaderName: publicHeaderName,

		JwtAlg: defaultAlg,
		JwtCty: defaultCty,
		JwtTyp: defaultTyp,

		Encrypter: e,

		ClockSkew:     defaultClockSkew,
		NotBeforeSkew: defaultNotBeforeSkew,

		SessionTTL: defaultSessionTTL,
		RefreshTTL: defaultRefreshTTL,

		SecureCookie: true,
		MaxAgeMargin: defaultMaxAgeMargin,

		DetectTokenSpoofing: true,
	}
}

func (p *DoubleSubmitCookieCSRFProtector) newSecretCookie(value string) *http.Cookie {
	return &http.Cookie{
		Name:     p.SecretCookieName,
		Value:    value,
		MaxAge:   int((p.SessionTTL + p.MaxAgeMargin).Seconds()),
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		Secure:   p.SecureCookie,
	}
}

func (p *DoubleSubmitCookieCSRFProtector) newAccessCookie(value string) *http.Cookie {
	return &http.Cookie{
		Name:     p.AccessCookieName,
		Value:    value,
		MaxAge:   int((p.RefreshTTL + p.MaxAgeMargin).Seconds()),
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		HttpOnly: false,
		Secure:   p.SecureCookie,
	}
}

func (p *DoubleSubmitCookieCSRFProtector) deleteSecretCookie(c *gin.Context) {
	ck := &http.Cookie{
		Name:     p.SecretCookieName,
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		Secure:   p.SecureCookie,
	}
	http.SetCookie(c.Writer, ck)
}

func (p *DoubleSubmitCookieCSRFProtector) deleteAccessCookie(c *gin.Context) {
	ck := &http.Cookie{
		Name:     p.AccessCookieName,
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		HttpOnly: false,
		Secure:   p.SecureCookie,
	}
	http.SetCookie(c.Writer, ck)
}

func (p *DoubleSubmitCookieCSRFProtector) isValidJwtHeader(hdr *jwt.JwtHeader) bool {
	return (hdr.Alg == p.JwtAlg) && (hdr.Cty == p.JwtCty) && (hdr.Typ == p.JwtTyp)
}

var errInvalidJWTHeader = errors.New("invalid jwt header")

func (p *DoubleSubmitCookieCSRFProtector) decryptToken(token string) (*decryptedToken, error) {
	hdrJSON, clJSON, aad, err := jwt.DecryptWithAAD(p.Encrypter, token)
	if err != nil {
		return nil, err
	}
	hdr, cl, err := jwt.Unmarshal(hdrJSON, clJSON)
	if err != nil {
		return nil, err
	}
	if !p.isValidJwtHeader(hdr) {
		return nil, errInvalidJWTHeader
	}
	return &decryptedToken{
		header:     hdr,
		claims:     cl,
		headerJSON: hdrJSON,
		claimsJSON: clJSON,
		aad:        aad,
	}, nil
}

func (p *DoubleSubmitCookieCSRFProtector) cookieValue(req *http.Request, name string) (string, bool) {
	ck, err := req.Cookie(name)
	if err != nil || ck == nil || ck.Value == "" {
		return "", false
	}
	return ck.Value, true
}

func (p *DoubleSubmitCookieCSRFProtector) detectTokenSpoofing(c *gin.Context, headerName string) (hdr []string, yes bool) {
	hdr = c.Request.Header.Values(headerName)
	yes = len(hdr) > 0
	return hdr, yes
}

func (p *DoubleSubmitCookieCSRFProtector) logSpoofedHeaders(c *gin.Context) {
	if !p.DetectTokenSpoofing {
		return
	}
	headers := []string{p.SecretHeaderName, p.AccessHeaderName, p.PublicHeaderName}
	for _, name := range headers {
		if hdr, ok := p.detectTokenSpoofing(c, name); ok {
			logTokenSpoofing(c, name, hdr)
		}
	}
}

func logTokenSpoofing(c *gin.Context, headerName string, header []string) {
	log.Printf(
		"session token spoofing detected: remote=%s uri=%s path=%s key=%s tokens=%s",
		c.ClientIP(),
		c.Request.RequestURI,
		c.FullPath(),
		headerName,
		strings.Join(header, ","), // 全文をそのまま出力
	)
}

func (p *DoubleSubmitCookieCSRFProtector) decryptTokenWithAAD(token string) (hdrJSON, clJSON, aadJSON []byte, err error) {
	// トークンを復号する
	return jwt.DecryptWithAAD(p.Encrypter, token)
}

func (p *DoubleSubmitCookieCSRFProtector) handleSecretExpiration(
	c *gin.Context,
	secretToken, accessToken *decryptedToken,
	publicPayload []byte,
) {
	jtiV7, err := uuid.NewV7()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": msg.FailedToGenerateSessionToken})
		return
	}

	jti := jtiV7.String()
	now := time.Now().UTC()
	iat := now.Unix()
	nbf := now.Add(-p.NotBeforeSkew).Unix()

	secretToken.claims.Jti = jti
	secretToken.claims.Iat = iat
	secretToken.claims.Nbf = nbf
	secretToken.claims.Exp = now.Add(p.SessionTTL).Unix()

	accessToken.claims.Jti = jti
	accessToken.claims.Iat = iat
	accessToken.claims.Nbf = nbf
	accessToken.claims.Exp = now.Add(p.RefreshTTL).Unix()

	hdrSecretJSON, clSecretJSON, err := secretToken.marshal()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": msg.FailedToGenerateSessionToken})
		return
	}
	hdrAccessJSON, clAccessJSON, err := accessToken.marshal()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": msg.FailedToGenerateSessionToken})
		return
	}

	secretCipher, err := jwt.EncryptWithAAD(p.Encrypter, hdrSecretJSON, clSecretJSON, nil)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": msg.FailedToGenerateSessionToken})
		return
	}
	accessCipher, err := jwt.EncryptWithAAD(p.Encrypter, hdrAccessJSON, clAccessJSON, publicPayload)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": msg.FailedToGenerateSessionToken})
		return
	}

	http.SetCookie(c.Writer, p.newSecretCookie(secretCipher))
	http.SetCookie(c.Writer, p.newAccessCookie(accessCipher))

	if h := c.GetHeader(p.AccessCookieName); h != "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": msg.SessionTokenRegenerated})
		return
	}

	info := &renewedInfo{
		hdrSecret:     secretToken.header,
		hdrAccess:     accessToken.header,
		clSecret:      secretToken.claims,
		clAccess:      accessToken.claims,
		publicPayload: publicPayload,
	}
	req := c.Request
	ctx := context.WithValue(req.Context(), ctxKeyRenewed{}, info)
	c.Request = req.WithContext(ctx)

	c.Next()
}

func (p *DoubleSubmitCookieCSRFProtector) tokensFromContext(req *http.Request) (*decryptedToken, *decryptedToken, bool, error) {
	if req == nil {
		return nil, nil, false, nil
	}

	v := req.Context().Value(ctxKeyRenewed{})
	if v == nil {
		return nil, nil, false, nil
	}
	info, ok := v.(*renewedInfo)
	if !ok || info == nil {
		return nil, nil, false, nil
	}

	hasSecret := info.clSecret != nil
	hasAccess := info.clAccess != nil
	if hasSecret != hasAccess {
		return nil, nil, false, errors.New("context is broken")
	}
	if !hasSecret {
		return nil, nil, false, nil
	}

	secretToken := &decryptedToken{
		header: info.hdrSecret,
		claims: info.clSecret,
	}
	accessToken := &decryptedToken{
		header: info.hdrAccess,
		claims: info.clAccess,
		aad:    info.publicPayload,
	}

	return secretToken, accessToken, true, nil
}

func (p *DoubleSubmitCookieCSRFProtector) tokensFromCookies(req *http.Request) (*decryptedToken, *decryptedToken, error) {
	if req == nil {
		return nil, nil, errors.New("request is nil")
	}

	secretValue, hasSecret := p.cookieValue(req, p.SecretCookieName)
	accessValue, hasAccess := p.cookieValue(req, p.AccessCookieName)

	if hasSecret != hasAccess {
		return nil, nil, errors.New("cookie is broken")
	}
	if !hasSecret {
		return nil, nil, nil
	}

	secretToken, err := p.decryptToken(secretValue)
	if err != nil {
		return nil, nil, err
	}
	accessToken, err := p.decryptToken(accessValue)
	if err != nil {
		return nil, nil, err
	}
	return secretToken, accessToken, nil
}

func (p *DoubleSubmitCookieCSRFProtector) encryptSessionTokens(secretToken, accessToken *decryptedToken, publicPayload []byte) (string, string, error) {
	hdrSecretJSON, clSecretJSON, err := secretToken.marshal()
	if err != nil {
		return "", "", err
	}
	hdrAccessJSON, clAccessJSON, err := accessToken.marshal()
	if err != nil {
		return "", "", err
	}

	secretTokenStr, err := jwt.EncryptWithAAD(p.Encrypter, hdrSecretJSON, clSecretJSON, nil)
	if err != nil {
		return "", "", err
	}
	accessTokenStr, err := jwt.EncryptWithAAD(p.Encrypter, hdrAccessJSON, clAccessJSON, publicPayload)
	if err != nil {
		return "", "", err
	}
	return secretTokenStr, accessTokenStr, nil
}

func (p *DoubleSubmitCookieCSRFProtector) newSessionTokenPair() (*decryptedToken, *decryptedToken, error) {
	jtiV7, err := uuid.NewV7()
	if err != nil {
		return nil, nil, err
	}

	jti := jtiV7.String()
	now := time.Now().UTC()
	iat := now.Unix()
	nbf := now.Add(-p.NotBeforeSkew).Unix()

	secretClaims := &jwt.JwtClaims{
		Jti: jti,
		Iat: iat,
		Nbf: nbf,
		Exp: now.Add(p.SessionTTL).Unix(),
	}
	accessClaims := &jwt.JwtClaims{
		Jti: jti,
		Iat: iat,
		Nbf: nbf,
		Exp: now.Add(p.RefreshTTL).Unix(),
	}

	secretHeader := &jwt.JwtHeader{Alg: p.JwtAlg, Cty: p.JwtCty, Typ: p.JwtTyp}
	accessHeader := &jwt.JwtHeader{Alg: p.JwtAlg, Cty: p.JwtCty, Typ: p.JwtTyp}

	return &decryptedToken{header: secretHeader, claims: secretClaims}, &decryptedToken{header: accessHeader, claims: accessClaims}, nil
}

func needsSessionUpdate(secretToken, accessToken *decryptedToken, encodedSecret, encodedAccess string, encodedPublic []byte) bool {
	if secretToken == nil || accessToken == nil {
		return true
	}

	if subtle.ConstantTimeCompare([]byte(secretToken.claims.Usr), []byte(encodedSecret)) != 1 {
		return true
	}
	if subtle.ConstantTimeCompare([]byte(accessToken.claims.Usr), []byte(encodedAccess)) != 1 {
		return true
	}
	if subtle.ConstantTimeCompare(accessToken.aad, encodedPublic) != 1 {
		return true
	}
	return false
}

// DoubleSubmitCookieCSRFProtection は暗号化されたクッキー/ヘッダーを復号して比較します。
// 仕様:
// - クライアント送信のバックエンド用ヘッダーが存在したら攻撃として検知して記録するが、攻撃を防いだ上で通常処理する
func (p *DoubleSubmitCookieCSRFProtector) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		p.logSpoofedHeaders(c)

		c.Request.Header.Del(p.SecretHeaderName)
		c.Request.Header.Del(p.AccessHeaderName)
		c.Request.Header.Del(p.PublicHeaderName)

		secretValue, hasSecret := p.cookieValue(c.Request, p.SecretCookieName)
		accessValue, hasAccess := p.cookieValue(c.Request, p.AccessCookieName)

		if !hasSecret {
			c.Request.Header.Del(p.AccessCookieName)
			p.deleteSecretCookie(c)
			p.deleteAccessCookie(c)
			c.Next()
			return
		}

		secretToken, err := p.decryptToken(secretValue)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": msg.InvalidSecretToken})
			return
		}

		if !hasAccess {
			c.Request.Header.Del(p.AccessCookieName)
			p.deleteSecretCookie(c)
			p.deleteAccessCookie(c)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": msg.MissingAccessToken})
			return
		}

		accessToken, err := p.decryptToken(accessValue)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": msg.InvalidAccessToken})
			return
		}

		publicPayload := accessToken.aad
		secretAlive := jwt.HasValidLifetime(secretToken.claims, p.ClockSkew)
		accessAlive := jwt.HasValidLifetime(accessToken.claims, p.ClockSkew)

		if !secretAlive && !accessAlive {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": msg.SessionExpired})
			return
		}

		if !secretAlive {
			p.handleSecretExpiration(c, secretToken, accessToken, publicPayload)
			return
		}

		if subtle.ConstantTimeCompare([]byte(secretToken.claims.Jti), []byte(accessToken.claims.Jti)) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": msg.TokenMismatch})
			return
		}

		submitToken := c.GetHeader(p.AccessCookieName)
		if submitToken == "" {
			c.Request.Header.Set(p.SecretHeaderName, string(secretToken.claimsJSON))
			if len(publicPayload) > 0 {
				c.Request.Header.Set(p.PublicHeaderName, string(publicPayload))
			}
			c.Request.Header.Del(p.AccessCookieName)
			c.Next()
			return
		}

		submitDecrypted, err := p.decryptToken(submitToken)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": msg.InvalidDoubleSubmitToken})
			return
		}

		if subtle.ConstantTimeCompare([]byte(secretToken.claims.Jti), []byte(submitDecrypted.claims.Jti)) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": msg.TokenMismatch})
			return
		}

		c.Request.Header.Set(p.SecretHeaderName, string(secretToken.claimsJSON))
		c.Request.Header.Set(p.AccessHeaderName, string(accessToken.claimsJSON))
		if len(publicPayload) > 0 {
			c.Request.Header.Set(p.PublicHeaderName, string(publicPayload))
		}
		c.Request.Header.Del(p.AccessCookieName)

		c.Next()
	}
}

func (p *DoubleSubmitCookieCSRFProtector) inIdentityCenterList(resp *http.Response) bool {
	if resp == nil || resp.Request == nil || resp.Request.URL == nil {
		return false
	}
	host := resp.Request.URL.Hostname() // "1.2.3.4" or "backend.local"
	if host == "" {
		return false
	}
	for _, allowed := range p.IdentityCenterAddress {
		// 文字列一致（IP想定）。必要に応じて net.ParseIP で厳密化可。
		if allowed == host {
			return true
		}
	}
	return false
}

// DoubleSubmitCookieModifyResponse は、既存の ModifyResponse をラップし、以下の機能を付与する
//   - PRISM-BACKEND-TOKEN を取り出して、リクエストに含まれていた PRISM-SECRET-TOKEN（復号値）と比較
//   - 不一致（またはリクエスト側 Cookie が無い/復号不可）なら、新トークンとして
//     PRISM-SECRET-TOKEN / PRISM-ACCESS-TOKEN を暗号化して Set-Cookie で再配布
//   - 最後に PRISM-BACKEND-TOKEN ヘッダを除去
func (p *DoubleSubmitCookieCSRFProtector) ModifyResponse(orig func(*http.Response) error) func(*http.Response) error {
	return func(resp *http.Response) error {
		// 先に元の処理
		if orig != nil {
			if err := orig(resp); err != nil {
				return err
			}
		}

		secretPayload := resp.Header.Get(p.SecretHeaderName)
		accessPayload := resp.Header.Get(p.AccessHeaderName)
		publicPayload := resp.Header.Get(p.PublicHeaderName)

		encodePayload := func(payload string) string {
			if payload == "" {
				return ""
			}
			return base64.RawURLEncoding.EncodeToString([]byte(payload))
		}

		encodedSecretPayload := encodePayload(secretPayload)
		encodedAccessPayload := encodePayload(accessPayload)
		encodedPublicPayload := encodePayload(publicPayload)

		var encodedPublicPayloadBytes []byte
		if encodedPublicPayload != "" {
			encodedPublicPayloadBytes = []byte(encodedPublicPayload)
		}

		resp.Header.Del(p.SecretHeaderName)
		resp.Header.Del(p.AccessHeaderName)
		resp.Header.Del(p.PublicHeaderName)

		if secretPayload == "" && accessPayload == "" && publicPayload == "" {
			return nil
		}

		if resp.Request == nil || p.Encrypter == nil {
			return nil
		}

		if p.IdentityCenterAddress != nil && !p.inIdentityCenterList(resp) {
			return nil
		}

		secretToken, accessToken, foundInContext, err := p.tokensFromContext(resp.Request)
		if err != nil {
			return err
		}
		if !foundInContext {
			secretToken, accessToken, err = p.tokensFromCookies(resp.Request)
			if err != nil {
				return err
			}
		}

		if !needsSessionUpdate(secretToken, accessToken, encodedSecretPayload, encodedAccessPayload, encodedPublicPayloadBytes) {
			return nil
		}

		if secretToken == nil || accessToken == nil {
			secretToken, accessToken, err = p.newSessionTokenPair()
			if err != nil {
				return err
			}
		}

		secretToken.claims.Usr = encodedSecretPayload
		accessToken.claims.Usr = encodedAccessPayload
		accessToken.aad = encodedPublicPayloadBytes

		secretTokenStr, accessTokenStr, err := p.encryptSessionTokens(secretToken, accessToken, encodedPublicPayloadBytes)
		if err != nil {
			return err
		}

		resp.Header.Add("Set-Cookie", p.newSecretCookie(secretTokenStr).String())
		resp.Header.Add("Set-Cookie", p.newAccessCookie(accessTokenStr).String())

		return nil
	}
}

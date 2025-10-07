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
	Iss string `json:"iss"`           // トークン発行者の識別子
	Sub string `json:"sub"`           // トークンの主題の識別子
	Aud string `json:"aud"`           // トークンが意図している受信者の識別子
	Exp int64  `json:"exp"`           // トークンの有効期限。秒（UNIX time）。
	Nbf int64  `json:"nbf"`           // トークンの開始日時。秒。
	Iat int64  `json:"iat"`           // トークンの発行日時。秒。
	Jti string `json:"jti"`           // 発行者ごとトークンごとに一意な識別子。
	Usr string `json:"usr,omitempty"` // ユーザー定義フィールド
}

func DefaultJwtHeader() JwtHeader {
	return JwtHeader{
		Alg: DefaultAlg,
		Cty: DefaultCty,
		Typ: DefaultTyp,
	}
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

func Marshal(header *JwtHeader, claims *JwtClaims) ([]byte, []byte, error) {
	h, err := json.Marshal(header)
	if err != nil {
		return nil, nil, err
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return nil, nil, err
	}
	return h, c, nil
}

func UnmarshalJwtHeader(headerJSON []byte) (*JwtHeader, error) {
	var hdr JwtHeader
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return nil, err
	}
	return &hdr, nil
}

func UnmarshalJwtClaims(claimsJSON []byte) (*JwtClaims, error) {
	var cl JwtClaims
	if err := json.Unmarshal(claimsJSON, &cl); err != nil {
		return nil, err
	}
	return &cl, nil
}

func Unmarshal(headerJSON, claimsJSON []byte) (*JwtHeader, *JwtClaims, error) {
	hdr, err := UnmarshalJwtHeader(headerJSON)
	if err != nil {
		return nil, nil, err
	}
	cl, err := UnmarshalJwtClaims(claimsJSON)
	if err != nil {
		return nil, nil, err
	}
	return hdr, cl, nil
}

func HasValidLifetime(claims *JwtClaims, clockSkew time.Duration) bool {
	// time.Time 演算でクロックスキュー考慮（Seconds の丸め誤差回避）
	now := time.Now()
	nowPlusSkew := now.Add(clockSkew).Unix()
	nowMinusSkew := now.Add(-clockSkew).Unix()

	// nbf: now+skew >= nbf
	if nowPlusSkew < claims.Nbf {
		return false
	}
	// exp: now-skew < exp
	if nowMinusSkew >= claims.Exp {
		return false
	}
	return true
}

func Sign(s cipher.SignerInterface, headerJSON, claimsJSON []byte) string {
	// JWT: base64url(headerJSON) + "." + base64url(claimsJSON) + "." + base64url(signature)
	h := b64urlEncode(headerJSON)
	c := b64urlEncode(claimsJSON)
	unsigned := h + "." + c

	sig := s.Sign([]byte(unsigned))
	return unsigned + "." + b64urlEncode(sig)
}

func Verify(s cipher.SignerInterface, token string) (headerJSON, claimsJSON []byte, err error) {
	// token は "b64(header).b64(payload).b64(signature)"
	// strings.Cut でドット2つを段階的に処理（#6）
	hPart, rest, okCut := strings.Cut(token, ".")
	if !okCut {
		return headerJSON, claimsJSON, errors.New("Invalid format JWT")
	}
	pPart, sPart, okCut := strings.Cut(rest, ".")
	if !okCut {
		return headerJSON, claimsJSON, errors.New("Invalid format JWT")
	}
	// base64url には '.' は現れないため、余分な '.' があれば不正
	if strings.Contains(sPart, ".") {
		return headerJSON, claimsJSON, errors.New("Invalid format JWT")
	}

	// 署名検証を先に行う（#5）
	unsigned := hPart + "." + pPart
	sb, err := b64urlDecode(sPart)
	if err != nil {
		return headerJSON, claimsJSON, err
	}
	if !s.Verify([]byte(unsigned), sb) {
		return headerJSON, claimsJSON, errors.New("JWT verify failed")
	}

	// 署名OKなら JSON パース
	headerJSON, err = b64urlDecode(hPart)
	if err != nil {
		return headerJSON, claimsJSON, err
	}
	claimsJSON, err = b64urlDecode(pPart)
	if err != nil {
		return headerJSON, claimsJSON, err
	}
	// if err := json.Unmarshal(hb, &header); err != nil {
	// 	return header, claims, false
	// }
	// if err := json.Unmarshal(pb, &claims); err != nil {
	// 	return header, claims, false
	// }

	// （任意）ヘッダー/寿命チェック
	// if header.Alg != DefaultAlg || header.Typ != DefaultTyp { return header, claims, false }
	// if !HasValidLifetime(claims) { return header, claims, false }

	return headerJSON, claimsJSON, nil
}

// Encrypt は EncryptWithAAD を使って、AAD なしで暗号化します。
func Encrypt(e cipher.EncrypterInterface, headerJSON, claimsJSON []byte) (string, error) {
	return EncryptWithAAD(e, headerJSON, claimsJSON, nil)
}

// EncryptWithAAD は "b64(header).b64(payload)" を平文とし、aadJSON を AAD に使って暗号化します。
// 戻り値トークン形式:
//   - AAD なし: base64url(nonce||ciphertext)
//   - AAD あり: base64url(nonce||ciphertext) + "." + base64url(aadJSON)
func EncryptWithAAD(e cipher.EncrypterInterface, headerJSON, claimsJSON, aadJSON []byte) (string, error) {
	h := b64urlEncode(headerJSON)
	c := b64urlEncode(claimsJSON)
	plain := h + "." + c

	var p string
	var aad []byte
	if len(aadJSON) > 0 {
		p = b64urlEncode(aadJSON)
		aad = []byte(p)
	}

	ct, err := e.EncryptWithAAD([]byte(plain), aad) // nonce||ciphertext (binary)
	if err != nil {
		return "", err
	}

	token := b64urlEncode(ct)
	if aad != nil {
		token += "." + p
	}
	return token, nil
}

func Decrypt(e cipher.EncrypterInterface, token string) (headerJSON, claimsJSON []byte, err error) {
	headerJSON, claimsJSON, _, err = DecryptWithAAD(e, token)
	return headerJSON, claimsJSON, err
}

// DecryptWithAAD は Encrypt / EncryptWithAAD が出力したトークンを復号します。
// トークンが 2 パートなら後段が AAD、1 パートなら AAD なし。
func DecryptWithAAD(e cipher.EncrypterInterface, token string) (headerJSON, claimsJSON, aadJSON []byte, err error) {
	// 1 or 2 パート想定なので strings.Cut を使用
	first, second, hasDot := strings.Cut(token, ".")
	if hasDot && strings.Contains(second, ".") {
		// base64url は '.' を含まないため、2個以上の '.' は不正
		return headerJSON, claimsJSON, nil, errors.New("Invalid format JWT")
	}

	// 1パート目: base64url(nonce||ciphertext)
	cb, err := b64urlDecode(first)
	if err != nil {
		return headerJSON, claimsJSON, nil, errors.New("Invalid format JWT")
	}

	// AAD（= base64url(aadJSON) の文字列バイト）を準備
	var aad []byte
	if hasDot {
		if second == "" {
			return headerJSON, claimsJSON, nil, errors.New("Invalid format JWT")
		}
		aad = []byte(second)

		pj, err := b64urlDecode(second)
		if err != nil {
			return headerJSON, claimsJSON, nil, err
		}
		aadJSON = pj
	}

	// 復号して "b64(header).b64(payload)" を得る
	pt, err := e.DecryptWithAAD(cb, aad)
	if err != nil {
		return headerJSON, claimsJSON, aadJSON, err
	}

	// 平文は 2 パート固定なので Cut を使用
	hPart, rest, okCut := strings.Cut(string(pt), ".")
	if !okCut {
		return headerJSON, claimsJSON, aadJSON, errors.New("Invalid format JWT")
	}
	if strings.Contains(rest, ".") { // 過剰な '.'
		return headerJSON, claimsJSON, aadJSON, errors.New("Invalid format JWT")
	}

	headerJSON, err = b64urlDecode(hPart)
	if err != nil {
		return headerJSON, claimsJSON, aadJSON, err
	}
	claimsJSON, err = b64urlDecode(rest)
	if err != nil {
		return headerJSON, claimsJSON, aadJSON, err
	}

	// if err := json.Unmarshal(hb, &header); err != nil {
	// 	return header, claims, aadJSON, false
	// }
	// if err := json.Unmarshal(pb, &claims); err != nil {
	// 	return header, claims, aadJSON, false
	// }

	// （任意）寿命チェック:
	// if !HasValidLifetime(claims) { return header, claims, aadJSON, false }

	return headerJSON, claimsJSON, aadJSON, nil
}

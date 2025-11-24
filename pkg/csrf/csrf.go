package csrf

import (
	"fmt"
	"strings"
)

const (
	// tokens
	DefaultSecretCookieName = "PRISM-SECRET-TOKEN" // SecretCookie
	DefaultAccessCookieName = "PRISM-ACCESS-TOKEN" // AccessCookie
	DefaultSubmitHeaderName = "PRISM-SUBMIT-TOKEN" // SubmitHeader

	// payloads
	DefaultSecretHeaderName = "PRISM-SECRET" // secretPayload
	DefaultAccessHeaderName = "PRISM-ACCESS" // accessPayload
	DefaultPublicHeaderName = "PRISM-PUBLIC" // publicPayload
	DefaultNotifyHeaderName = "PRISM-NOTIFY" // notification
)

type AesGcmJwtConfig struct {
	// tokens
	SecretCookieName string `yaml:"secret_cookie_name,omitempty"` // SecretCookie
	AccessCookieName string `yaml:"access_cookie_name,omitempty"` // AccessCookie
	SubmitHeaderName string `yaml:"submit_header_name,omitempty"` // SubmitHeader

	// payloads
	SecretHeaderName string `yaml:"secret_header_name,omitempty"` // secretPayload
	AccessHeaderName string `yaml:"access_header_name,omitempty"` // accessPayload
	PublicHeaderName string `yaml:"public_header_name,omitempty"` // publicPayload
	NotifyHeaderName string `yaml:"notify_hedear_name,omitempty"` // notification
}

func (c *AesGcmJwtConfig) Normalize() (*AesGcmJwtConfig, error) {
	// shallow copy
	n := *c

	// デフォルト補完
	if n.SecretCookieName == "" {
		n.SecretCookieName = DefaultSecretCookieName
	}
	if n.AccessCookieName == "" {
		n.AccessCookieName = DefaultAccessCookieName
	}
	if n.SubmitHeaderName == "" {
		n.SubmitHeaderName = DefaultSubmitHeaderName
	}

	if n.SecretHeaderName == "" {
		n.SecretHeaderName = DefaultSecretHeaderName
	}
	if n.AccessHeaderName == "" {
		n.AccessHeaderName = DefaultAccessHeaderName
	}
	if n.PublicHeaderName == "" {
		n.PublicHeaderName = DefaultPublicHeaderName
	}
	if n.NotifyHeaderName == "" {
		n.NotifyHeaderName = DefaultNotifyHeaderName
	}

	// Cookie 名の重複チェック（HTTP 的には大文字小文字を無視）
	if strings.EqualFold(n.SecretCookieName, n.AccessCookieName) {
		return nil, fmt.Errorf("cookie name duplicated: SecretCookieName(%q) and AccessCookieName(%q)", n.SecretCookieName, n.AccessCookieName)
	}

	// ヘッダー名の重複チェック（Secret/Access/Public/Notify の4つ）
	headers := map[string]string{
		"SecretHeaderName": n.SecretHeaderName,
		"AccessHeaderName": n.AccessHeaderName,
		"PublicHeaderName": n.PublicHeaderName,
		"NotifyHeaderName": n.NotifyHeaderName,
	}
	seen := make(map[string]string) // lower(header) -> fieldName
	for field, val := range headers {
		lower := strings.ToLower(val)
		if prev, ok := seen[lower]; ok {
			return nil, fmt.Errorf("header name duplicated: %s(%q) conflicts with %s", field, val, prev)
		}
		seen[lower] = field
	}

	return &n, nil
}

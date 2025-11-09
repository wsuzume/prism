package csrf

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
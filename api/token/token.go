package token

// SecretToken represents the payload returned to clients via the PRISM-SECRET header.
type SecretToken struct {
	SecretPayload string `json:"secretPayload"`
	JTI           string `json:"jti,omitempty"`
}

// AccessToken represents the payload returned to clients via the PRISM-ACCESS header.
type AccessToken struct {
	AccessPayload string `json:"accessPayload"`
	JTI           string `json:"jti,omitempty"`
}

// PublicToken represents the payload returned to clients via the PRISM-PUBLIC header.
type PublicToken struct {
	PublicPayload string `json:"publicPayload"`
}

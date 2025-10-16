package token

// SecretToken represents the payload returned to clients via the PRISM-SECRET header.
type SecretToken struct {
	UserID string `json:"user_id"`
}

// AccessToken represents the payload returned to clients via the PRISM-ACCESS header.
type AccessToken struct {
	UserID string `json:"user_id"`
}

// PublicToken represents the payload returned to clients via the PRISM-PUBLIC header.
type PublicToken struct {
	Email string `json:"email"`
}

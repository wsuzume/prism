package msg

const (
	// Failed to get origin or referer header for basic CSRF protection
	MissingOriginAndRefererHeader = "MissingOriginAndRefererHeader"
	// Origin has invalid format
	InvalidFormatOrigin = "InvalidFormatOrigin"
	// The request came from not allowed origin
	InvalidOrigin = "InvalidOrigin"
	// Secret token is broken
	InvalidSecretToken = "InvalidSecretToken"
	// Access token is missing despite existing an secret token
	MissingAccessToken = "MissingAccessToken"
	// Access token is broken
	InvalidAccessToken = "InvalidAccessToken"
	// Secret token and access token mismatch
	TokenMismatch = "TokenMismatch"
	// Double-submitted access token in request header is broken
	InvalidDoubleSubmitToken = "InvalidDoubleSubmitToken"
	// Session is expired
	SessionExpired = "SessionExpired"
	// Failed to generate session token
	FailedToGenerateSessionToken = "FailedToGenerateSessionToken"
	// Session tokens are regenerated successfully
	SessionTokenRegenerated = "SessionTokenRegenerated"
)

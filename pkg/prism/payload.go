package prism

// PRISM-SECRET response structure
type SecretPayload struct {
	Authorized    bool   `json:"authorized"`     // 認可が正常に行われたか
	AgentVerified bool   `json:"agent_verified"` // エージェントが検証済みかどうか
	AgentType     string `json:"agent_type"`     // エージェントの種類
	SessionID     string `json:"session_id"`     // セッションID
	UserID        string `json:"user_id"`        // ユーザID
}

// PRISM-ACCESS response structure
type AccessPayload struct {
	SessionID     string `json:"session_id"`    // セッションID
	Authenticated bool   `json:"authenticated"` // 認証済みのセッションなら True
}

type PublicPayload struct {
	UserName string `json:"user_name"` // ユーザ名
}

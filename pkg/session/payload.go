package session

import "encoding/json"

// PRISM-SECRET response structure
type SecretPayload struct {
	Authorized    bool   `json:"authorized"`     // 認可が正常に行われたか
	Authenticated bool   `json:"authenticated"`  // 認証済みのセッションなら True
	AgentVerified bool   `json:"agent_verified"` // エージェントが検証済みかどうか
	AgentType     string `json:"agent_type"`     // エージェントの種類
	SessionID     string `json:"session_id"`     // セッションID
	UserID        string `json:"user_id"`        // ユーザID
	UserName      string `json:"user_name"`      // ユーザ名
}

func SecretPayloadFromJson(jsonData []byte) (*SecretPayload, error) {
	var payload SecretPayload
	err := json.Unmarshal(jsonData, &payload)
	if err != nil {
		return nil, err
	}
	return &payload, nil
}

// PRISM-ACCESS response structure
type AccessPayload struct {
	SessionID     string `json:"session_id"`    // セッションID
}

func BuildAccessPayload(secret *SecretPayload) *AccessPayload {
	return &AccessPayload{
		SessionID: secret.SessionID,
	}
}

type PublicPayload struct {
	UserName string `json:"user_name"` // ユーザ名
}

func BuildPublicPayload(secret *SecretPayload) *PublicPayload {
	return &PublicPayload{
		UserName: secret.UserName,
	}
}

type NotifyPayload struct {
	SessionID string `json:"session_id"` // セッションID
	UserID    string `json:"user_id"`    // ユーザID
	Authorized bool   `json:"authorized"` // 認可が正常に行われたか
	Authenticated bool   `json:"authenticated"`  // 認証済みのセッションなら True
	CSRFProtected bool   `json:"csrf_protected"` // CSRF保護が有効かどうか
}

func BuildNotifyPayload(secret *SecretPayload) *NotifyPayload {
	// TODO: CSRFProtected を指定可能にする
	return &NotifyPayload{
		Authorized: secret.Authorized,
		Authenticated: secret.Authenticated,
		CSRFProtected: false,
		SessionID: secret.SessionID,
		UserID: secret.UserID,
	}
}
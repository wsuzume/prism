package cipher

import (
	"crypto/hmac"
	"crypto/sha256"
)

// ========================================================
// HS256 ユーティリティ
// ========================================================

type SignerHS256 struct {
	secret []byte
}

func NewSignerHS256(secret []byte) *SignerHS256 {
	return &SignerHS256{secret: secret}
}

func (s *SignerHS256) Sign(msg []byte) []byte {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write(msg)
	return mac.Sum(nil)
}

func (s *SignerHS256) Verify(msg, sig []byte) bool {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write(msg)
	expected := mac.Sum(nil)
	return hmac.Equal(expected, sig)
}
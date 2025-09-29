package cipher

import (
	"crypto/aes"
	stdcipher "crypto/cipher" // 衝突回避
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

// 署名インターフェース
type SignerInterface interface {
	Sign(msg []byte) []byte
	Verify(msg, sig []byte) bool
}

// 暗号化インターフェース
type EncrypterInterface interface {
	Encrypt(plain []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
	EncryptWithAAD(plain, aad []byte) ([]byte, error)
	DecryptWithAAD(ciphertext, aad []byte) ([]byte, error)
}

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

// ========================================================
// AES-GCM ユーティリティ
// ========================================================

type EncrypterAESGCM struct {
	gcm stdcipher.AEAD
}

// key は 16/24/32 バイト（AES-128/192/256）
func NewEncrypterAESGCM(key []byte) (*EncrypterAESGCM, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := stdcipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &EncrypterAESGCM{gcm: gcm}, nil
}

// nonce || ciphertext （AADなし）
func (e *EncrypterAESGCM) Encrypt(plain []byte) ([]byte, error) {
	return e.EncryptWithAAD(plain, nil)
}

func (e *EncrypterAESGCM) Decrypt(ciphertext []byte) ([]byte, error) {
	return e.DecryptWithAAD(ciphertext, nil)
}

// nonce || ciphertext （AADあり）
func (e *EncrypterAESGCM) EncryptWithAAD(plain, aad []byte) ([]byte, error) {
	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := e.gcm.Seal(nil, nonce, plain, aad)
	out := append(nonce, ct...)
	return out, nil
}

func (e *EncrypterAESGCM) DecryptWithAAD(ciphertext, aad []byte) ([]byte, error) {
	ns := e.gcm.NonceSize()
	if len(ciphertext) < ns {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := ciphertext[:ns], ciphertext[ns:]
	pt, err := e.gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, err
	}
	return pt, nil
}

package cipher

import (
	"crypto/aes"
	stdcipher "crypto/cipher" // 衝突回避
	"crypto/rand"
	"errors"
	"io"
)

// ========================================================
// AES-GCM ユーティリティ
// ========================================================

// EncrypterAESGCM is safe for concurrent use.

// Ensure at compile time that EncrypterAESGCM implements EncrypterAAD interface
var _ EncrypterAAD = (*EncrypterAESGCM)(nil)

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

func (e *EncrypterAESGCM) Alg() string {
	return "AES-GCM"
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
	return e.gcm.Seal(nonce, nonce, plain, aad), nil
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

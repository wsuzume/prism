package cipher

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

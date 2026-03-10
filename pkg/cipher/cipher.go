package cipher

type Algorithm interface {
	Alg() string
}

// 署名インターフェース
type Signer interface {
	Algorithm
	Sign(msg []byte) ([]byte, error)
	Verify(msg, sig []byte) (bool, error)
}

// 暗号化インターフェース
type Encrypter interface {
	Algorithm
	Encrypt(plain []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

// AAD付き暗号化インターフェース
type EncrypterAAD interface {
	Encrypter
	EncryptWithAAD(plain, aad []byte) ([]byte, error)
	DecryptWithAAD(ciphertext, aad []byte) ([]byte, error)
}

package cipher

type SignerDummy struct{}

func NewSignerDummy() *SignerDummy {
	return &SignerDummy{}
}

func (s *SignerDummy) Alg() string {
	return "DUMMY-S"
}

func (s *SignerDummy) Sign(msg []byte) ([]byte, error) {
	return msg, nil
}

func (s *SignerDummy) Verify(msg []byte, sig []byte) (bool, error) {
	return string(msg) == string(sig), nil
}

type EncrypterDummy struct{}

func NewEncrypterDummy() *EncrypterDummy {
	return &EncrypterDummy{}
}

func (e *EncrypterDummy) Alg() string {
	return "DUMMY-E"
}

func (e *EncrypterDummy) Encrypt(plain []byte) ([]byte, error) {
	return plain, nil
}

func (e *EncrypterDummy) Decrypt(ciphertext []byte) ([]byte, error) {
	return ciphertext, nil
}

func (e *EncrypterDummy) EncryptWithAAD(plain, aad []byte) ([]byte, error) {
	return plain, nil
}

func (e *EncrypterDummy) DecryptWithAAD(ciphertext, aad []byte) ([]byte, error) {
	return ciphertext, nil
}

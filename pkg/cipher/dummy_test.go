package cipher

import (
	"testing"
)

func TestSignerDummy_Alg(t *testing.T) {
	s := NewSignerDummy()
	if s.Alg() != "DUMMY-S" {
		t.Errorf("expected DUMMY-S, got %s", s.Alg())
	}
}

func TestSignerDummy_SignVerify(t *testing.T) {
	s := NewSignerDummy()
	msg := []byte("hello")

	sig, err := s.Sign(msg)
	if err != nil {
		t.Fatalf("Sign error: %v", err)
	}
	if string(sig) != string(msg) {
		t.Errorf("expected sig == msg, got %q", sig)
	}

	ok, err := s.Verify(msg, sig)
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if !ok {
		t.Error("expected Verify to return true")
	}
}

func TestSignerDummy_VerifyFail(t *testing.T) {
	s := NewSignerDummy()
	ok, err := s.Verify([]byte("hello"), []byte("wrong"))
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if ok {
		t.Error("expected Verify to return false for mismatched sig")
	}
}

func TestEncrypterDummy_Alg(t *testing.T) {
	e := NewEncrypterDummy()
	if e.Alg() != "DUMMY-E" {
		t.Errorf("expected DUMMY-E, got %s", e.Alg())
	}
}

func TestEncrypterDummy_EncryptDecrypt(t *testing.T) {
	e := NewEncrypterDummy()
	plain := []byte("secret")

	ct, err := e.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}
	if string(ct) != string(plain) {
		t.Errorf("expected ciphertext == plain, got %q", ct)
	}

	pt, err := e.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}
	if string(pt) != string(plain) {
		t.Errorf("expected plaintext == original, got %q", pt)
	}
}

func TestEncrypterDummy_EncryptDecryptWithAAD(t *testing.T) {
	e := NewEncrypterDummy()
	plain := []byte("secret")
	aad := []byte("additional")

	ct, err := e.EncryptWithAAD(plain, aad)
	if err != nil {
		t.Fatalf("EncryptWithAAD error: %v", err)
	}
	if string(ct) != string(plain) {
		t.Errorf("expected ciphertext == plain, got %q", ct)
	}

	pt, err := e.DecryptWithAAD(ct, aad)
	if err != nil {
		t.Fatalf("DecryptWithAAD error: %v", err)
	}
	if string(pt) != string(plain) {
		t.Errorf("expected plaintext == original, got %q", pt)
	}
}

func TestEncrypterDummy_ImplementsInterfaces(t *testing.T) {
	var _ Encrypter = NewEncrypterDummy()
	var _ EncrypterAAD = NewEncrypterDummy()
}

func TestSignerDummy_ImplementsInterface(t *testing.T) {
	var _ Signer = NewSignerDummy()
}

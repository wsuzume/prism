package cipher

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// インターフェース適合性（コンパイル時チェック）
var (
	_ SignerInterface    = (*SignerHS256)(nil)
	_ EncrypterInterface = (*EncrypterAESGCM)(nil)
)

func TestSignerHS256_SignAndVerify(t *testing.T) {
	secret := []byte("unit-test-secret")
	s := NewSignerHS256(secret)

	msg := []byte("hello world")
	sig := s.Sign(msg)
	if len(sig) == 0 {
		t.Fatal("signature must not be empty")
	}

	if !s.Verify(msg, sig) {
		t.Fatal("Verify should succeed for correct (msg,sig)")
	}

	// メッセージ改ざん
	if s.Verify([]byte("HELLO WORLD"), sig) {
		t.Fatal("Verify should fail for tampered message")
	}

	// 署名改ざん
	tampered := make([]byte, len(sig))
	copy(tampered, sig)
	tampered[0] ^= 0xFF
	if s.Verify(msg, tampered) {
		t.Fatal("Verify should fail for tampered signature")
	}
}

func TestSignerHS256_WrongKey(t *testing.T) {
	s1 := NewSignerHS256([]byte("k1"))
	s2 := NewSignerHS256([]byte("k2"))

	msg := []byte("data")
	sig := s1.Sign(msg)
	if s2.Verify(msg, sig) {
		t.Fatal("Verify should fail with different key")
	}
}

func TestEncrypterAESGCM_RoundTrip_AllKeySizes(t *testing.T) {
	tests := []struct {
		name string
		klen int
	}{
		{"AES-128", 16},
		{"AES-192", 24},
		{"AES-256", 32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.klen)
			if _, err := rand.Read(key); err != nil {
				t.Fatalf("rand.Read: %v", err)
			}
			enc, err := NewEncrypterAESGCM(key)
			if err != nil {
				t.Fatalf("NewEncrypterAESGCM: %v", err)
			}

			plain := []byte("secret message")
			ct, err := enc.Encrypt(plain)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if bytes.Equal(ct, plain) {
				t.Fatal("ciphertext must differ from plaintext")
			}

			pt, err := enc.Decrypt(ct)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(pt, plain) {
				t.Fatalf("round-trip mismatch: got %q want %q", pt, plain)
			}
		})
	}
}

func TestEncrypterAESGCM_WithAAD(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	enc, err := NewEncrypterAESGCM(key)
	if err != nil {
		t.Fatalf("NewEncrypterAESGCM: %v", err)
	}

	plain := []byte("message with aad")
	aad := []byte("session=12345;user=alice")

	// 正常系: 同じ AAD で往復
	ct, err := enc.EncryptWithAAD(plain, aad)
	if err != nil {
		t.Fatalf("EncryptWithAAD: %v", err)
	}
	pt, err := enc.DecryptWithAAD(ct, aad)
	if err != nil {
		t.Fatalf("DecryptWithAAD: %v", err)
	}
	if !bytes.Equal(pt, plain) {
		t.Fatalf("round-trip mismatch: got %q want %q", pt, plain)
	}

	// AAD 相違は失敗
	if _, err := enc.DecryptWithAAD(ct, []byte("session=9999")); err == nil {
		t.Fatal("DecryptWithAAD should fail when AAD differs")
	}

	// AAD 付き暗号文を AAD なし API で復号 → 失敗
	if _, err := enc.Decrypt(ct); err == nil {
		t.Fatal("Decrypt should fail if ciphertext was created with AAD")
	}
}

func TestEncrypterAESGCM_TamperDetection(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	enc, err := NewEncrypterAESGCM(key)
	if err != nil {
		t.Fatalf("NewEncrypterAESGCM: %v", err)
	}

	plain := []byte("authenticated data")
	ct, err := enc.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// どこか1バイト改ざん
	ct[len(ct)/2] ^= 0x01

	if _, err := enc.Decrypt(ct); err == nil {
		t.Fatal("Decrypt should fail for tampered ciphertext")
	}
}

func TestEncrypterAESGCM_ShortCiphertext(t *testing.T) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	enc, err := NewEncrypterAESGCM(key)
	if err != nil {
		t.Fatalf("NewEncrypterAESGCM: %v", err)
	}

	// Nonce サイズ未満の入力
	short := make([]byte, enc.gcm.NonceSize()-1)
	if _, err := rand.Read(short); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	if _, err := enc.Decrypt(short); err == nil {
		t.Fatal("Decrypt should fail for too-short ciphertext")
	}
}

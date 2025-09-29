package core

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// ──────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────────────────────────────────

const (
	permDir  fs.FileMode = 0o700
	permFile fs.FileMode = 0o600
)

// decodeBase64Flexible tries RawStdEncoding first, then StdEncoding.
func decodeBase64Flexible(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty base64 string")
	}
	if dec, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return dec, nil
	}
	dec, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	return dec, nil
}

// check0600 ensures file is not a symlink and permission is exactly 0600.
// （コメント修正: 「exactly 0600」かつシンボリックリンクを禁止）
func check0600(path string) error {
	st, err := os.Lstat(path) // Lstat でシンボリックリンクも検査
	if err != nil {
		return fmt.Errorf("stat secret file: %s: %w", path, err)
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("secret file is symlink (refused): %s", path)
	}
	if st.Mode().Perm() != 0o600 {
		return fmt.Errorf("secret file permission must be 0600: %s (got %o)", path, st.Mode().Perm())
	}
	return nil
}

// check0700Dir ensures dir exists, is a directory (not symlink), and permission is exactly 0700.
// （新規追加: ディレクトリの厳密 0700 とシンボリックリンク禁止を担保）
func check0700Dir(dir string) error {
	st, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("stat secret dir: %s: %w", dir, err)
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("secret dir is symlink (refused): %s", dir)
	}
	if !st.IsDir() {
		return fmt.Errorf("secret dir is not a directory: %s", dir)
	}
	if st.Mode().Perm() != 0o700 {
		return fmt.Errorf("secret dir permission must be 0700: %s (got %o)", dir, st.Mode().Perm())
	}
	return nil
}

// atomicWrite writes data to path atomically with given perm.
// The caller must ensure parent directory exists.
func atomicWrite(path string, data []byte, perm fs.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return fmt.Errorf("write temp file: %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename temp file to target: %s -> %s: %w", tmp, path, err)
	}
	return nil
}

// randBytes returns n bytes of cryptographically secure random data.
func randBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, errors.New("random length must be > 0")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// loadOrCreateWithFormat は base64 で保存された秘密（固定長）を読み書きする共通実装。
//   - wantLen > 0 のときは長さ一致を要求
//   - allowedLens が非nilのときは allowed に含まれる長さのみ許可（AEAD用）
//   - enc は書き出し時の base64 エンコーダ（読み出しは柔軟デコード）
//   - newline は書き出し時に末尾改行を付与するか
//   - ディレクトリは 0700（正確に）・ファイルは 0600（正確に）。シンボリックリンクは拒否。
func loadOrCreateWithFormat(
	dir, filename string,
	wantLen int,
	allowedLens []int,
	enc *base64.Encoding,
	newline bool,
) ([]byte, error) {
	// ディレクトリ作成（0700）後に厳密チェック
	if err := os.MkdirAll(dir, permDir); err != nil {
		return nil, fmt.Errorf("mkdir secret dir: %s: %w", dir, err)
	}
	if err := check0700Dir(dir); err != nil {
		return nil, err
	}

	path := filepath.Join(dir, filename)

	// 既存ファイル
	if data, err := os.ReadFile(path); err == nil {
		// 1) perm 先行（シンボリックリンク拒否 & 正確に 0600）
		if err := check0600(path); err != nil {
			return nil, err
		}
		// 2) 柔軟デコード
		raw, derr := decodeBase64Flexible(string(data))
		if derr != nil {
			return nil, fmt.Errorf("invalid secret file format (expecting base64): %s: %w", path, derr)
		}
		// 3) 長さ検査
		if wantLen > 0 && len(raw) != wantLen {
			return nil, fmt.Errorf("secret length mismatch: %s (want %d, got %d)", path, wantLen, len(raw))
		}
		if allowedLens != nil && !slices.Contains(allowedLens, len(raw)) {
			return nil, fmt.Errorf("secret length not allowed: %s (allowed %v, got %d)", path, allowedLens, len(raw))
		}
		return raw, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read secret file: %s: %w", path, err)
	}

	// 新規作成
	var n int
	if wantLen > 0 {
		n = wantLen
	} else if allowedLens != nil && len(allowedLens) > 0 {
		// allowed が与えられて wantLen が無い場合、先頭を採用
		n = allowedLens[0]
	} else {
		return nil, errors.New("no length constraint provided")
	}

	buf, err := randBytes(n)
	if err != nil {
		return nil, fmt.Errorf("generate random secret (%d bytes): %w", n, err)
	}

	out := enc.EncodeToString(buf)
	if newline {
		out += "\n"
	}
	if err := atomicWrite(path, []byte(out), permFile); err != nil {
		return nil, err
	}
	// 書き込み後の最終パーミッション確認（厳密 0600）
	if err := check0600(path); err != nil {
		return nil, err
	}
	return buf, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────────────────────

// LoadOrCreateSecret reads a base64-encoded secret from dir/filename.
// If missing, it creates a new random secret of secretLength bytes,
// writes it in StdEncoding (with trailing newline) as 0600, and returns raw bytes.
// （コメント修正: ファイルは厳密に 0600、ディレクトリは厳密に 0700、シンボリックリンクは禁止）
func LoadOrCreateSecret(dir, filename string, secretLength int) ([]byte, error) {
	if secretLength <= 0 {
		return nil, errors.New("invalid secret length")
	}
	return loadOrCreateWithFormat(
		dir, filename,
		secretLength,       // wantLen
		nil,                // allowedLens
		base64.StdEncoding, // write as StdEncoding
		true,               // newline
	)
}

// LoadOrCreateAEADKey reads an AEAD key (base64 in file) of wantLen bytes from dir/filename.
// If missing, it generates a new key of wantLen bytes, writes it in RawStdEncoding (no newline)
// as 0600, and returns raw bytes.
// （コメント修正: ファイルは厳密に 0600、ディレクトリは厳密に 0700、シンボリックリンクは禁止）
func LoadOrCreateAEADKey(dir, filename string, wantLen int) ([]byte, error) {
	switch wantLen {
	case 16, 24, 32:
	default:
		return nil, errors.New("invalid AES key length (must be 16, 24, or 32)")
	}
	return loadOrCreateWithFormat(
		dir, filename,
		wantLen,               // wantLen（厳密一致）
		[]int{16, 24, 32},     // allowedLens（保険）
		base64.RawStdEncoding, // write as RawStdEncoding
		false,                 // no newline
	)
}

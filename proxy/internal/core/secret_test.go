// secret_test.go
package core

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Helpers
func isWindows() bool { return runtime.GOOS == "windows" }

func mustStat(t *testing.T, p string) os.FileInfo {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatalf("stat %s: %v", p, err)
	}
	return fi
}

func mustPerm(t *testing.T, p string) os.FileMode {
	t.Helper()
	return mustStat(t, p).Mode().Perm()
}

func writeFile(t *testing.T, p string, data []byte, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(p, data, perm); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
}

func chmod(t *testing.T, p string, perm os.FileMode) {
	t.Helper()
	if err := os.Chmod(p, perm); err != nil {
		t.Fatalf("chmod %s: %v", p, err)
	}
}

func TestLoadOrCreateSecret_CreateAndRead(t *testing.T) {
	tmp := t.TempDir()
	// Ensure dir starts with 0700 for strict check (some OS may create with 0700 already)
	chmod(t, tmp, 0o700)

	const name = "session-hmac-secret"
	const n = 32

	// First call: creates
	sec1, err := LoadOrCreateSecret(tmp, name, n)
	if err != nil {
		t.Fatalf("LoadOrCreateSecret create: %v", err)
	}
	if len(sec1) != n {
		t.Fatalf("secret length want %d got %d", n, len(sec1))
	}

	// Dir/file perms
	if p := mustPerm(t, tmp); p != 0o700 && !isWindows() {
		t.Fatalf("dir perm want 0700 got %o", p)
	}
	fp := filepath.Join(tmp, name)
	if p := mustPerm(t, fp); p != 0o600 && !isWindows() {
		t.Fatalf("file perm want 0600 got %o", p)
	}

	// Second call: reads existing, must be identical
	sec2, err := LoadOrCreateSecret(tmp, name, n)
	if err != nil {
		t.Fatalf("LoadOrCreateSecret read: %v", err)
	}
	if string(sec1) != string(sec2) {
		t.Fatalf("secrets differ between create and read")
	}
}

func TestLoadOrCreateSecret_PermissionStrict(t *testing.T) {
	if isWindows() {
		t.Skip("skip permission-strict test on Windows")
	}
	tmp := t.TempDir()
	chmod(t, tmp, 0o700)

	const name = "secret"
	const n = 16

	// Prepare a valid file but with loose perms
	raw := make([]byte, n)
	enc := base64.StdEncoding.EncodeToString(raw) + "\n"
	fp := filepath.Join(tmp, name)
	writeFile(t, fp, []byte(enc), 0o644) // loose

	_, err := LoadOrCreateSecret(tmp, name, n)
	if err == nil {
		t.Fatalf("expected error for 0600 strict check, got nil")
	}
}

func TestLoadOrCreateSecret_SymlinkFileRefused(t *testing.T) {
	if isWindows() {
		t.Skip("symlink tests are flaky on Windows CI")
	}
	tmp := t.TempDir()
	chmod(t, tmp, 0o700)

	const name = "secret"
	const n = 16

	// Create target outside and link
	target := filepath.Join(tmp, "realfile")
	writeFile(t, target, []byte(base64.StdEncoding.EncodeToString(make([]byte, n))+"\n"), 0o600)

	link := filepath.Join(tmp, name)
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	_, err := LoadOrCreateSecret(tmp, name, n)
	if err == nil {
		t.Fatalf("expected symlink refusal error, got nil")
	}
}

func TestLoadOrCreateSecret_DirPermStrictAndSymlinkRefused(t *testing.T) {
	if isWindows() {
		t.Skip("skip dir-perm/symlink test on Windows")
	}
	// Make a symlinked dir and ensure it's refused by check0700Dir
	base := t.TempDir()
	realDir := filepath.Join(base, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatalf("mkdir real: %v", err)
	}
	linkDir := filepath.Join(base, "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatalf("symlink dir: %v", err)
	}

	_, err := LoadOrCreateSecret(linkDir, "s", 16)
	if err == nil {
		t.Fatalf("expected error for symlinked dir, got nil")
	}

	// Now test loose dir perm
	looseDir := filepath.Join(base, "loose")
	if err := os.Mkdir(looseDir, 0o755); err != nil {
		t.Fatalf("mkdir loose: %v", err)
	}
	_, err = LoadOrCreateSecret(looseDir, "s", 16)
	if err == nil {
		t.Fatalf("expected error for dir perm != 0700, got nil")
	}
}

func TestLoadOrCreateSecret_LengthMismatchExisting(t *testing.T) {
	tmp := t.TempDir()
	chmod(t, tmp, 0o700)
	const name = "secret"
	const n = 32

	// Write valid base64 but wrong length
	raw := make([]byte, n-1)
	fp := filepath.Join(tmp, name)
	writeFile(t, fp, []byte(base64.StdEncoding.EncodeToString(raw)+"\n"), 0o600)

	_, err := LoadOrCreateSecret(tmp, name, n)
	if err == nil {
		t.Fatalf("expected length mismatch error, got nil")
	}
}

func TestLoadOrCreateAEADKey_CreateRead_ValidLens(t *testing.T) {
	tmp := t.TempDir()
	chmod(t, tmp, 0o700)

	for _, n := range []int{16, 24, 32} {
		// filename はベース名のみを渡す（dir と join されるため）
		name := fmt.Sprintf("aeadkey_%d", n)

		key1, err := LoadOrCreateAEADKey(tmp, name, n)
		if err != nil {
			t.Fatalf("create aead key len=%d: %v", n, err)
		}
		if len(key1) != n {
			t.Fatalf("aead key length want %d got %d", n, len(key1))
		}

		// perms
		if p := mustPerm(t, filepath.Join(tmp, name)); p != 0o600 && !isWindows() {
			t.Fatalf("aead file perm want 0600 got %o", p)
		}

		// read again
		key2, err := LoadOrCreateAEADKey(tmp, name, n)
		if err != nil {
			t.Fatalf("read aead key len=%d: %v", n, err)
		}
		if string(key1) != string(key2) {
			t.Fatalf("aead keys differ for len=%d", n)
		}
	}
}

func TestLoadOrCreateAEADKey_InvalidLenRejected(t *testing.T) {
	tmp := t.TempDir()
	chmod(t, tmp, 0o700)
	if _, err := LoadOrCreateAEADKey(tmp, "k", 15); err == nil {
		t.Fatalf("want error for invalid AES key length (15), got nil")
	}
	if _, err := LoadOrCreateAEADKey(tmp, "k", 0); err == nil {
		t.Fatalf("want error for invalid AES key length (0), got nil")
	}
}

func TestLoadOrCreateAEADKey_ExistingWrongLen(t *testing.T) {
	tmp := t.TempDir()
	chmod(t, tmp, 0o700)
	const name = "k"

	// Write 24 bytes, but request 32
	raw := make([]byte, 24)
	fp := filepath.Join(tmp, name)
	writeFile(t, fp, []byte(base64.RawStdEncoding.EncodeToString(raw)), 0o600)

	_, err := LoadOrCreateAEADKey(tmp, name, 32)
	if err == nil {
		t.Fatalf("expected length mismatch error, got nil")
	}
}

func TestLoadOrCreateAEADKey_BadBase64(t *testing.T) {
	tmp := t.TempDir()
	chmod(t, tmp, 0o700)
	const name = "k"

	// Invalid base64
	writeFile(t, filepath.Join(tmp, name), []byte("not-base64!@@"), 0o600)

	_, err := LoadOrCreateAEADKey(tmp, name, 16)
	if err == nil {
		t.Fatalf("expected base64 error, got nil")
	}
}

func TestLoadOrCreateAEADKey_FilePermLooseRejected(t *testing.T) {
	if isWindows() {
		t.Skip("skip permission-strict test on Windows")
	}
	tmp := t.TempDir()
	chmod(t, tmp, 0o700)
	const name = "k"

	writeFile(t, filepath.Join(tmp, name), []byte(base64.RawStdEncoding.EncodeToString(make([]byte, 16))), 0o644)

	_, err := LoadOrCreateAEADKey(tmp, name, 16)
	if err == nil {
		t.Fatalf("expected 0600 strict error, got nil")
	}
}

func TestErrorMessagesContainPath(t *testing.T) {
	tmp := t.TempDir()
	chmod(t, tmp, 0o700)
	// Deliberately set dir perm wrong to trigger path-in-error
	loose := filepath.Join(tmp, "loose")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatalf("mkdir loose: %v", err)
	}
	_, err := LoadOrCreateSecret(loose, "s", 16)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	// Basic check that path is included somewhere
	if !errors.Is(err, os.ErrPermission) { // may not map; fallback to substring check instead
		if !strings.Contains(err.Error(), loose) {
			t.Fatalf("error should include path %q, got: %v", loose, err)
		}
	}
}

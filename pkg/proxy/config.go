package proxy

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/wsuzume/prism/pkg/csrf"
)

const (
	DefaultUnixSocketPath = "/var/run/prism"
	DefaultUnixSocketPermission = "0600"
)

type Config struct {
	CommandServerConfig CommandServerConfig `yaml:"command_server,omitempty"`
	AesGcmJwtConfig csrf.AesGcmJwtConfig `yaml:"aes_gcm_jwt,omitempty"`
	Backends map[string]BackendConfig `yaml:"backends,omitempty"`
}

func (c *Config) Normalize() (*Config, error) {
	var err error

	// 元の値を壊さないために最初にシャローコピーを作る
	n := *c

	csc, err := c.CommandServerConfig.Normalize()
	if err != nil {
		return nil, err
	}
	n.CommandServerConfig = *csc

	return &n, nil
}

func (c *Config) String() string {
	b, err := yaml.Marshal(c)
	if err != nil {
		// Marshal に失敗することはほぼないが、念のためエラー内容を含める
		return fmt.Sprintf("Config<error: %v>", err)
	}
	return string(b)
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Prism の CommandServer を制御する設定
//   - Mode: "none"
//     - CommandServer を起動しない（デフォルトの挙動）
//     - Port, Address, Path, Owner, Permission の指定を許容しない
//   - Mode: "disable"
//     - CommandServer を起動しない
//     - Port, Address, Path, Owner, Permission を指定しても無視する
//   - Mode: "unix"
//     - CommandServer を Unix ソケットで listen する
//     - Path に Unix ソケットへのパスを指定する
//     - Owner に Unix ソケットのファイルオーナーを指定する（"user:group" または "uid:gid"）
//     - Permission に Unix ソケットのファイルパーミッションを指定する
//     - Port, Address の指定を許容しない
//   - Mode: "tcp"
//     - CommandServer を TCP で listen する
//     - Port または Address のうち一方の指定を許可する
//     - Port を指定した場合、Address が ":{Port}" であるときの挙動になる
//     - Address を指定した場合、Address が直接 http.Server の Addr となる
//     - Path, Owner, Permission の指定を許容しない
type CommandServerConfig struct {
	Mode       string `yaml:"mode,omitempty"`
	Port       string `yaml:"port,omitempty"`
	Address    string `yaml:"address,omitempty"`
	Path       string `yaml:"path,omitempty"`
	Owner      string `yaml:"owner,omitempty"`      // 例: "user:group" または "uid:gid"
	Permission string `yaml:"permission,omitempty"` // 例: "0600", "600", "0o600"
}

func (c *CommandServerConfig) Normalize() (*CommandServerConfig, error) {
	if c == nil {
		return nil, errors.New("nil CommandServerConfig")
	}

	// 元の値を壊さないために最初にシャローコピーを作る
	n := *c

	// 空なら none 扱い
	if strings.TrimSpace(n.Mode) == "" {
		n.Mode = "none"
	}
	n.Mode = strings.ToLower(strings.TrimSpace(n.Mode))

	switch n.Mode {
	case "none":
		// Port/Address/Path/Owner/Permission は許容しない
		if n.Port != "" {
			return nil, fmt.Errorf(`mode "none" does not allow "port" (got %q)`, n.Port)
		}
		if n.Address != "" {
			return nil, fmt.Errorf(`mode "none" does not allow "address" (got %q)`, n.Address)
		}
		if n.Path != "" {
			return nil, fmt.Errorf(`mode "none" does not allow "path" (got %q)`, n.Path)
		}
		if n.Owner != "" {
			return nil, fmt.Errorf(`mode "none" does not allow "owner" (got %q)`, n.Owner)
		}
		if n.Permission != "" {
			return nil, fmt.Errorf(`mode "none" does not allow "permission" (got %q)`, n.Permission)
		}
		n.Mode = "none"
		return &n, nil

	case "disable":
		// 指定は無視（ここではクリーンに）
		n.Port, n.Address, n.Path, n.Owner, n.Permission = "", "", "", "", ""
		n.Mode = "disable"
		return &n, nil


	case "unix":
		// Port/Address は不可（フォーマット段階で弾く）
		if n.Port != "" || n.Address != "" {
			return nil, fmt.Errorf(`mode "unix" does not allow "port" (%q) or "address" (%q)`, n.Port, n.Address)
		}

		// Path 省略時はデフォルト、絶対パス化（副作用なし）
		if strings.TrimSpace(n.Path) == "" {
			n.Path = DefaultUnixSocketPath
		}
		abs, err := makeAbsolutePath(n.Path)
		if err != nil {
			return nil, fmt.Errorf(`invalid unix socket "path" %q: %w`, n.Path, err)
		}

		// Permission は省略可（デフォルト 0600）: 文字列の正規化のみ
		permStr := strings.TrimSpace(n.Permission)
		if permStr == "" {
			permStr = DefaultUnixSocketPermission
		}
		_, normPerm, err := parseAndNormalizeFileMode(permStr)
		if err != nil {
			return nil, fmt.Errorf(`invalid "permission" %q: %w`, n.Permission, err)
		}

		// Owner は任意: 文字列の正規化のみ（uid:gid）
		var normOwn string
		if strings.TrimSpace(n.Owner) != "" {
			_, _, norm, err := parseAndNormalizeOwner(n.Owner)
			if err != nil {
				return nil, fmt.Errorf(`invalid "owner" %q: %w`, n.Owner, err)
			}
			normOwn = norm
		}

		// ここではファイルシステムへ一切アクセスしない（副作用なし）
		n.Mode = "unix"
		n.Path = abs
		n.Permission = normPerm
		n.Owner = normOwn // 指定が無い場合は "" のまま
		n.Port, n.Address = "", ""
		return &n, nil

	case "tcp":
		// Path/Owner/Permission は不可
		if n.Path != "" {
			return nil, fmt.Errorf(`mode "tcp" does not allow "path" (got %q)`, n.Path)
		}
		if n.Owner != "" {
			return nil, fmt.Errorf(`mode "tcp" does not allow "owner" (got %q)`, n.Owner)
		}
		if n.Permission != "" {
			return nil, fmt.Errorf(`mode "tcp" does not allow "permission" (got %q)`, n.Permission)
		}
		// Port と Address は同時指定不可
		if n.Port != "" && n.Address != "" {
			return nil, errors.New(`mode "tcp" allows only one of "port" or "address"`)
		}

		if n.Port != "" {
			// port は数字のみを簡易チェック（サービス名は不可）
			if _, err := strconv.Atoi(n.Port); err != nil {
				return nil, fmt.Errorf(`invalid "port" %q: %w`, n.Port, err)
			}
			addr := ":" + n.Port
			if _, err := net.ResolveTCPAddr("tcp", addr); err != nil {
				return nil, fmt.Errorf(`failed to resolve addr from port (%q -> %q): %w`, n.Port, addr, err)
			}
			n.Address = addr
			n.Port = "" // 正規化として Address に寄せる
		} else if n.Address != "" {
			// Address 直接指定時はそのまま http.Server に渡せる形かを軽く検証
			if _, err := net.ResolveTCPAddr("tcp", n.Address); err != nil {
				return nil, fmt.Errorf(`invalid "address" %q: %w`, n.Address, err)
			}
		}
		n.Mode = "tcp"
		return &n, nil

	default:
		return nil, fmt.Errorf(`unknown mode %q (expected: none/disable/unix/tcp)`, n.Mode)
	}
}

// RetouchUnixSocket は、Normalize 済みの Unix ソケット設定に対して、
// 実ファイルの状態を検証し、必要に応じて chmod/chown を行う。
// ※ cfg 自体は変更しない（副作用はファイルシステムのみ）。
func RetouchUnixSocket(cfg *CommandServerConfig) error {
	if cfg == nil {
		return errors.New("nil config")
	}
	if cfg.Mode != "unix" {
		return fmt.Errorf("RetouchUnixSocket: mode must be \"unix\" (got %q)", cfg.Mode)
	}
	// 必須値の最低限チェック
	if strings.TrimSpace(cfg.Path) == "" {
		return errors.New(`RetouchUnixSocket: empty "path"`)
	}

	// path がディレクトリを指していないか確認
	if fi, err := os.Stat(cfg.Path); err == nil && fi.IsDir() {
		return fmt.Errorf(`unix socket "path" points to a directory: %q`, cfg.Path)
	}

	// 既存ソケットがある場合：
	//  1) in-use かを Dial で確認
	//  2) in-use でなければ permission/owner を整える
	if st, err := os.Lstat(cfg.Path); err == nil {
		// 1) in-use チェック
		if conn, dialErr := net.DialTimeout("unix", cfg.Path, 200*time.Millisecond); dialErr == nil {
			_ = conn.Close()
			return fmt.Errorf(`unix socket %q is already in use (someone is listening)`, cfg.Path)
		}

		// 2) permission/owner を整備
		// permission
		if strings.TrimSpace(cfg.Permission) != "" {
			wantMode, _, err := parseAndNormalizeFileMode(cfg.Permission)
			if err != nil {
				return fmt.Errorf(`RetouchUnixSocket: invalid "permission" %q: %w`, cfg.Permission, err)
			}
			if st.Mode().Perm() != wantMode.Perm() {
				if err := os.Chmod(cfg.Path, wantMode); err != nil {
					return fmt.Errorf(`chmod failed for %q: want=%04o: %w`, cfg.Path, wantMode.Perm(), err)
				}
			}
		}

		// owner
		if strings.TrimSpace(cfg.Owner) != "" {
			wantUID, wantGID, _, err := parseAndNormalizeOwner(cfg.Owner)
			if err != nil {
				return fmt.Errorf(`RetouchUnixSocket: invalid "owner" %q: %w`, cfg.Owner, err)
			}
			if curUID, curGID, ok := fileOwner(st); ok &&
				(curUID != wantUID || curGID != wantGID) {
				if err := os.Chown(cfg.Path, int(wantUID), int(wantGID)); err != nil {
					return fmt.Errorf(`chown failed for %q: want=%d:%d: %w`, cfg.Path, wantUID, wantGID, err)
				}
			}
		}
	}

	return nil
}

// "~" 展開 → 絶対パス化
func makeAbsolutePath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", errors.New("empty path")
	}

	// "~" または "~/..." 展開
	if p == "~" || strings.HasPrefix(p, "~"+string(os.PathSeparator)) {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			if err == nil {
				err = errors.New("user home not found")
			}
			return "", fmt.Errorf("expand ~: %w", err)
		}
		if p == "~" {
			p = home
		} else {
			p = filepath.Join(home, strings.TrimPrefix(p, "~"+string(os.PathSeparator)))
		}
	}

	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("to absolute: %w", err)
	}
	return abs, nil
}

// パーミッション文字列を受け取り、os.FileMode とゼロ埋め 4 桁の 8 進文字列へ正規化する。
// 受理: "600", "0600", "0o600", "0O600"。範囲: 0000–0777。
func parseAndNormalizeFileMode(s string) (os.FileMode, string, error) {
	in := strings.TrimSpace(s)
	in = strings.TrimPrefix(in, "0o")
	in = strings.TrimPrefix(in, "0O")

	// "600" のような 3 桁も許容する（内部で 4 桁に揃える）
	v, err := strconv.ParseUint(in, 8, 16)
	if err != nil {
		return 0, "", fmt.Errorf("parse octal: %w", err)
	}
	if v > 0o777 {
		return 0, "", fmt.Errorf("out of range %04o (must be <= 0777)", v)
	}
	mode := os.FileMode(v)
	return mode, fmt.Sprintf("%04o", v), nil
}

// Owner 文字列を受け取り、uid/gid と正規化文字列 "uid:gid" を返す。
// 受理: "user:group" または "uid:gid"（いずれも両方必須）。空や片方のみはエラー。
func parseAndNormalizeOwner(s string) (uid, gid uint32, normalized string, err error) {
	in := strings.TrimSpace(s)
	if in == "" {
		return 0, 0, "", errors.New("empty owner")
	}
	parts := strings.Split(in, ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return 0, 0, "", fmt.Errorf("owner must be in the form \"user:group\" or \"uid:gid\" (got %q)", s)
	}

	// user / uid
	var uID uint64
	if isDigits(parts[0]) {
		uID, err = strconv.ParseUint(parts[0], 10, 32)
		if err != nil {
			return 0, 0, "", fmt.Errorf("invalid uid %q: %w", parts[0], err)
		}
	} else {
		uu, err := user.Lookup(parts[0])
		if err != nil {
			return 0, 0, "", fmt.Errorf("lookup user %q: %w", parts[0], err)
		}
		uID, err = strconv.ParseUint(uu.Uid, 10, 32)
		if err != nil {
			return 0, 0, "", fmt.Errorf("parse uid %q: %w", uu.Uid, err)
		}
	}

	// group / gid
	var gID uint64
	if isDigits(parts[1]) {
		gID, err = strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return 0, 0, "", fmt.Errorf("invalid gid %q: %w", parts[1], err)
		}
	} else {
		gg, err := user.LookupGroup(parts[1])
		if err != nil {
			return 0, 0, "", fmt.Errorf("lookup group %q: %w", parts[1], err)
		}
		gID, err = strconv.ParseUint(gg.Gid, 10, 32)
		if err != nil {
			return 0, 0, "", fmt.Errorf("parse gid %q: %w", gg.Gid, err)
		}
	}

	return uint32(uID), uint32(gID), fmt.Sprintf("%d:%d", uID, gID), nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// os.FileInfo から (uid,gid) を取得。Unix 前提。取得できない場合は ok=false を返す。
func fileOwner(fi os.FileInfo) (uid, gid uint32, ok bool) {
	if fi == nil {
		return 0, 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, 0, false
	}
	return st.Uid, st.Gid, true
}

type BackendConfig struct {
	TargetURL    string `yaml:"target_url"`
	Route        string `yaml:"route,omitempty"`
	RemovePrefix bool   `yaml:"remove_prefix,omitempty"`
}

var configPriorityList = []string{
	"./config.yml",
	"./config.yaml",
	"~/.prism/config.yml",
	"~/.prism/config.yaml",
	"~/.config/prism/config.yml",
	"~/.config/prism/config.yaml",
}

// GetTopPriorityConfig は優先順リスト内で実在する最初の設定ファイルを返す。
// 見つからない場合は空文字と nil を返す。
func GetTopPriorityConfig() (string, error) {
	home, _ := os.UserHomeDir()

	sep := string(os.PathSeparator)
	prefix := "~" + sep // "~/" or "~\"

	seen := make(map[string]struct{})

	for _, in := range configPriorityList {
		p := in

		// ~ 展開（"~" と "~/" / "~\"）
		if p == "~" || strings.HasPrefix(p, prefix) {
			if home == "" {
				return "", fmt.Errorf("expand home for %q: %w", in, errors.New("couldn't get user home directory"))
			}
			if p == "~" {
				p = home
			} else {
				p = filepath.Join(home, p[2:])
			}
		}

		// 正規化 → 絶対パス化
		p = filepath.Clean(p)
		abs, err := filepath.Abs(p)
		if err != nil {
			return "", fmt.Errorf("abspath for %q: %w", in, err)
		}

		// 存在確認（通常ファイルのみ。リンクは実体を辿る）
		fi, err := os.Stat(abs)
		if err != nil {
			continue // 存在しない/権限なし等はスキップ
		}
		if !fi.Mode().IsRegular() {
			continue
		}

		// 重複除外
		if _, ok := seen[abs]; ok {
			continue
		}
		seen[abs] = struct{}{}

		// 最初に見つかったものを返す
		return abs, nil
	}

	// どれも存在しなければ空文字
	return "", nil
}

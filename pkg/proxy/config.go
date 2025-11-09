package proxy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/wsuzume/prism/pkg/csrf"
)

type Config struct {
	AesGcmJwtConfig csrf.AesGcmJwtConfig `yaml:"aes_gcm_jwt,omitempty"`
	Backends map[string]BackendConfig `yaml:"backends,omitempty"`
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

func (c *Config) String() string {
	b, err := yaml.Marshal(c)
	if err != nil {
		// Marshal に失敗することはほぼないが、念のためエラー内容を含める
		return fmt.Sprintf("Config<error: %v>", err)
	}
	return string(b)
}
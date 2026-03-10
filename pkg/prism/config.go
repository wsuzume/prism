package prism

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/wsuzume/prism/pkg/domain"
)

type ProxyConfig struct {
	BaseDomain string `yaml:"base_domain,omitempty"`
}

type CookieConfig struct {
	Domain string `yaml:"domain,omitempty"`
	Secure bool   `yaml:"secure,omitempty"`
}

type BackendConfig struct {
	TargetURL string `yaml:"target_url"`
	Hostname  string `yaml:"hostname,omitempty"`
}

type PrismConfig struct {
	ProxyConfig  ProxyConfig              `yaml:"proxy_config,omitempty"`
	CookieConfig CookieConfig             `yaml:"cookie_config,omitempty"`
	Backends     map[string]BackendConfig `yaml:"backends,omitempty"`
}

func (c *PrismConfig) String() string {
	b, err := yaml.Marshal(c)
	if err != nil {
		// Marshal に失敗することはほぼないが、念のためエラー内容を含める
		return fmt.Sprintf("Config<error: %v>", err)
	}
	return string(b)
}

func (c *PrismConfig) NormalizedBackends() map[string]string {
	if c.Backends == nil {
		return nil
	}

	bs := make(map[string]string, len(c.Backends))
	for k, b := range c.Backends {
		key := k
		if b.Hostname != "" {
			key = b.Hostname
		}
		if k == "default" {
			key = "" // default は空文字ホスト名にマッピング
		}
		bs[key] = domain.NormalizeHost(b.TargetURL)
	}

	return bs
}

func LoadConfig(path string) (*PrismConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg PrismConfig
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

var configPriorityList = []string{
	"./config.yml",
	"./config.yaml",
	"./.prism/config.yml",
	"./.prism/config.yml",
	"~/.prism/config.yml",
	"~/.prism/config.yaml",
	"~/.config/prism/config.yml",
	"~/.config/prism/config.yaml",
}

// GetTopPriorityConfig は優先順リスト内で実在する最初の設定ファイルを返す。
// 見つからない場合は空文字と nil を返す。
func GetTopPriorityConfigPath() (string, error) {
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

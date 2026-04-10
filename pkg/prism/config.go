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

// 仕様：
// - BaseDomain の指定がない場合はサブドメインによる振り分けができないため、警告を表示して main のみをルーティングする。

type ProxyConfig struct {
	BaseDomain   string `yaml:"base_domain,omitempty"`   // ルーティングの基準となるドメイン。例: "example.com"。
	MainTenant   string `yaml:"main_tenant,omitempty"`   // サブドメインが与えられなかった場合を意味するキー。デフォルト値は main である。
	DefaultRoute string `yaml:"default_route,omitempty"` // 合致するルートがない場合を意味するキー。デフォルト値は default である。
	Port         string `yaml:"port,omitempty"`          // リッスンするポート番号。デフォルト値は 8080 である。
}

func (p *ProxyConfig) IsMainTenant(host string) bool {
	if p == nil || p.MainTenant == "" {
		return host == "" || host == "main"
	}
	return host == "" || host == p.MainTenant
}

func (p *ProxyConfig) IsDefaultRoute(route string) bool {
	if p == nil || p.DefaultRoute == "" {
		return route == "" || route == "default"
	}
	return route == "" || route == p.DefaultRoute
}

func (p *ProxyConfig) NormalizeTenant(host string) string {
	if p.IsMainTenant(host) {
		return ""
	}
	return host
}

func (p *ProxyConfig) NormalizeRoute(route string) string {
	if p.IsDefaultRoute(route) {
		return ""
	}
	return route
}

type CookieConfig struct {
	Domain string `yaml:"domain,omitempty"`
	Secure bool   `yaml:"secure,omitempty"`
}

type BackendConfig struct {
	Targets  []string `yaml:"targets"`
	Hostname string   `yaml:"hostname,omitempty"`
}

func (b *BackendConfig) NormalizeTargets() []string {
	normalized := make([]string, len(b.Targets))
	for i, target := range b.Targets {
		normalized[i] = domain.NormalizeHost(target)
	}
	return normalized
}

func (b *BackendConfig) Normalize() *BackendConfig {
	return &BackendConfig{
		Targets:  b.NormalizeTargets(),
		Hostname: b.Hostname,
	}
}

type PrismConfig struct {
	ProxyConfig  *ProxyConfig                         `yaml:"proxy_config,omitempty"`
	CookieConfig *CookieConfig                        `yaml:"cookie_config,omitempty"`
	Backends     map[string]map[string]*BackendConfig `yaml:"backends,omitempty"`
}

func (c *PrismConfig) String() string {
	b, err := yaml.Marshal(c)
	if err != nil {
		// Marshal に失敗することはほぼないが、念のためエラー内容を含める
		return fmt.Sprintf("Config<error: %v>", err)
	}
	return string(b)
}

func (c *PrismConfig) IsProxyConfigEmpty() bool {
	return c.ProxyConfig == nil
}

func (c *PrismConfig) IsBaseDomainEmpty() bool {
	return c.ProxyConfig == nil || c.ProxyConfig.BaseDomain == ""
}

func (c *PrismConfig) IsCookieConfigEmpty() bool {
	return c.CookieConfig == nil
}

func (c *PrismConfig) IsBackendsEmpty() bool {
	return c.Backends == nil || len(c.Backends) == 0
}

func (c *PrismConfig) Validate() error {
	if c.IsBackendsEmpty() {
		// バックエンドが空の場合はエコーモードで起動するためエラーではない
		return nil
	}

	for host, routes := range c.Backends {
		for route, cfg := range routes {
			if len(cfg.Targets) == 0 {
				return fmt.Errorf("backend %q route %q: target is required", host, route)
			}
			// if !strings.HasPrefix(cfg.Target, "http://") && !strings.HasPrefix(cfg.Target, "https://") {
			// 	return fmt.Errorf("backend %q route %q: target must start with http:// or https://", host, route)
			// }
		}
	}

	return nil
}

func (c *PrismConfig) NormalizeBackends() map[string]map[string]*BackendConfig {
	if c.IsBackendsEmpty() {
		return nil
	}

	bs := make(map[string]map[string]*BackendConfig, len(c.Backends))
	for tenant, routes := range c.Backends {
		t := c.ProxyConfig.NormalizeTenant(tenant)
		bs[t] = make(map[string]*BackendConfig, len(routes))
		for route, backend := range routes {
			r := c.ProxyConfig.NormalizeRoute(route)
			bs[t][r] = backend.Normalize()
		}
	}
	return bs
}

func (c *PrismConfig) Normalize() *PrismConfig {
	return &PrismConfig{
		ProxyConfig:  c.ProxyConfig,  // ProxyConfig は正規化不要
		CookieConfig: c.CookieConfig, // CookieConfig は正規化不要
		Backends:     c.NormalizeBackends(),
	}
}

func EmptyConfig() *PrismConfig {
	return &PrismConfig{
		ProxyConfig:  nil,
		CookieConfig: nil,
		Backends:     nil,
	}
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

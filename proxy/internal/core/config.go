package core

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Mode string `yaml:"mode"` // DEVELOP or PRODUCT

	TLS struct {
		Domains  []string `yaml:"domains"`
		CacheDir string   `yaml:"cache_dir"`
	} `yaml:"tls"`

	AllowedOrigins []string                 `yaml:"allowed_origins"`
	IdentityCenterAddresses []string          `yaml:"identity_center_addresses"`
	Backends       map[string]BackendConfig `yaml:"backends"`
}

type BackendConfig struct {
	TargetURL    string `yaml:"target_url"`
	Route        string `yaml:"route,omitempty"`
	RemovePrefix bool   `yaml:"remove_prefix,omitempty"`
}

func LoadConfig() (*Config, error) {
	path := os.Getenv("CONFIG_PATH")
	if path == "" {
		path = "./config.yml"
	}
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

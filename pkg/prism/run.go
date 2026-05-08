package prism

import (
	"log"
)

func Run(configPath string, port string) {
	verbose := true

	////  Config の読み取り  ////

	var cfg *PrismConfig
	var err error

	// configPath が指定されていない場合は、優先順位の高い場所から config を探す
	path := configPath
	if path == "" {
		path, err = GetTopPriorityConfigPath()
		if err != nil {
			log.Fatal(err)
		}
	}

	if path == "" {
		// config ファイルが見つからない場合は、空の config を使用する
		if verbose {
			log.Println("no config file found, using empty config")
		}
		cfg = EmptyConfig()
	} else {
		// config ファイルが見つかった場合は、読み込む
		if verbose {
			log.Printf("found config file at %q, loading...", path)
		}
		cfg, err = LoadConfig(path)
		if err != nil {
			log.Fatal(err)
		}
	}

	// 読み込んだ config を表示する
	if verbose {
		log.Printf("loaded config from %q:\n%+v\n", path, cfg)
	}

	if port != "" {
		if cfg.ProxyConfig == nil {
			cfg.ProxyConfig = &ProxyConfig{}
		}
		cfg.ProxyConfig.Port = port
		log.Printf("overriding port to %q", port)
	}

	if err := cfg.Validate(); err != nil {
		log.Fatalf("invalid config: %v", err)
	}

	cfg = cfg.Normalize()

	log.Printf("loaded config from %q (normalized):\n%+v\n", path, cfg)

	////  サーバー起動  ////

	if cfg.IsBackendsEmpty() {
		RunEchoServer(cfg)
	} else {
		RunReverseProxyServer(cfg)
	}
}

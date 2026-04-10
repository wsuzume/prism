package prism

import (
	"fmt"
	"log"
)

func Run(configPath string) {
	verbose := true

	////  Config の読み取り  ////

	var cfg *PrismConfig
	var err error

	path := configPath
	if path == "" {
		path, err = GetTopPriorityConfigPath()
		if err != nil {
			log.Fatal(err)
		}
	}

	if path == "" {
		if verbose {
			log.Println("no config file found, using empty config")
		}
		cfg = EmptyConfig()
	} else {
		if verbose {
			log.Printf("found config file at %q, loading...", path)
		}
		cfg, err = LoadConfig(path)
		if err != nil {
			log.Fatal(err)
		}
	}

	if verbose {
		fmt.Printf("loaded config from %q:\n%+v\n", path, cfg)
	}

	if err := cfg.Validate(); err != nil {
		log.Fatalf("invalid config: %v", err)
	}

	cfg = cfg.Normalize()

	fmt.Printf("loaded config from %q (normalized):\n%+v\n", path, cfg)

	////  サーバー起動  ////

	if cfg.IsBackendsEmpty() {
		RunEchoServer(cfg)
	} else {
		RunReverseProxyServer(cfg)
	}
}

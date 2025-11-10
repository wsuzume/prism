package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/wsuzume/prism/pkg/proxy"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Show config",
	Run: func(cmd *cobra.Command, args []string) {
		path, err := proxy.GetTopPriorityConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to find config file: %v\n", err)
			os.Exit(1)
		}

		cfg, err := proxy.LoadConfig(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
			os.Exit(1)
		}

		cfg, err = cfg.Normalize()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to normalize config: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Config loaded from %s\n", path)
		fmt.Println(cfg.String())
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}

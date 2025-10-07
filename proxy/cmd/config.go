package cmd

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/spf13/cobra"

	"github.com/wsuzume/prism/proxy/internal/core"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Show loaded config",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := core.LoadConfig()
		if err != nil {
			log.Fatalf("load config: %v", err)
		}
		out, _ := json.MarshalIndent(cfg, "", "  ")
		fmt.Println(string(out))
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}

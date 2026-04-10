package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/wsuzume/prism/pkg/prism"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "show config",
	Run: func(cmd *cobra.Command, args []string) {
		path := configFile
		if path == "" {
			var err error
			path, err = prism.GetTopPriorityConfigPath()
			if err != nil {
				fmt.Printf("prism config error: %v\n", err)
			}
		}

		config, _ := prism.LoadConfig(path)

		fmt.Println(config.String())
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}

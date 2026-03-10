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
		path, err := prism.GetTopPriorityConfigPath()
		if err != nil {
			fmt.Printf("prism config error: %v\n", err)
		}

		config, err := prism.LoadConfig(path)

		fmt.Println(config.String())
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}

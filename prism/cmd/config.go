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

		if path == "" {
			fmt.Println("no config file found")
			fmt.Println()
			fmt.Println("specify a config file with the -f flag:")
			fmt.Println("  prism -f /path/to/config.yml config")
			fmt.Println()
			fmt.Println("or place a config file in one of the following locations (highest priority first):")
			for _, p := range prism.GetConfigPriorityList() {
				fmt.Printf("  %s\n", p)
			}
			fmt.Println()
			fmt.Println("run 'prism generate' to output a config template.")
			return
		}

		config, _ := prism.LoadConfig(path)

		fmt.Println(config.String())
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}

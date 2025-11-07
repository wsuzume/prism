package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/wsuzume/prism/pkg/mode"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Prism version 0.0.1")
		if mode.Debug {
			fmt.Println("Build mode: debug")
		}
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

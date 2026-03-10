package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/wsuzume/prism/pkg/prism"
)

var rootCmd = &cobra.Command{
	Use: "app",
	Run: func(cmd *cobra.Command, args []string) {
		prism.Run()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

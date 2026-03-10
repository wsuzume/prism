package cmd

import (
	"github.com/spf13/cobra"

	"github.com/wsuzume/prism/pkg/prism"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "start HTTP server",
	Run: func(cmd *cobra.Command, args []string) {
		prism.Run()
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

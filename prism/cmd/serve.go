package cmd

import (
	"github.com/spf13/cobra"
	"github.com/wsuzume/prism/pkg/prism"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Prism Reverse Proxy",
	Run:   runReverseProxy,
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

func runReverseProxy(cmd *cobra.Command, args []string) {
	prism.Run()
}
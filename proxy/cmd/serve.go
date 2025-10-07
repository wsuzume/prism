package cmd

import (
	"github.com/spf13/cobra"
	"github.com/wsuzume/prism/proxy/internal/server" // loadConfig があるパッケージ
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Prism server",
	Run:   server.RunReverseProxy,
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

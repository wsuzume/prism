package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/wsuzume/prism/pkg/prism"
)

var configFile string
var port string

var rootCmd = &cobra.Command{
	Use: "prism",
	Run: func(cmd *cobra.Command, args []string) {
		prism.Run(configFile, port)
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&configFile, "file", "f", "", "config file path")
	rootCmd.PersistentFlags().StringVarP(&port, "port", "p", "", "port number to listen on")
}

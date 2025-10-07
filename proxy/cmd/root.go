package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/wsuzume/prism/proxy/internal/server"
)

var rootCmd = &cobra.Command{
	Use:          "prism",
	Short:        "Prism is a reverse proxy server with config",
	SilenceUsage: true,                   // エラー時に usage を自動表示しない
	Run:          server.RunReverseProxy, // 追加: デフォルトで serve 相当を実行
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

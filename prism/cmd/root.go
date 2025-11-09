package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	
)

var rootCmd = &cobra.Command{
	Use:          "prism",
	Short:        "Prism is a reverse proxy server with config",
	SilenceUsage: true,          // エラー時に usage を自動表示しない
	Run:          runReverseProxy, // 追加: デフォルトで serve 相当を実行
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func RunHelloWorld(cmd *cobra.Command, args []string) {
	fmt.Println("Hello World!!")
}

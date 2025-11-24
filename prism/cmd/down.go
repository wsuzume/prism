package cmd

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/spf13/cobra"
)

var downCmd = &cobra.Command{
	Use:   "down",
	Short: "shutdown via socket",
	Run: func(cmd *cobra.Command, args []string) {
		const sock = "/tmp/prism.sock"

		// Unix ソケット専用の http.Client を作る
		client := &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					// network/addr は無視して Unix ソケットに接続
					return net.Dial("unix", sock)
				},
			},
		}
		// addr はダミーでよい（http.Client 的には必要なため）
		resp, err := client.Post("http://unix/down", "text/plain", nil)
		if err != nil {
			panic(err)
		}
		defer resp.Body.Close()

		var body []byte
		body, _ = io.ReadAll(resp.Body)
		fmt.Println(string(body))
	},
}

func init() {
	rootCmd.AddCommand(downCmd)
}

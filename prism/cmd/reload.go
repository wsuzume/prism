package cmd

import (
	"bufio"
	"fmt"
	"net"

	"github.com/spf13/cobra"

)

var reloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "reload via socket",
	Run: func(cmd *cobra.Command, args []string) {
		const sock = "/tmp/mydaemon.sock"

		c, err := net.Dial("unix", sock)
		if err != nil {
			panic(err)
		}
		defer c.Close()

		// 例: コマンドを1行で送る
		fmt.Fprintln(c, "reload")

		// 応答を受け取る
		r := bufio.NewReader(c)
		resp, _ := r.ReadString('\n')
		fmt.Print(resp)
	},
}

func init() {
	rootCmd.AddCommand(reloadCmd)
}

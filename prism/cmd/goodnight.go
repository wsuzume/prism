package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var goodNightCmd = &cobra.Command{
	Use:   "goodnight",
	Short: "say good night",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Good night, baby.")
	},
}

func init() {
	rootCmd.AddCommand(goodNightCmd)
}

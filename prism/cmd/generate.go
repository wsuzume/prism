package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/wsuzume/prism/pkg/prism"
)

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "output a config template to stdout",
	Run: func(cmd *cobra.Command, args []string) {
		cfg := &prism.PrismConfig{
			ProxyConfig: &prism.ProxyConfig{
				BaseDomain:   "example.com",
				MainTenant:   "main",
				DefaultRoute: "default",
				Port:         "8080",
			},
			CookieConfig: &prism.CookieConfig{
				Domain: "example.com",
				Secure: true,
			},
			Backends: map[string]map[string]*prism.BackendConfig{
				"main": {
					"default": {
						Targets: []string{"http://localhost:3000"},
					},
				},
			},
		}

		b, err := yaml.Marshal(cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(string(b))
	},
}

func init() {
	rootCmd.AddCommand(generateCmd)
}

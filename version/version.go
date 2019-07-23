package version

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"
)

var (
	Build        = ""
	GitSHA       = ""
	GoLoomGitSHA = ""
	EthGitSHA    = ""
	BtcdGitSHA   = ""
)

func FullVersion() string {
	version := Build
	if Build == "" {
		version = "dev"
	}
	return version + "@" + GitSHA
}

func printEnv(env map[string]string) {
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	for _, key := range keys {
		val := env[key]
		fmt.Printf("%s = %s\n", key, val)
	}
}

func NewVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show the Oracle version",
		RunE: func(cmd *cobra.Command, args []string) error {
			println(FullVersion())
			return nil
		},
	}
}

func NewEnvCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "env",
		Short: "Show loom config settings",
		RunE: func(cmd *cobra.Command, args []string) error {
			printEnv(map[string]string{
				"version":     FullVersion(),
				"build":       Build,
				"git sha":     GitSHA,
				"go-loom":     GoLoomGitSHA,
				"go-ethereum": EthGitSHA,
				"go-btcd":     BtcdGitSHA,
			})
			return nil
		},
	}
}

// +build evm

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/loomnetwork/transfer-gateway/gateway"
	"github.com/loomnetwork/transfer-gateway/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type LoomConfig struct {
	ChainID             string
	RPCProxyPort        int32
	TronTransferGateway *gateway.TransferGatewayConfig
}

func main() {
	cmd := &cobra.Command{
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := parseConfig(nil)
			if err != nil {
				panic(err)
			}

			orc, err := gateway.CreateTronOracle(cfg.TronTransferGateway, cfg.ChainID)
			if err != nil {
				panic(err)
			}

			go orc.RunWithRecovery()

			http.HandleFunc("/status", func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(orc.Status())
			})

			http.Handle("/metrics", promhttp.Handler())

			log.Fatal(http.ListenAndServe(cfg.TronTransferGateway.OracleQueryAddress, nil))
			return nil
		},
	}
	cmd.AddCommand(
		version.NewVersionCommand(),
		version.NewEnvCommand(),
	)
	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// Loads loom.yml or equivalent from one of the usual location, or if overrideCfgDirs is provided
// from one of those config directories.
func parseConfig(overrideCfgDirs []string) (*LoomConfig, error) {
	v := viper.New()
	v.SetConfigName("loom")
	if len(overrideCfgDirs) == 0 {
		// look for the loom config file in all the places loom itself does
		v.AddConfigPath(".")
		v.AddConfigPath(filepath.Join(".", "config"))
	} else {
		for _, dir := range overrideCfgDirs {
			v.AddConfigPath(dir)
		}
	}
	v.ReadInConfig()
	conf := &LoomConfig{
		ChainID:             "default",
		RPCProxyPort:        46658,
		TronTransferGateway: gateway.DefaultTronConfig(46658),
	}
	err := v.Unmarshal(conf)
	if err != nil {
		return nil, err
	}
	return conf, err
}

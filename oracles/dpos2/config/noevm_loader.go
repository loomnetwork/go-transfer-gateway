// +build !evm

package config

import oracle "github.com/loomnetwork/transfer-gateway/oracles/dpos2"

func LoadSerializableConfig(chainID string, serializableConfig *OracleSerializableConfig) (*oracle.Config, error) {
	return &oracle.Config{
		Enabled: false,
	}, nil
}

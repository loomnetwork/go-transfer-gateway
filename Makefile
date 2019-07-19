PKG = github.com/loomnetwork/transfer-gateway

PLUGIN_DIR = $(GOPATH)/src/github.com/loomnetwork/go-loom
LOOMCHAIN_DIR = $(GOPATH)/src/github.com/loomnetwork/loomchain
GOLANG_PROTOBUF_DIR = $(GOPATH)/src/github.com/golang/protobuf
GENPROTO_DIR = $(GOPATH)/src/google.golang.org/genproto
GOGO_PROTOBUF_DIR = $(GOPATH)/src/github.com/gogo/protobuf
GRPC_DIR = $(GOPATH)/src/google.golang.org/grpc
GO_ETHEREUM_DIR = $(GOPATH)/src/github.com/ethereum/go-ethereum
SSHA3_DIR = $(GOPATH)/src/github.com/miguelmota/go-solidity-sha3
HASHICORP_DIR = $(GOPATH)/src/github.com/hashicorp/go-plugin
LEVIGO_DIR = $(GOPATH)/src/github.com/jmhodges/levigo
BTCD_DIR = $(GOPATH)/src/github.com/btcsuite/btcd
IAVL_DIR = $(GOPATH)/src/github.com/tendermint/iavl
TENDERMINT_DIR = $(GOPATH)/src/github.com/tendermint/tendermint
GO_AMINO_DIR = $(GOPATH)/src/github.com/tendermint/go-amino
TENDERMINT_BTCD_DIR = $(GOPATH)/src/github.com/tendermint/btcd
YUBIHSM_DIR = $(GOPATH)/src/github.com/certusone/yubihsm-go

# NOTE: To build on Jenkins using a custom go-loom branch update the `deps` target below to checkout
#       that branch, you only need to update GO_LOOM_GIT_REV if you wish to lock the build to a
#       specific commit.
GO_LOOM_GIT_REV = HEAD
LOOMCHAIN_GIT_REV = HEAD
# loomnetwork/go-ethereum loomchain branch
ETHEREUM_GIT_REV = 1fb6138d017a4309105d91f187c126cf979c93f9
# use go-plugin we get 'timeout waiting for connection info' error
HASHICORP_GIT_REV = f4c3476bd38585f9ec669d10ed1686abd52b9961
LEVIGO_GIT_REV = c42d9e0ca023e2198120196f842701bb4c55d7b9
BTCD_GIT_REV = 7d2daa5bfef28c5e282571bc06416516936115ee
YUBIHSM_REV = 0299fd5d703d2a576125b414abbe172eaec9f65e
# This is locked down to this particular revision because this is the last revision before the
# google.golang.org/genproto was recompiled with a new version of protoc, which produces pb.go files
# that don't appear to be compatible with the gogo protobuf & protoc versions we use.
# google.golang.org/genproto seems to be pulled in by the grpc package.
GENPROTO_GIT_REV = b515fa19cec88c32f305a962f34ae60068947aea
IAVL_GIT_REV = tmreal2
TENDERMINT_GIT_REV = loomchain

BUILD_DATE = `date -Iseconds`
GIT_SHA = `git rev-parse --verify HEAD`
GO_LOOM_GIT_SHA = `cd ${PLUGIN_DIR} && git rev-parse --verify ${GO_LOOM_GIT_REV}`
ETHEREUM_GIT_SHA = `cd ${GO_ETHEREUM_DIR} && git rev-parse --verify ${ETHEREUM_GIT_REV}`
HASHICORP_GIT_SHA = `cd ${HASHICORP_DIR} && git rev-parse --verify ${HASHICORP_GIT_REV}`
BTCD_GIT_SHA = `cd ${BTCD_DIR} && git rev-parse --verify ${BTCD_GIT_REV}`

GOFLAGS_BASE = \
	-X $(PKG).Build=$(BUILD_NUMBER) \
	-X $(PKG).GitSHA=$(GIT_SHA) \
	-X $(PKG).GoLoomGitSHA=$(GO_LOOM_GIT_SHA) \
	-X $(PKG).EthGitSHA=$(ETHEREUM_GIT_SHA) \
	-X $(PKG).HashicorpGitSHA=$(HASHICORP_GIT_SHA) \
	-X $(PKG).BtcdGitSHA=$(BTCD_GIT_SHA)
GOFLAGS = -tags "evm gateway" -ldflags "$(GOFLAGS_BASE)"
GOFLAGS_NOEVM = -tags "gateway" -ldflags "$(GOFLAGS_BASE)"

E2E_TESTS_TIMEOUT = 20m

.PHONY: all clean test get_lint update_lint deps oracles lint

all: loom

oracles: tgoracle loomcoin_tgoracle tron_tgoracle

tgoracle:
	go build $(GOFLAGS) -o $@ $(PKG)/cmd/$@

loomcoin_tgoracle:
	go build $(GOFLAGS) -o $@ $(PKG)/cmd/$@

tron_tgoracle:
	go build $(GOFLAGS) -o $@ $(PKG)/cmd/$@

$(PLUGIN_DIR):
	git clone -q git@github.com:loomnetwork/go-loom.git $@

$(GO_ETHEREUM_DIR):
	git clone -q git@github.com:loomnetwork/go-ethereum.git $@

$(SSHA3_DIR):
	git clone -q git@github.com:loomnetwork/go-solidity-sha3.git $@

$(IAVL_DIR):
	git clone -q git@github.com:loomnetwork/iavl.git $@

$(TENDERMINT_DIR):
	git clone -q git@github.com:loomnetwork/tendermint.git $@

deps: $(PLUGIN_DIR) $(LOOMCHAIN_DIR) $(GO_ETHEREUM_DIR) $(SSHA3_DIR) $(IAVL_DIR) $(TENDERMINT_DIR)
	go get \
		golang.org/x/crypto/ed25519 \
		google.golang.org/grpc \
		github.com/gogo/protobuf/gogoproto \
		github.com/gogo/protobuf/proto \
		github.com/hashicorp/go-plugin \
		github.com/spf13/cobra \
		github.com/spf13/pflag \
		github.com/go-kit/kit/log \
		github.com/grpc-ecosystem/go-grpc-prometheus \
		github.com/prometheus/client_golang/prometheus \
		github.com/go-kit/kit/log \
		github.com/BurntSushi/toml \
		github.com/ulule/limiter \
		github.com/loomnetwork/mamamerkle \
		golang.org/x/sys/cpu \
		github.com/certusone/yubihsm-go \
		github.com/gorilla/websocket \
		github.com/phonkee/go-pubsub \
		github.com/inconshreveable/mousetrap \
		github.com/posener/wstest \
		github.com/btcsuite/btcd \
		github.com/allegro/bigcache \
		github.com/gomodule/redigo/redis \
		github.com/hashicorp/golang-lru \
		github.com/stretchr/testify \
		github.com/syndtr/goleveldb/leveldb \
		github.com/tendermint/go-amino \
		github.com/tendermint/btcd/btcec

	cd $(PLUGIN_DIR) && git checkout master && git pull && git checkout $(GO_LOOM_GIT_REV)
	cd $(LOOMCHAIN_DIR) && git checkout master && git pull && git checkout $(LOOMCHAIN_GIT_REV)
	cd $(IAVL_DIR) && git checkout master && git pull && git checkout $(IAVL_GIT_REV)
	cd $(GOLANG_PROTOBUF_DIR) && git checkout v1.1.0
	cd $(GOGO_PROTOBUF_DIR) && git checkout v1.1.1
	cd $(GRPC_DIR) && git checkout v1.20.1
	cd $(GENPROTO_DIR) && git checkout master && git pull && git checkout $(GENPROTO_GIT_REV)
	cd $(GO_ETHEREUM_DIR) && git checkout master && git pull && git checkout $(ETHEREUM_GIT_REV)
	cd $(HASHICORP_DIR) && git checkout $(HASHICORP_GIT_REV)
	cd $(BTCD_DIR) && git checkout $(BTCD_GIT_REV)
	cd $(GO_AMINO_DIR) && git checkout v0.14.0
	cd $(TENDERMINT_BTCD_DIR) && git checkout e5840949ff4fff0c56f9b6a541e22b63581ea9df
	cd $(YUBIHSM_DIR) && git checkout master && git pull && git checkout $(YUBIHSM_REV)
	# fetch vendored packages
	dep ensure -vendor-only

vendor-deps:
	dep ensure -vendor-only

test:
	go test -failfast -timeout $(E2E_TESTS_TIMEOUT) -v $(GOFLAGS) $(PKG)/...

test-race:
	go test -race -failfast -timeout $(E2E_TESTS_TIMEOUT) -v $(GOFLAGS) $(PKG)/...

test-no-evm:
	go test -failfast -timeout $(E2E_TESTS_TIMEOUT) -v $(GOFLAGS_NOEVM) $(PKG)/...

# Only builds the tests with the EVM disabled, but doesn't actually run them.
no-evm-tests:
	go test -failfast -v -vet=off $(GOFLAGS_NOEVM) -run nothing $(PKG)/...

vet:
	go vet ./...

vet-evm:
	go vet -tags evm ./...

clean:
	go clean
	rm -f \
		pcoracle

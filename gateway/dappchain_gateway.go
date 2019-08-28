package gateway

import (
	"time"

	loom "github.com/loomnetwork/go-loom"
	"github.com/loomnetwork/go-loom/auth"
	tgtypes "github.com/loomnetwork/go-loom/builtin/types/transfer_gateway"
	"github.com/loomnetwork/go-loom/client"
	"github.com/pkg/errors"
)

type (
	ProcessEventBatchRequest           = tgtypes.TransferGatewayProcessEventBatchRequest
	GatewayStateRequest                = tgtypes.TransferGatewayStateRequest
	GatewayStateResponse               = tgtypes.TransferGatewayStateResponse
	ConfirmWithdrawalReceiptRequest    = tgtypes.TransferGatewayConfirmWithdrawalReceiptRequest
	PendingWithdrawalsRequest          = tgtypes.TransferGatewayPendingWithdrawalsRequest
	PendingWithdrawalsResponse         = tgtypes.TransferGatewayPendingWithdrawalsResponse
	MainnetEvent                       = tgtypes.TransferGatewayMainnetEvent
	MainnetDepositEvent                = tgtypes.TransferGatewayMainnetEvent_Deposit
	MainnetWithdrawalEvent             = tgtypes.TransferGatewayMainnetEvent_Withdrawal
	MainnetTokenDeposited              = tgtypes.TransferGatewayTokenDeposited
	MainnetTokenWithdrawn              = tgtypes.TransferGatewayTokenWithdrawn
	TokenKind                          = tgtypes.TransferGatewayTokenKind
	PendingWithdrawalSummary           = tgtypes.TransferGatewayPendingWithdrawalSummary
	UnverifiedContractCreatorsRequest  = tgtypes.TransferGatewayUnverifiedContractCreatorsRequest
	UnverifiedContractCreatorsResponse = tgtypes.TransferGatewayUnverifiedContractCreatorsResponse
	VerifyContractCreatorsRequest      = tgtypes.TransferGatewayVerifyContractCreatorsRequest
	UnverifiedContractCreator          = tgtypes.TransferGatewayUnverifiedContractCreator
	VerifiedContractCreator            = tgtypes.TransferGatewayVerifiedContractCreator

	ConfirmWithdrawalReceiptRequestV2 = tgtypes.TransferGatewayConfirmWithdrawalReceiptRequestV2
	// Hot Wallet
	ClearInvalidHotWalletDepositTxHashRequest = tgtypes.TransferGatewayClearInvalidHotWalletDepositTxHashRequest
	PendingHotWalletDepositTxHashesResponse   = tgtypes.TransferGatewayPendingHotWalletDepositTxHashesResponse
	PendingHotWalletDepositTxHashesRequest    = tgtypes.TransferGatewayPendingHotWalletDepositTxHashesRequest
)

const (
	TokenKind_ERC721X      = tgtypes.TransferGatewayTokenKind_ERC721X
	TokenKind_ERC721       = tgtypes.TransferGatewayTokenKind_ERC721
	TokenKind_ERC20        = tgtypes.TransferGatewayTokenKind_ERC20
	TokenKind_ETH          = tgtypes.TransferGatewayTokenKind_ETH
	TokenKind_LoomCoin     = tgtypes.TransferGatewayTokenKind_LOOMCOIN
	TokenKind_TRX          = tgtypes.TransferGatewayTokenKind_TRX
	TokenKind_TRC20        = tgtypes.TransferGatewayTokenKind_TRC20
	TokenKind_BNBLoomToken = tgtypes.TransferGatewayTokenKind_BNBLoomToken
	TokenKind_BEP2         = tgtypes.TransferGatewayTokenKind_BEP2
)

// DAppChainGateway is a partial client-side binding of the Gateway Go contract
type DAppChainGateway struct {
	Address loom.Address
	// Timestamp of the last successful response from the DAppChain
	LastResponseTime time.Time

	contract       *client.Contract
	caller         loom.Address
	logger         *loom.Logger
	signer         auth.Signer
	mainnetAddress loom.Address
	// Allow to set hot wallet address
	HotWalletAddress loom.Address
}

func ConnectToDAppChainLoomCoinGateway(
	loomClient *client.DAppChainRPCClient, caller loom.Address, signer auth.Signer,
	logger *loom.Logger,
	mainnetGatewayAddress loom.Address,
) (*DAppChainGateway, error) {
	gatewayAddr, err := loomClient.Resolve("loomcoin-gateway")
	if err != nil {
		return nil, errors.Wrap(err, "failed to resolve Gateway Go contract address")
	}

	return &DAppChainGateway{
		Address:          gatewayAddr,
		LastResponseTime: time.Now(),
		mainnetAddress:   mainnetGatewayAddress,
		contract:         client.NewContract(loomClient, gatewayAddr.Local),
		caller:           caller,
		signer:           signer,
		logger:           logger,
	}, nil
}

func ConnectToDAppChainGateway(
	loomClient *client.DAppChainRPCClient, caller loom.Address, signer auth.Signer,
	logger *loom.Logger,
	mainnetGatewayAddress loom.Address,
) (*DAppChainGateway, error) {
	gatewayAddr, err := loomClient.Resolve("gateway")
	if err != nil {
		return nil, errors.Wrap(err, "failed to resolve Gateway Go contract address")
	}

	return &DAppChainGateway{
		Address:          gatewayAddr,
		LastResponseTime: time.Now(),
		mainnetAddress:   mainnetGatewayAddress,
		contract:         client.NewContract(loomClient, gatewayAddr.Local),
		caller:           caller,
		signer:           signer,
		logger:           logger,
	}, nil
}

func ConnectToDAppChainTronGateway(
	loomClient *client.DAppChainRPCClient, caller loom.Address, signer auth.Signer,
	logger *loom.Logger,
	mainnetGatewayAddress loom.Address,
) (*DAppChainGateway, error) {
	gatewayAddr, err := loomClient.Resolve("tron-gateway")
	if err != nil {
		return nil, errors.Wrap(err, "failed to resolve Gateway Go contract address")
	}

	return &DAppChainGateway{
		Address:          gatewayAddr,
		LastResponseTime: time.Now(),
		mainnetAddress:   mainnetGatewayAddress,
		contract:         client.NewContract(loomClient, gatewayAddr.Local),
		caller:           caller,
		signer:           signer,
		logger:           logger,
	}, nil
}

func ConnectToDAppChainBinanceGateway(
	loomClient *client.DAppChainRPCClient, caller loom.Address, signer auth.Signer,
	logger *loom.Logger,
	mainnetGatewayAddress loom.Address,
) (*DAppChainGateway, error) {
	gatewayAddr, err := loomClient.Resolve("binance-gateway")
	if err != nil {
		return nil, errors.Wrap(err, "failed to resolve Gateway Go contract address")
	}

	return &DAppChainGateway{
		Address:          gatewayAddr,
		LastResponseTime: time.Now(),
		mainnetAddress:   mainnetGatewayAddress,
		contract:         client.NewContract(loomClient, gatewayAddr.Local),
		caller:           caller,
		signer:           signer,
		logger:           logger,
	}, nil
}

func (gw *DAppChainGateway) LastMainnetBlockNum() (uint64, error) {
	var resp GatewayStateResponse
	if _, err := gw.contract.StaticCall("GetState", &GatewayStateRequest{}, gw.caller, &resp); err != nil {
		gw.logger.Error("failed to retrieve state from Gateway contract on DAppChain", "err", err)
		return 0, err
	}
	gw.LastResponseTime = time.Now()
	return resp.State.LastMainnetBlockNum, nil
}

func (gw *DAppChainGateway) ClearInvalidHotWalletDepositTxHashes(txHashes [][]byte) error {
	req := &ClearInvalidHotWalletDepositTxHashRequest{
		TxHashes:                txHashes,
		MainnetHotWalletAddress: gw.HotWalletAddress.MarshalPB(),
	}
	if _, err := gw.contract.Call("ClearInvalidHotWalletDepositTxHash", req, gw.signer, nil); err != nil {
		gw.logger.Error("failed to commit ClearInvalidHotWalletDepositTxHash", "err", err)
		return err
	}
	gw.LastResponseTime = time.Now()
	return nil
}

func (gw *DAppChainGateway) ProcessHotWalletEventBatch(events []*MainnetEvent) error {
	// TODO: limit max message size to under 1MB
	req := &ProcessEventBatchRequest{
		Events:                  events,
		MainnetHotWalletAddress: gw.HotWalletAddress.MarshalPB(),
	}
	if _, err := gw.contract.Call("ProcessHotWalletEventBatch", req, gw.signer, nil); err != nil {
		gw.logger.Error("failed to commit ProcessHotWalletEventBatch", "err", err)
		return err
	}
	gw.LastResponseTime = time.Now()
	return nil
}

func (gw *DAppChainGateway) ProcessEventBatch(events []*MainnetEvent) error {
	// TODO: limit max message size to under 1MB
	req := &ProcessEventBatchRequest{
		Events:                events,
		MainnetGatewayAddress: gw.mainnetAddress.MarshalPB(),
	}

	if _, err := gw.contract.Call("ProcessEventBatch", req, gw.signer, nil); err != nil {
		gw.logger.Error("failed to commit ProcessEventBatch tx", "err", err)
		return err
	}
	gw.LastResponseTime = time.Now()
	return nil
}

func (gw *DAppChainGateway) PendingWithdrawals() ([]*PendingWithdrawalSummary, error) {
	req := &PendingWithdrawalsRequest{
		MainnetGateway: gw.mainnetAddress.MarshalPB(),
	}
	resp := PendingWithdrawalsResponse{}
	if _, err := gw.contract.StaticCall("PendingWithdrawals", req, gw.caller, &resp); err != nil {
		gw.logger.Error("failed to fetch pending withdrawals from DAppChain", "err", err)
		return nil, err
	}
	gw.LastResponseTime = time.Now()
	return resp.Withdrawals, nil
}

func (gw *DAppChainGateway) GetPendingHotWalletDepositTxHashes() (*PendingHotWalletDepositTxHashesResponse, error) {
	req := &PendingHotWalletDepositTxHashesRequest{}
	resp := PendingHotWalletDepositTxHashesResponse{}
	if _, err := gw.contract.StaticCall("PendingHotWalletDepositTxHashes", req, gw.caller, &resp); err != nil {
		gw.logger.Error("failed to fetch pending hot wallet tx hashes from DAppChain", "err", err)
		return nil, err
	}
	gw.LastResponseTime = time.Now()
	return &resp, nil
}

func (gw *DAppChainGateway) PendingWithdrawalsV2() ([]*PendingWithdrawalSummary, error) {
	req := &PendingWithdrawalsRequest{
		MainnetGateway: gw.mainnetAddress.MarshalPB(),
	}
	resp := PendingWithdrawalsResponse{}
	if _, err := gw.contract.StaticCall("PendingWithdrawalsV2", req, gw.caller, &resp); err != nil {
		gw.logger.Error("failed to fetch pending withdrawals from DAppChain", "err", err)
		return nil, err
	}
	gw.LastResponseTime = time.Now()
	return resp.Withdrawals, nil
}

func (gw *DAppChainGateway) ConfirmWithdrawalReceipt(req *ConfirmWithdrawalReceiptRequest) error {
	_, err := gw.contract.Call("ConfirmWithdrawalReceipt", req, gw.signer, nil)
	if err != nil {
		return err
	}
	gw.LastResponseTime = time.Now()
	return nil
}

func (gw *DAppChainGateway) ConfirmWithdrawalReceiptV2(req *ConfirmWithdrawalReceiptRequestV2) error {
	_, err := gw.contract.Call("ConfirmWithdrawalReceiptV2", req, gw.signer, nil)
	if err != nil {
		return err
	}
	gw.LastResponseTime = time.Now()
	return nil
}

func (gw *DAppChainGateway) UnverifiedContractCreators() ([]*UnverifiedContractCreator, error) {
	req := &UnverifiedContractCreatorsRequest{}
	resp := UnverifiedContractCreatorsResponse{}
	if _, err := gw.contract.StaticCall("UnverifiedContractCreators", req, gw.caller, &resp); err != nil {
		gw.logger.Error("failed to fetch pending contract mappings from DAppChain", "err", err)
		return nil, err
	}
	gw.LastResponseTime = time.Now()
	return resp.Creators, nil
}

func (gw *DAppChainGateway) VerifyContractCreators(verifiedCreators []*VerifiedContractCreator) error {
	req := &VerifyContractCreatorsRequest{
		Creators:              verifiedCreators,
		MainnetGatewayAddress: gw.mainnetAddress.MarshalPB(),
	}
	_, err := gw.contract.Call("VerifyContractCreators", req, gw.signer, nil)
	if err != nil {
		return err
	}
	gw.LastResponseTime = time.Now()
	return nil
}

func (gw *DAppChainGateway) GetPendingWithdrawals() ([]*PendingWithdrawalSummary, error) {
	req := &PendingWithdrawalsRequest{
		TxStatus: tgtypes.TransferGatewayTxStatus_PENDING,
	}
	resp := PendingWithdrawalsResponse{}
	if _, err := gw.contract.StaticCall("GetWithdrawalsWithStatus", req, gw.caller, &resp); err != nil {
		gw.logger.Error("failed to fetch pending withdrawals from DAppChain", "err", err)
		return nil, err
	}
	gw.LastResponseTime = time.Now()
	return resp.Withdrawals, nil
}

func (gw *DAppChainGateway) GetProcessedWithdrawals(mainnetGatewayAddr loom.Address) ([]*PendingWithdrawalSummary, error) {
	req := &PendingWithdrawalsRequest{
		MainnetGateway: gw.mainnetAddress.MarshalPB(),
		TxStatus:       tgtypes.TransferGatewayTxStatus_PROCESSED,
	}
	resp := PendingWithdrawalsResponse{}
	if _, err := gw.contract.StaticCall("GetWithdrawalsWithStatus", req, gw.caller, &resp); err != nil {
		gw.logger.Error("failed to fetch processed withdrawals from DAppChain", "err", err)
		return nil, err
	}
	gw.LastResponseTime = time.Now()
	return resp.Withdrawals, nil
}

func (gw *DAppChainGateway) UpdateWithdrawalReceipt(req *ConfirmWithdrawalReceiptRequest) error {
	_, err := gw.contract.Call("UpdateWithdrawalReceipt", req, gw.signer, nil)
	if err != nil {
		return err
	}
	gw.LastResponseTime = time.Now()
	return nil
}

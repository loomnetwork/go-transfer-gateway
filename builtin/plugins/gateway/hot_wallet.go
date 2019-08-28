// +build evm

package gateway

import (
	"bytes"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gogo/protobuf/proto"
	loom "github.com/loomnetwork/go-loom"
	tgtypes "github.com/loomnetwork/go-loom/builtin/types/transfer_gateway"
	contract "github.com/loomnetwork/go-loom/plugin/contractpb"
	"github.com/loomnetwork/go-loom/types"
	"github.com/loomnetwork/go-loom/util"
	"github.com/loomnetwork/loomchain/features"
	"github.com/pkg/errors"
)

type (
	// HotWallet used by Ethereum Gateway
	SubmitHotWalletDepositTxHashRequest       = tgtypes.TransferGatewaySubmitHotWalletDepositTxHashRequest
	ClearInvalidHotWalletDepositTxHashRequest = tgtypes.TransferGatewayClearInvalidHotWalletDepositTxHashRequest
	PendingHotWalletDepositTxHashesResponse   = tgtypes.TransferGatewayPendingHotWalletDepositTxHashesResponse
	PendingHotWalletDepositTxHashesRequest    = tgtypes.TransferGatewayPendingHotWalletDepositTxHashesRequest
	UpdateMainnetHotWalletRequest             = tgtypes.TransferGatewayUpdateMainnetHotWalletRequest
	HotWalletTxHashes                         = tgtypes.TransferGatewayHotWalletTxHashes
)

var (
	// Hot Wallet
	hotWalletDepositAccountKeyPrefix = []byte("hwdacct")
)

func hotWalletDepositAccountKey(owner loom.Address) []byte {
	return util.PrefixKey(hotWalletDepositAccountKeyPrefix, owner.Bytes())
}

// ProcessHotWalletEventBatch handles hot wallet events
// This method expects that TGHotWalletFeature is enabled on chain
func (gw *Gateway) ProcessHotWalletEventBatch(ctx contract.Context, req *ProcessEventBatchRequest) error {
	if !ctx.FeatureEnabled(features.TGHotWalletFeature, false) {
		return ErrHotWalletFeatureDisabled
	}

	if ok, _ := ctx.HasPermission(submitEventsPerm, []string{oracleRole}); !ok {
		return ErrNotAuthorized
	}

	if err := validateMainnetHotWalletAddress(ctx, req.MainnetHotWalletAddress); err != nil {
		return err
	}

	for _, ev := range req.Events {
		switch payload := ev.Payload.(type) {
		case *tgtypes.TransferGatewayMainnetEvent_Deposit:
			// We need to pass ev here, as emitProcessEvent expects it.
			if err := gw.handleDeposit(ctx, ev, true); err != nil {
				return err
			}

			ownerAddr := loom.UnmarshalAddressPB(payload.Deposit.TokenOwner)
			if err := deleteHotWalletDepositTxHash(ctx, ownerAddr, payload.Deposit.TxHash); err != nil {
				ctx.Logger().Error("[Transfer Gateway] failed to clear hot wallet deposit",
					"err", err,
					"txHash", common.BytesToHash(payload.Deposit.TxHash),
					"owner", ownerAddr.String(),
				)
				return err
			}
		case nil:
			ctx.Logger().Error("[Transfer Gateway] missing event payload")
			continue
		default:
			ctx.Logger().Error("[Transfer Gateway] only deposit event is allowed, got %T", payload)
			continue
		}
	}

	return nil
}

// SubmitHotWalletDepositTxHash is called by a user to submit the Ethereum hash of a token deposit to the
// Ethereum Gateway contract. Later the Oracle will verify the tx hash and forward the deposit event
// to the DAppChain Gateway contract.
// The user must have a mapping between their DAppChain address and their Eth address before they
// can submit a tx hash.
func (gw *Gateway) SubmitHotWalletDepositTxHash(ctx contract.Context, req *SubmitHotWalletDepositTxHashRequest) error {
	if !ctx.FeatureEnabled(features.TGHotWalletFeature, false) {
		return ErrHotWalletFeatureDisabled
	}

	txHash := req.TxHash
	if txHash == nil {
		return ErrInvalidRequest
	}

	// It's cheapter to check if the tx hash is already processed than letting the request in and
	// check later when TG processes the deposit.
	if hasSeenTxHash(ctx, txHash) {
		return ErrTxHashAlreadyExists
	}

	addressMapperAddress, err := ctx.Resolve("addressmapper")
	if err != nil {
		return err
	}

	ownerAddr := ctx.Message().Sender
	ownerEthAddr, err := resolveToEthAddr(ctx, addressMapperAddress, ownerAddr)
	if err != nil {
		return err
	}

	// User are not allowed to resubmit the pending tx hash
	deposit, err := loadHotWalletDepositTxHashes(ctx, ownerEthAddr)
	if err != nil {
		return err
	}
	for _, entry := range deposit.TxHashes {
		if bytes.Equal(entry, txHash) {
			return ErrTxHashAlreadyExists
		}
	}

	if err = saveHotWalletDepositTxHash(ctx, ownerEthAddr, txHash); err != nil {
		return err
	}

	return nil
}

// ClearInvalidHotWalletDepositTxHash is an Oracle only method that's called by Oracle to clear invalid
// hot wallet deposit tx hashes submitted by users.
func (gw *Gateway) ClearInvalidHotWalletDepositTxHash(ctx contract.Context, req *ClearInvalidHotWalletDepositTxHashRequest) error {
	if !ctx.FeatureEnabled(features.TGHotWalletFeature, false) {
		return ErrHotWalletFeatureDisabled
	}

	if req.TxHashes == nil {
		return ErrInvalidRequest
	}

	if ok, _ := ctx.HasPermission(submitEventsPerm, []string{oracleRole}); !ok {
		return ErrNotAuthorized
	}

	if err := validateMainnetHotWalletAddress(ctx, req.MainnetHotWalletAddress); err != nil {
		return err
	}

	// Build txHashMap for faster lookup when deleting account key
	txHashMap := make(map[string]bool, len(req.TxHashes))
	for _, txHash := range req.TxHashes {
		txHashMap[string(txHash)] = true
	}

	accountList := make([][]byte, 0)
	txHashList := make([]*HotWalletTxHashes, 0)
	for _, entry := range ctx.Range(hotWalletDepositAccountKeyPrefix) {
		var htx HotWalletTxHashes
		if err := proto.Unmarshal(entry.Value, &htx); err != nil {
			return errors.Wrapf(err, "failed to decode deposit tx hash for account: %x", entry.Key)
		}

		var remainingTxHashes = make([][]byte, 0, len(htx.TxHashes))
		for _, hash := range htx.TxHashes {
			if !txHashMap[string(hash)] {
				remainingTxHashes = append(remainingTxHashes, hash)
			}
		}

		accountList = append(accountList, util.PrefixKey(hotWalletDepositAccountKeyPrefix, entry.Key))
		txHashList = append(txHashList, &HotWalletTxHashes{TxHashes: remainingTxHashes})
	}

	for i := 0; i < len(accountList); i++ {
		account := accountList[i]
		txh := txHashList[i]

		if len(txh.TxHashes) == 0 {
			ctx.Delete(account)
		} else {
			if err := ctx.Set(account, txh); err != nil {
				return err
			}
		}

	}

	return nil
}

// PendingHotWalletDepositTxHashes returns deposit tx hashes that have not been processed yet by the Oracle.
func (gw *Gateway) PendingHotWalletDepositTxHashes(
	ctx contract.StaticContext, req *PendingHotWalletDepositTxHashesRequest,
) (*PendingHotWalletDepositTxHashesResponse, error) {
	txHashes := make([][]byte, 0)
	for _, entry := range ctx.Range(hotWalletDepositAccountKeyPrefix) {
		var htx HotWalletTxHashes
		if err := proto.Unmarshal(entry.Value, &htx); err != nil {
			return nil, errors.Errorf("failed to decode deposit tx hash for account: %x", entry.Key)
		}

		for _, txHash := range htx.TxHashes {
			txHashes = append(txHashes, txHash)
		}
	}

	return &PendingHotWalletDepositTxHashesResponse{TxHashes: txHashes}, nil
}

// UpdateMainnetHotWalletAddress sets the given mainnet hot wallet address to the contract state
func (gw *Gateway) UpdateMainnetHotWalletAddress(ctx contract.Context, req *UpdateMainnetHotWalletRequest) error {
	if !ctx.FeatureEnabled(features.TGHotWalletFeature, false) {
		return ErrHotWalletFeatureDisabled
	}

	if req.MainnetHotWalletAddress == nil {
		return ErrInvalidRequest
	}

	state, err := loadState(ctx)
	if err != nil {
		return err
	}

	if loom.UnmarshalAddressPB(state.Owner).Compare(ctx.Message().Sender) != 0 {
		return ErrNotAuthorized
	}

	state.MainnetHotWalletAddress = req.MainnetHotWalletAddress

	return saveState(ctx, state)
}

func loadHotWalletDepositTxHashes(ctx contract.StaticContext, owner loom.Address) (*HotWalletTxHashes, error) {
	tgTxHashes := &HotWalletTxHashes{}
	err := ctx.Get(hotWalletDepositAccountKey(owner), tgTxHashes)
	if err != nil {
		if err == contract.ErrNotFound {
			return tgTxHashes, nil
		}
		return nil, errors.Wrapf(err, "failed to load hot wallet deposit tx hash for %v", owner)
	}

	return tgTxHashes, nil
}

func saveHotWalletDepositTxHash(ctx contract.Context, owner loom.Address, txHash []byte) error {
	depositTxHashes, err := loadHotWalletDepositTxHashes(ctx, owner)
	if err != nil {
		return err
	}

	depositTxHashes.TxHashes = append(depositTxHashes.TxHashes, txHash)
	return ctx.Set(hotWalletDepositAccountKey(owner), depositTxHashes)
}

func deleteHotWalletDepositTxHash(ctx contract.Context, owner loom.Address, txHash []byte) error {
	depositTxHashes, err := loadHotWalletDepositTxHashes(ctx, owner)
	if err != nil {
		return err
	}
	newTxHashes := make([][]byte, 0, len(depositTxHashes.TxHashes))
	for i := 0; i < len(depositTxHashes.TxHashes); i++ {
		entry := depositTxHashes.TxHashes[i]
		if !bytes.Equal(entry, txHash) {
			newTxHashes = append(newTxHashes, entry)
		}
	}

	// save some storage by removing the key if new tx hashes size is 0.
	if len(newTxHashes) == 0 {
		ctx.Delete(hotWalletDepositAccountKey(owner))
	} else {
		err := ctx.Set(hotWalletDepositAccountKey(owner), &HotWalletTxHashes{TxHashes: newTxHashes})
		if err != nil {
			return err
		}
	}

	return nil
}

func validateMainnetHotWalletAddress(ctx contract.Context, walletAddress *types.Address) error {
	if !ctx.FeatureEnabled(features.TGHotWalletFeature, false) {
		return nil
	}

	if walletAddress == nil {
		return ErrInvalidRequest
	}

	state, err := loadState(ctx)
	if err != nil {
		return err
	}

	if loom.UnmarshalAddressPB(state.MainnetHotWalletAddress).Compare(loom.UnmarshalAddressPB(walletAddress)) != 0 {
		return ErrInvalidHotWalletAddress
	}

	return nil
}

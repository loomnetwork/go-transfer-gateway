// +build evm

package gateway

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/gogo/protobuf/proto"
	"github.com/loomnetwork/go-loom"
	tgtypes "github.com/loomnetwork/go-loom/builtin/types/transfer_gateway"
	"github.com/loomnetwork/go-loom/common/evmcompat"
	contract "github.com/loomnetwork/go-loom/plugin/contractpb"
	"github.com/loomnetwork/go-loom/types"
	"github.com/loomnetwork/loomchain"
	ssha "github.com/miguelmota/go-solidity-sha3"
)

type (
	PendingContractMapping             = tgtypes.TransferGatewayPendingContractMapping
	ContractAddressMapping             = tgtypes.TransferGatewayContractAddressMapping
	UnverifiedContractCreator          = tgtypes.TransferGatewayUnverifiedContractCreator
	VerifiedContractCreator            = tgtypes.TransferGatewayVerifiedContractCreator
	ContractMappingConfirmed           = tgtypes.TransferGatewayContractMappingConfirmed
	ContractMappingRejected            = tgtypes.TransferGatewayContractMappingRejected
	AddContractMappingRequest          = tgtypes.TransferGatewayAddContractMappingRequest
	UnverifiedContractCreatorsRequest  = tgtypes.TransferGatewayUnverifiedContractCreatorsRequest
	UnverifiedContractCreatorsResponse = tgtypes.TransferGatewayUnverifiedContractCreatorsResponse
	VerifyContractCreatorsRequest      = tgtypes.TransferGatewayVerifyContractCreatorsRequest
)

// AddContractMapping adds a mapping between a DAppChain contract and a Mainnet contract.
func (gw *Gateway) AddContractMapping(ctx contract.Context, req *AddContractMappingRequest) error {
	if req.ForeignContract == nil || req.LocalContract == nil || req.ForeignContractCreatorSig == nil {
		return ErrInvalidRequest
	}

	switch gw.Type {
	case TronGateway:
		// Skip checking tx hash since these gateways do not have API for us to verify
	case BinanceGateway:
		// This gateway doesn't need a tx hash to verify contract ownership, but because the original
		// version was released with this requirement we have to use a feature flag to safely switch
		// over to the correct behavior.
		if req.ForeignContractTxHash == nil && !ctx.FeatureEnabled(loomchain.TGBinanceContractMappingFeature, false) {
			return ErrInvalidRequest
		}
	default:
		if req.ForeignContractTxHash == nil {
			return ErrInvalidRequest
		}
	}

	foreignAddr := loom.UnmarshalAddressPB(req.ForeignContract)
	localAddr := loom.UnmarshalAddressPB(req.LocalContract)
	if foreignAddr.ChainID == "" || localAddr.ChainID == "" {
		return ErrInvalidRequest
	}
	if foreignAddr.Compare(localAddr) == 0 {
		return ErrInvalidRequest
	}

	localRec, err := ctx.ContractRecord(localAddr)
	if err != nil {
		return err
	}

	callerAddr := ctx.Message().Sender
	if callerAddr.Compare(localRec.CreatorAddress) != 0 {
		return ErrNotAuthorized
	}

	if contractMappingExists(ctx, foreignAddr, localAddr) {
		return ErrContractMappingExists
	}

	state, err := loadState(ctx)
	if err != nil {
		return err
	}

	hash := ssha.SoliditySHA3(
		ssha.Address(common.BytesToAddress(req.ForeignContract.Local)),
		ssha.Address(common.BytesToAddress(req.LocalContract.Local)),
	)

	allowedSigTypes := []evmcompat.SignatureType{
		evmcompat.SignatureType_EIP712,
		evmcompat.SignatureType_GETH,
		evmcompat.SignatureType_TREZOR,
		evmcompat.SignatureType_TRON,
	}

	if gw.Type == BinanceGateway && ctx.FeatureEnabled(loomchain.TGBinanceContractMappingFeature, false) {
		allowedSigTypes = append(allowedSigTypes, evmcompat.SignatureType_BINANCE)
		hash = evmcompat.GenSHA256(
			ssha.Address(common.BytesToAddress(req.ForeignContract.Local)),
			ssha.Address(common.BytesToAddress(req.LocalContract.Local)),
		)
	}

	signerAddr, err := evmcompat.RecoverAddressFromTypedSig(hash, req.ForeignContractCreatorSig, allowedSigTypes)
	if err != nil {
		return err
	}

	err = ctx.Set(pendingContractMappingKey(state.NextContractMappingID),
		&PendingContractMapping{
			ID:              state.NextContractMappingID,
			ForeignContract: req.ForeignContract,
			LocalContract:   req.LocalContract,
			ForeignContractCreator: loom.Address{
				ChainID: foreignAddr.ChainID,
				Local:   loom.LocalAddress(signerAddr.Bytes()),
			}.MarshalPB(),
			ForeignContractTxHash: req.ForeignContractTxHash,
		},
	)
	if err != nil {
		return err
	}

	state.NextContractMappingID++
	return ctx.Set(stateKey, state)
}

// AddAuthorizedContractMapping adds a mapping between a DAppChain contract and a Mainnet contract
// without verifying contract ownership. Only the Gateway owner is authorized to create such mappings.
func (gw *Gateway) AddAuthorizedContractMapping(ctx contract.Context, req *AddContractMappingRequest) error {
	if req.ForeignContract == nil || req.LocalContract == nil {
		return ErrInvalidRequest
	}
	foreignAddr := loom.UnmarshalAddressPB(req.ForeignContract)
	localAddr := loom.UnmarshalAddressPB(req.LocalContract)
	if foreignAddr.ChainID == "" || localAddr.ChainID == "" {
		return ErrInvalidRequest
	}
	if foreignAddr.Compare(localAddr) == 0 {
		return ErrInvalidRequest
	}

	state, err := loadState(ctx)

	if err != nil {
		return err
	}

	callerAddr := ctx.Message().Sender

	// Only the Gateway owner is allowed to bypass contract ownership checks
	if callerAddr.Compare(loom.UnmarshalAddressPB(state.Owner)) != 0 {
		return ErrNotAuthorized
	}

	if contractMappingExists(ctx, foreignAddr, localAddr) {
		return ErrContractMappingExists
	}

	err = ctx.Set(contractAddrMappingKey(foreignAddr), &ContractAddressMapping{
		From: req.ForeignContract,
		To:   req.LocalContract,
	})
	if err != nil {
		return err
	}

	err = ctx.Set(contractAddrMappingKey(localAddr), &ContractAddressMapping{
		From: req.LocalContract,
		To:   req.ForeignContract,
	})
	if err != nil {
		return err
	}

	payload, err := proto.Marshal(&ContractMappingConfirmed{
		ForeignContract: req.ForeignContract,
		LocalContract:   req.LocalContract,
	})
	if err != nil {
		return err
	}

	ctx.EmitTopics(payload, contractMappingConfirmedEventTopic)
	return nil
}

func (gw *Gateway) UnverifiedContractCreators(ctx contract.StaticContext,
	req *UnverifiedContractCreatorsRequest) (*UnverifiedContractCreatorsResponse, error) {
	var creators []*UnverifiedContractCreator
	for _, entry := range ctx.Range(pendingContractMappingKeyPrefix) {
		var mapping PendingContractMapping
		if err := proto.Unmarshal(entry.Value, &mapping); err != nil {
			return nil, err
		}

		switch gw.Type {
		case TronGateway, BinanceGateway:
			// Tron and Binance Gateway do not have contract tx hash,
			// Return only contract address to the client
			creators = append(creators, &UnverifiedContractCreator{
				ContractMappingID: mapping.ID,
				ContractAddress:   mapping.ForeignContract,
			})
		default:
			creators = append(creators, &UnverifiedContractCreator{
				ContractMappingID: mapping.ID,
				ContractTxHash:    mapping.ForeignContractTxHash,
			})
		}

	}
	return &UnverifiedContractCreatorsResponse{
		Creators: creators,
	}, nil
}

func (gw *Gateway) VerifyContractCreators(ctx contract.Context, req *VerifyContractCreatorsRequest) error {
	if len(req.Creators) == 0 {
		return ErrInvalidRequest
	}

	if ok, _ := ctx.HasPermission(verifyCreatorsPerm, []string{oracleRole}); !ok {
		return ErrNotAuthorized
	}

	if err := validateMainnetGatewayAddress(ctx, req.MainnetGatewayAddress); err != nil {
		return err
	}

	for _, creatorInfo := range req.Creators {
		mappingKey := pendingContractMappingKey(creatorInfo.ContractMappingID)
		mapping := &PendingContractMapping{}
		if err := ctx.Get(mappingKey, mapping); err != nil {
			if err == contract.ErrNotFound {
				// A pending mapping is removed as soon as an oracle submits a confirmation,
				// so it won't be unusual for it to be missing when multiple oracles are running.
				continue
			}
			return err
		}

		if err := confirmContractMapping(ctx, mappingKey, mapping, creatorInfo); err != nil {
			payload, marshalErr := proto.Marshal(&ContractMappingRejected{
				LocalContract:           mapping.LocalContract,
				ExpectedForeignContract: mapping.ForeignContract,
				ExpectedCreator:         mapping.ForeignContractCreator,
				ActualForeignContract:   creatorInfo.Contract,
				ActualCreator:           creatorInfo.Creator,
				ErrorMessage:            err.Error(),
			})
			if marshalErr != nil {
				ctx.Logger().Error(
					"[Transfer Gateway] failed to marshal contract mapping rejection event",
					"err", marshalErr,
				)
				return err
			}
			ctx.EmitTopics(payload, contractMappingRejectedEventTopic)
			return err
		}
	}

	return nil
}

// GetContractMapping attempts to find a pending or confirmed mappings for the given contract address.
func (gw *Gateway) GetContractMapping(ctx contract.StaticContext, req *GetContractMappingRequest) (*GetContractMappingResponse, error) {
	var mapping ContractAddressMapping
	var isPending bool
	var mappedAddress *types.Address
	if err := ctx.Get(contractAddrMappingKey(loom.UnmarshalAddressPB(req.From)), &mapping); err == nil {
		isPending = false
		mappedAddress = mapping.To
	} else {
		if err != contract.ErrNotFound {
			return nil, err
		} else {
			for _, entry := range ctx.Range(pendingContractMappingKeyPrefix) {
				var mapping PendingContractMapping
				if err := proto.Unmarshal(entry.Value, &mapping); err != nil {
					return nil, err
				}
				if loom.UnmarshalAddressPB(mapping.ForeignContract).Compare(loom.UnmarshalAddressPB(req.From)) == 0 {
					isPending = true
					mappedAddress = mapping.LocalContract
					break
				}
				if loom.UnmarshalAddressPB(mapping.LocalContract).Compare(loom.UnmarshalAddressPB(req.From)) == 0 {
					isPending = true
					mappedAddress = mapping.ForeignContract
					break
				}
			}
		}
	}
	return &GetContractMappingResponse{
		MappedAddress: mappedAddress,
		IsPending:     isPending,
		Found:         mappedAddress != nil,
	}, nil
}

// ListContractMapping returns a list of all pending and confirmed contract mappings.
func (gw *Gateway) ListContractMapping(ctx contract.StaticContext, req *ListContractMappingRequest) (*ListContractMappingResponse, error) {
	var mappings []*ContractAddressMapping
	var pendingmappings []*PendingContractMapping
	pendingMappingsKeysSet := make(map[string]bool)
	confirmedMappingKeysSet := make(map[string]bool)
	for _, entry := range ctx.Range(contractAddrMappingKeyPrefix) {
		var mapping ContractAddressMapping
		if err := proto.Unmarshal(entry.Value, &mapping); err != nil {
			return nil, err
		}
		if _, ok := confirmedMappingKeysSet[loom.UnmarshalAddressPB(mapping.From).String()]; !ok {
			confirmedMappingKeysSet[loom.UnmarshalAddressPB(mapping.To).String()] = true
			confirmedMappingKeysSet[loom.UnmarshalAddressPB(mapping.From).String()] = true
			mappings = append(mappings, &mapping)
		}
	}
	for _, entry := range ctx.Range(pendingContractMappingKeyPrefix) {
		var mapping PendingContractMapping
		if err := proto.Unmarshal(entry.Value, &mapping); err != nil {
			return nil, err
		}
		if _, ok := pendingMappingsKeysSet[loom.UnmarshalAddressPB(mapping.LocalContract).String()]; !ok {
			pendingMappingsKeysSet[loom.UnmarshalAddressPB(mapping.LocalContract).String()] = true
			pendingMappingsKeysSet[loom.UnmarshalAddressPB(mapping.ForeignContract).String()] = true
			pendingmappings = append(pendingmappings, &mapping)
		}

	}
	return &ListContractMappingResponse{
		ConfimedMappings: mappings,
		PendingMappings:  pendingmappings,
	}, nil
}

func confirmContractMapping(ctx contract.Context, pendingMappingKey []byte, mapping *PendingContractMapping,
	confirmation *VerifiedContractCreator) error {
	// Clear out the pending mapping regardless of whether it's successfully confirmed or not
	ctx.Delete(pendingMappingKey)

	ctx.Logger().Info("Contract mapping info",
		"expected-contract", loom.UnmarshalAddressPB(mapping.ForeignContract),
		"expected-creator", loom.UnmarshalAddressPB(mapping.ForeignContractCreator),
		"actual-contract", loom.UnmarshalAddressPB(confirmation.Contract),
		"actual-creator", loom.UnmarshalAddressPB(confirmation.Creator),
	)

	if (mapping.ForeignContractCreator.ChainId != confirmation.Creator.ChainId) ||
		(mapping.ForeignContractCreator.Local.Compare(confirmation.Creator.Local) != 0) ||
		(mapping.ForeignContract.ChainId != confirmation.Contract.ChainId) ||
		(mapping.ForeignContract.Local.Compare(confirmation.Contract.Local) != 0) {
		ctx.Logger().Debug("[Transfer Gateway] failed to verify foreign contract creator",
			"expected-contract", mapping.ForeignContract.Local,
			"expected-creator", mapping.ForeignContractCreator.Local,
			"actual-contract", confirmation.Contract.Local,
			"actual-creator", confirmation.Creator.Local,
		)
		payload, err := proto.Marshal(&ContractMappingRejected{
			LocalContract:           mapping.LocalContract,
			ExpectedForeignContract: mapping.ForeignContract,
			ExpectedCreator:         mapping.ForeignContractCreator,
			ActualForeignContract:   confirmation.Contract,
			ActualCreator:           confirmation.Creator,
		})
		if err != nil {
			ctx.Logger().Error("[Transfer Gateway] failed to marshal contract mapping rejection event", "err", err)
			return nil
		}
		ctx.EmitTopics(payload, contractMappingRejectedEventTopic)
		return nil
	}

	foreignContractAddr := loom.UnmarshalAddressPB(mapping.ForeignContract)
	localContractAddr := loom.UnmarshalAddressPB(mapping.LocalContract)
	err := ctx.Set(contractAddrMappingKey(foreignContractAddr), &ContractAddressMapping{
		From: mapping.ForeignContract,
		To:   mapping.LocalContract,
	})
	if err != nil {
		return err
	}
	err = ctx.Set(contractAddrMappingKey(localContractAddr), &ContractAddressMapping{
		From: mapping.LocalContract,
		To:   mapping.ForeignContract,
	})
	if err != nil {
		return err
	}

	payload, err := proto.Marshal(&ContractMappingConfirmed{
		ForeignContract: mapping.ForeignContract,
		LocalContract:   mapping.LocalContract,
	})
	if err != nil {
		return err
	}
	ctx.EmitTopics(payload, contractMappingConfirmedEventTopic)
	return nil
}

// Returns the address of the DAppChain contract that corresponds to the given Ethereum address
func resolveToLocalContractAddr(ctx contract.StaticContext, foreignContractAddr loom.Address) (loom.Address, error) {
	var mapping ContractAddressMapping
	if err := ctx.Get(contractAddrMappingKey(foreignContractAddr), &mapping); err != nil {
		return loom.Address{}, err
	}
	return loom.UnmarshalAddressPB(mapping.To), nil
}

// Returns the address of the Ethereum contract that corresponds to the given DAppChain address
func resolveToForeignContractAddr(ctx contract.StaticContext, localContractAddr loom.Address) (loom.Address, error) {
	var mapping ContractAddressMapping
	if err := ctx.Get(contractAddrMappingKey(localContractAddr), &mapping); err != nil {
		return loom.Address{}, err
	}
	return loom.UnmarshalAddressPB(mapping.To), nil
}

// Checks if a pending or confirmed contract mapping referencing either of the given contracts exists
func contractMappingExists(ctx contract.StaticContext, foreignContractAddr, localContractAddr loom.Address) bool {
	var mapping ContractAddressMapping
	if err := ctx.Get(contractAddrMappingKey(foreignContractAddr), &mapping); err == nil {
		return true
	}
	if err := ctx.Get(contractAddrMappingKey(localContractAddr), &mapping); err == nil {
		return true
	}

	for _, entry := range ctx.Range(pendingContractMappingKeyPrefix) {
		var mapping PendingContractMapping
		if err := proto.Unmarshal(entry.Value, &mapping); err != nil {
			continue
		}
		if loom.UnmarshalAddressPB(mapping.ForeignContract).Compare(foreignContractAddr) == 0 {
			return true
		}
		if loom.UnmarshalAddressPB(mapping.LocalContract).Compare(localContractAddr) == 0 {
			return true
		}
	}

	return false
}

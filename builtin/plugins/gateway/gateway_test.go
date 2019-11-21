// +build evm

package gateway

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gogo/protobuf/proto"
	loom "github.com/loomnetwork/go-loom"
	"github.com/loomnetwork/go-loom/builtin/types/coin"
	tgtypes "github.com/loomnetwork/go-loom/builtin/types/transfer_gateway"
	"github.com/loomnetwork/go-loom/client"
	"github.com/loomnetwork/go-loom/common/evmcompat"
	lp "github.com/loomnetwork/go-loom/plugin"
	contract "github.com/loomnetwork/go-loom/plugin/contractpb"
	"github.com/loomnetwork/go-loom/types"
	"github.com/loomnetwork/loomchain/builtin/plugins/address_mapper"
	"github.com/loomnetwork/loomchain/features"
	"github.com/loomnetwork/loomchain/plugin"
	ssha "github.com/miguelmota/go-solidity-sha3"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/tendermint/tendermint/crypto/ed25519"
)

var (
	addr1 = loom.MustParseAddress("chain:0xb16a379ec18d4093666f8f38b11a3071c920207d")
	addr2 = loom.MustParseAddress("chain:0xfa4c7920accfd66b86f5fd0e69682a79f762d49e")
	addr3 = loom.MustParseAddress("chain:0x5cecd1f7261e1f4c684e297be3edf03b825e01c4")
	addr4 = loom.MustParseAddress("chain:0x5cecd1f7261e1f4c684e297be3edf03b825e01c9")
	addr5 = loom.MustParseAddress("chain:0x5cecd1f7261e1f4c684e297be3edf03b825e01c8")

	dappAccAddr1 = loom.MustParseAddress("chain:0x5cecd1f7261e1f4c684e297be3edf03b825e01c4")
	ethAccAddr1  = loom.MustParseAddress("eth:0x5cecd1f7261e1f4c684e297be3edf03b825e01c4")

	ethTokenAddr  = loom.MustParseAddress("eth:0xb16a379ec18d4093666f8f38b11a3071c920207d")
	ethTokenAddr2 = loom.MustParseAddress("eth:0xfa4c7920accfd66b86f5fd0e69682a79f762d49e")
	ethTokenAddr3 = loom.MustParseAddress("eth:0x5d1ddf5223a412d24901c32d14ef56cb706c0f64")
	ethTokenAddr4 = loom.MustParseAddress("eth:0xb16a379ec18d4093666f8f38b11a3071c920207d")

	tronTokenAddr  = loom.MustParseAddress("tron:0x774cc7b7d66e5aec6cbfcffb96c5d1421758402f")
	tronTokenAddr2 = loom.MustParseAddress("tron:0xc8C88F1c531fcC6C55395b57CFdF4226Fbf77799")

	binanceTokenAddr  = loom.MustParseAddress("binance:0xb16a379ec18d4093666f8f38b11a3071c920207d")
	binanceTokenAddr2 = loom.MustParseAddress("binance:0x0000000000000000000000004d4f4f4c2d434243")
	binanceBNBAddr    = loom.MustParseAddress("binance:0x0000000000000000000000000000000000424e42")

	sigType = evmcompat.SignatureType_EIP712
)

const (
	coinDecimals = 18
)

type testValidator struct {
	DAppPrivKey ed25519.PrivKeyEd25519
	EthPrivKey  *ecdsa.PrivateKey
	EthAddress  loom.Address
	DAppAddress loom.Address
}

type GatewayTestSuite struct {
	suite.Suite
	ethKey            *ecdsa.PrivateKey
	ethKey2           *ecdsa.PrivateKey
	ethKey3           *ecdsa.PrivateKey
	ethKey4           *ecdsa.PrivateKey
	ethAddr           loom.Address
	ethAddr2          loom.Address
	ethAddr3          loom.Address
	ethAddr4          loom.Address
	dAppAddr          loom.Address
	dAppAddr2         loom.Address
	dAppAddr3         loom.Address
	dAppAddr4         loom.Address
	dAppAddr5         loom.Address
	validatorsDetails []*testValidator
	tronKey           *ecdsa.PrivateKey
	tronKey2          *ecdsa.PrivateKey
	tronAddr          loom.Address
	tronAddr2         loom.Address
	binanceKey        *ecdsa.PrivateKey
	binanceAddr       loom.Address
	ethTokenAddr      loom.Address
	ethTokenAddr2     loom.Address
}

func (ts *GatewayTestSuite) SetupTest() {
	require := ts.Require()
	var err error
	ts.ethKey, err = crypto.GenerateKey()
	require.NoError(err)
	ethLocalAddr, err := loom.LocalAddressFromHexString(crypto.PubkeyToAddress(ts.ethKey.PublicKey).Hex())
	require.NoError(err)
	ts.ethAddr = loom.Address{ChainID: "eth", Local: ethLocalAddr}
	ts.ethKey2, err = crypto.GenerateKey()
	require.NoError(err)
	ethLocalAddr, err = loom.LocalAddressFromHexString(crypto.PubkeyToAddress(ts.ethKey2.PublicKey).Hex())
	require.NoError(err)
	ts.ethAddr2 = loom.Address{ChainID: "eth", Local: ethLocalAddr}
	ts.dAppAddr = loom.Address{ChainID: "chain", Local: addr1.Local}
	ts.dAppAddr2 = loom.Address{ChainID: "chain", Local: addr2.Local}
	ts.dAppAddr3 = loom.Address{ChainID: "chain", Local: addr3.Local}
	ts.dAppAddr4 = loom.Address{ChainID: "chain", Local: addr4.Local}
	ts.dAppAddr5 = loom.Address{ChainID: "chain", Local: addr5.Local}
	ts.tronKey, err = crypto.GenerateKey()
	require.NoError(err)
	tronLocalAddr, err := loom.LocalAddressFromHexString(crypto.PubkeyToAddress(ts.tronKey.PublicKey).Hex())
	require.NoError(err)
	ts.tronAddr = loom.Address{ChainID: "tron", Local: tronLocalAddr}
	ts.tronKey2, err = crypto.GenerateKey()
	require.NoError(err)
	tronLocalAddr2, err := loom.LocalAddressFromHexString(crypto.PubkeyToAddress(ts.tronKey2.PublicKey).Hex())
	require.NoError(err)
	ts.tronAddr2 = loom.Address{ChainID: "tron", Local: tronLocalAddr2}
	var err1 error
	ts.ethKey3, err1 = crypto.GenerateKey()
	require.NoError(err1)
	ethLocalAddr3, err1 := loom.LocalAddressFromHexString(crypto.PubkeyToAddress(ts.ethKey3.PublicKey).Hex())
	require.NoError(err1)
	ts.ethAddr3 = loom.Address{ChainID: "eth", Local: ethLocalAddr3}
	ts.ethKey4, err1 = crypto.GenerateKey()
	require.NoError(err1)
	ethLocalAddr4, err1 := loom.LocalAddressFromHexString(crypto.PubkeyToAddress(ts.ethKey4.PublicKey).Hex())
	require.NoError(err1)
	ts.ethAddr4 = loom.Address{ChainID: "eth", Local: ethLocalAddr4}
	var err2 error
	ts.binanceKey, err2 = crypto.GenerateKey()
	require.NoError(err2)
	bnbLocalAddr, err2 := loom.LocalAddressFromHexString(crypto.PubkeyToAddress(ts.binanceKey.PublicKey).Hex())
	require.NoError(err2)
	ts.binanceAddr = loom.Address{ChainID: "binance", Local: bnbLocalAddr}

	ts.validatorsDetails = make([]*testValidator, 5)
	for i, _ := range ts.validatorsDetails {
		ts.validatorsDetails[i] = &testValidator{}
		ts.validatorsDetails[i].DAppPrivKey = ed25519.GenPrivKey()

		ts.validatorsDetails[i].EthPrivKey, err = crypto.GenerateKey()
		require.NoError(err)

		ts.validatorsDetails[i].EthAddress = loom.Address{
			ChainID: "eth",
			Local:   crypto.PubkeyToAddress(ts.validatorsDetails[i].EthPrivKey.PublicKey).Bytes(),
		}

		ts.validatorsDetails[i].DAppAddress = loom.Address{
			ChainID: "chain",
			Local:   loom.LocalAddressFromPublicKey(ts.validatorsDetails[i].DAppPrivKey.PubKey().Bytes()),
		}
	}
}

func TestGatewayTestSuite(t *testing.T) {
	suite.Run(t, new(GatewayTestSuite))
}

func (ts *GatewayTestSuite) TestInit() {
	require := ts.Require()
	ctx := contract.WrapPluginContext(
		lp.CreateFakeContext(addr1 /*caller*/, addr1 /*contract*/),
	)

	gw := &Gateway{}
	require.NoError(gw.Init(ctx, &InitRequest{
		Owner: addr1.MarshalPB(),
	}))

	resp, err := gw.GetState(ctx, &GatewayStateRequest{})
	require.NoError(err)
	s := resp.State
	ts.Equal(uint64(0), s.LastMainnetBlockNum)
}

func (ts *GatewayTestSuite) TestEmptyEventBatchProcessing() {
	require := ts.Require()
	ctx := contract.WrapPluginContext(
		lp.CreateFakeContext(addr1 /*caller*/, addr1 /*contract*/),
	)

	contract := &Gateway{}
	require.NoError(contract.Init(ctx, &InitRequest{
		Owner:   addr1.MarshalPB(),
		Oracles: []*types.Address{addr1.MarshalPB()},
	}))

	// Should error out on an empty batch
	require.Error(contract.ProcessEventBatch(ctx, &ProcessEventBatchRequest{}))
}

func (ts *GatewayTestSuite) TestOwnerPermissions() {
	require := ts.Require()
	fakeCtx := plugin.CreateFakeContextWithEVM(ts.dAppAddr, loom.RootAddress("chain"))
	fakeCtx = fakeCtx.WithFeature(features.TGVersion1_1, true)
	require.True(fakeCtx.FeatureEnabled(features.TGVersion1_1, false))

	ownerAddr := ts.dAppAddr
	oracleAddr := ts.dAppAddr2
	contractAddr := ts.ethTokenAddr

	gwContract := &Gateway{}
	require.NoError(gwContract.Init(contract.WrapPluginContext(fakeCtx), &InitRequest{
		Owner:   ownerAddr.MarshalPB(),
		Oracles: []*types.Address{oracleAddr.MarshalPB()},
	}))

	err := gwContract.AddOracle(
		contract.WrapPluginContext(fakeCtx.WithSender(oracleAddr)),
		&AddOracleRequest{Oracle: oracleAddr.MarshalPB()},
	)
	require.Equal(ErrNotAuthorized, err, "Only owner should be allowed to add oracles")

	err = gwContract.RemoveOracle(
		contract.WrapPluginContext(fakeCtx.WithSender(oracleAddr)),
		&RemoveOracleRequest{Oracle: oracleAddr.MarshalPB()},
	)
	require.Equal(ErrNotAuthorized, err, "Only owner should be allowed to remove oracles")

	require.NoError(gwContract.RemoveOracle(
		contract.WrapPluginContext(fakeCtx.WithSender(ownerAddr)),
		&RemoveOracleRequest{Oracle: oracleAddr.MarshalPB()},
	), "Owner should be allowed to remove oracles")

	require.NoError(gwContract.AddOracle(
		contract.WrapPluginContext(fakeCtx.WithSender(ownerAddr)),
		&AddOracleRequest{Oracle: oracleAddr.MarshalPB()},
	), "Owner should be allowed to add oracles")

	err = gwContract.ProcessEventBatch(
		contract.WrapPluginContext(fakeCtx.WithSender(ownerAddr)),
		&ProcessEventBatchRequest{Events: genERC721Deposits(ethTokenAddr, ts.ethAddr, []uint64{5}, nil)},
	)
	require.Equal(ErrNotAuthorized, err, "Only an oracle should be allowed to submit Mainnet events")

	err = gwContract.ConfirmWithdrawalReceipt(
		contract.WrapPluginContext(fakeCtx.WithSender(ownerAddr)),
		&ConfirmWithdrawalReceiptRequest{},
	)
	require.Equal(ErrNotAuthorized, err, "Only an oracle should be allowed to confirm withdrawals")

	require.NoError(gwContract.UpdateMainnetGatewayAddress(
		contract.WrapPluginContext(fakeCtx.WithSender(ownerAddr)),
		&UpdateMainnetGatewayRequest{
			MainnetGatewayAddress: contractAddr.MarshalPB(),
		}), "Owner should be allowed to replace mainet gateway address")

	err = gwContract.UpdateMainnetGatewayAddress(
		contract.WrapPluginContext(fakeCtx.WithSender(oracleAddr)),
		&UpdateMainnetGatewayRequest{
			MainnetGatewayAddress: contractAddr.MarshalPB(),
		})
	require.Equal(ErrNotAuthorized, err, "Only owner should be allowed to replace mainet gateway address")
}

func (ts *GatewayTestSuite) TestResetBlock() {
	require := ts.Require()

	pctx := lp.CreateFakeContext(addr1, addr1)
	oracleAddr := ts.dAppAddr2

	startBlock := uint64(123)
	gw := &UnsafeGateway{Gateway{}}
	require.NoError(gw.Init(contract.WrapPluginContext(pctx.WithSender(ts.dAppAddr3)), &InitRequest{
		Owner:                addr1.MarshalPB(),
		Oracles:              []*types.Address{oracleAddr.MarshalPB()},
		FirstMainnetBlockNum: startBlock,
	}))

	// Pre state
	resp, err := gw.GetState(contract.WrapPluginContext(pctx.WithSender(oracleAddr)), &GatewayStateRequest{})
	require.NoError(err)
	s := resp.State
	ts.Equal(startBlock, s.LastMainnetBlockNum)

	// Anyone can call the function
	block2 := uint64(0)
	require.NoError(gw.ResetMainnetBlock(contract.WrapPluginContext(pctx.WithSender(addr1)), &ResetMainnetBlockRequest{}))

	// Post state
	resp, err = gw.GetState(contract.WrapPluginContext(pctx.WithSender(oracleAddr)), &GatewayStateRequest{})
	require.NoError(err)
	s = resp.State
	ts.Equal(block2, s.LastMainnetBlockNum)

	block3 := uint64(1000)
	require.NoError(gw.ResetMainnetBlock(contract.WrapPluginContext(pctx.WithSender(addr1)), &ResetMainnetBlockRequest{
		LastMainnetBlockNum: block3,
	}))

	// Post state
	resp, err = gw.GetState(contract.WrapPluginContext(pctx.WithSender(oracleAddr)), &GatewayStateRequest{})
	require.NoError(err)
	s = resp.State
	ts.Equal(block3, s.LastMainnetBlockNum)

}

func (ts *GatewayTestSuite) TestOraclePermissions() {
	require := ts.Require()
	fakeCtx := lp.CreateFakeContext(ts.dAppAddr, loom.RootAddress("chain"))
	ownerAddr := ts.dAppAddr
	oracleAddr := ts.dAppAddr2
	oracle2Addr := ts.dAppAddr3

	gwContract := &Gateway{}
	require.NoError(gwContract.Init(
		contract.WrapPluginContext(fakeCtx),
		&InitRequest{
			Owner:   ownerAddr.MarshalPB(),
			Oracles: []*types.Address{oracleAddr.MarshalPB()},
		},
	))

	// Check that an oracle added via genesis has all the expected permission
	err := gwContract.ProcessEventBatch(
		contract.WrapPluginContext(fakeCtx.WithSender(oracleAddr)),
		&ProcessEventBatchRequest{},
	)
	require.NotEqual(ErrNotAuthorized, err, "Genesis Oracle should be allowed to submit Mainnet events")

	err = gwContract.ConfirmWithdrawalReceipt(
		contract.WrapPluginContext(fakeCtx.WithSender(oracleAddr)),
		&ConfirmWithdrawalReceiptRequest{},
	)
	require.NotEqual(ErrNotAuthorized, err, "Genesis Oracle should be allowed to confirm withdrawals")

	// Check that a newly added oracle has all the expected permissions
	require.NoError(gwContract.AddOracle(
		contract.WrapPluginContext(fakeCtx.WithSender(ownerAddr)),
		&AddOracleRequest{Oracle: oracle2Addr.MarshalPB()},
	))

	err = gwContract.ProcessEventBatch(
		contract.WrapPluginContext(fakeCtx.WithSender(oracle2Addr)),
		&ProcessEventBatchRequest{},
	)
	require.NotEqual(ErrNotAuthorized, err, "New Oracle should be allowed to submit Mainnet events")

	err = gwContract.ConfirmWithdrawalReceipt(
		contract.WrapPluginContext(fakeCtx.WithSender(oracle2Addr)),
		&ConfirmWithdrawalReceiptRequest{},
	)
	require.NotEqual(ErrNotAuthorized, err, "New Oracle should be allowed to confirm withdrawals")

	// Check that an oracle that has been removed had all its permissions revoked
	require.NoError(gwContract.RemoveOracle(
		contract.WrapPluginContext(fakeCtx.WithSender(ownerAddr)),
		&RemoveOracleRequest{Oracle: oracleAddr.MarshalPB()},
	))

	err = gwContract.ProcessEventBatch(
		contract.WrapPluginContext(fakeCtx.WithSender(oracleAddr)),
		&ProcessEventBatchRequest{},
	)
	require.Equal(ErrNotAuthorized, err, "Removed Oracle shouldn't be allowed to submit Mainnet events")

	err = gwContract.ConfirmWithdrawalReceipt(
		contract.WrapPluginContext(fakeCtx.WithSender(oracleAddr)),
		&ConfirmWithdrawalReceiptRequest{},
	)
	require.Equal(ErrNotAuthorized, err, "Removed Oracle shouldn't be allowed to confirm withdrawals")
}

// TODO: Re-enable when ERC20 is supported
/*
func TestOldEventBatchProcessing(t *testing.T) {
	callerAddr := addr1
	contractAddr := loom.Address{}
	fakeCtx := lp.CreateFakeContext(callerAddr, contractAddr)
	gw := &Gateway{}
	gwAddr := fakeCtx.CreateContract(contract.MakePluginContract(gw))
	gwCtx := contract.WrapPluginContext(fakeCtx.WithAddress(gwAddr))

	coinContract, err := deployCoinContract(fakeCtx, gwAddr, 100000)
	require.Nil(t, err)
	initialGatewayCoinBal := sciNot(100000, coinDecimals)

	err = gw.Init(gwCtx, &GatewayInitRequest{
		Oracles: []*types.Address{addr1.MarshalPB()},
		Tokens: []*GatewayTokenMapping{&GatewayTokenMapping{
			FromToken: ethTokenAddr.MarshalPB(),
			ToToken:   coinContract.Address.MarshalPB(),
		}},
	})
	require.Nil(t, err)

	coinBal, err := coinContract.getBalance(fakeCtx, gwAddr)
	require.Nil(t, err)
	assert.Equal(t, initialGatewayCoinBal, coinBal, "gateway account balance should match initial balance")

	err = gw.ProcessEventBatch(gwCtx, &ProcessEventBatchRequest{
		FtDeposits: genTokenDeposits([]uint64{5}),
	})
	require.Nil(t, err)
	resp, err := gw.GetState(gwCtx, &GatewayStateRequest{})
	require.Nil(t, err)
	s := resp.State
	assert.Equal(t, uint64(5), s.LastEthBlock)

	coinBal, err = coinContract.getBalance(fakeCtx, gwAddr)
	require.Nil(t, err)
	assert.True(t, coinBal.Cmp(initialGatewayCoinBal) < 0, "gateway account balance should have been reduced")

	// Events from each block should only be processed once, even if multiple batches contain the
	// same block.
	err = gw.ProcessEventBatch(gwCtx, &ProcessEventBatchRequest{
		FtDeposits: genTokenDeposits([]uint64{5}),
	})
	require.NotNil(t, err)
	resp, err = gw.GetState(gwCtx, &GatewayStateRequest{})
	require.Nil(t, err)
	s = resp.State
	assert.Equal(t, uint64(5), s.LastEthBlock)

	coinBal2, err := coinContract.getBalance(fakeCtx, gwAddr)
	require.Nil(t, err)
	assert.True(t, coinBal.Cmp(coinBal2) == 0, "gateway account balance should not have changed")
}
*/

func (ts *GatewayTestSuite) TestConfirmWithdrawalReceiptV2() {
	require := ts.Require()
	fakeCtx := plugin.CreateFakeContextWithEVM(ts.dAppAddr, loom.RootAddress("chain"))

	addressMapper, err := deployAddressMapperContract(fakeCtx)
	require.NoError(err)

	ownerAddr := ts.dAppAddr2

	gwHelper, err := deployGatewayContract(fakeCtx, &InitRequest{
		Owner:   ownerAddr.MarshalPB(),
		Oracles: []*types.Address{ts.dAppAddr.MarshalPB()},
	}, EthereumGateway)
	require.NoError(err)

	ethHelper, err := deployETHContract(fakeCtx)
	require.NoError(err)

	// Deploy ERC721 Solidity contract to DAppChain EVM
	dappTokenAddr, err := deployTokenContract(fakeCtx, "SampleERC721Token", gwHelper.Address, ts.dAppAddr)
	require.NoError(err)

	require.NoError(gwHelper.AddContractMapping(fakeCtx, ethTokenAddr, dappTokenAddr))
	sig, err := address_mapper.SignIdentityMapping(ts.ethAddr, ts.dAppAddr, ts.ethKey, sigType)
	require.NoError(err)
	require.NoError(addressMapper.AddIdentityMapping(fakeCtx, ts.ethAddr, ts.dAppAddr, sig))

	// Initializes validators
	for i, _ := range ts.validatorsDetails {
		var sig []byte

		sig, err = address_mapper.SignIdentityMapping(ts.validatorsDetails[i].EthAddress,
			ts.validatorsDetails[i].DAppAddress, ts.validatorsDetails[i].EthPrivKey, sigType)
		require.NoError(err)

		require.NoError(addressMapper.AddIdentityMapping(fakeCtx.WithSender(ts.validatorsDetails[i].DAppAddress), ts.validatorsDetails[i].EthAddress, ts.validatorsDetails[i].DAppAddress, sig))
	}

	// First two become trusted validators
	trustedValidatorDetails := make([]*testValidator, 2)
	trustedValidatorDetails[0] = ts.validatorsDetails[0]
	trustedValidatorDetails[1] = ts.validatorsDetails[1]

	trustedValidators := &TrustedValidators{
		Validators: make([]*types.Address, len(trustedValidatorDetails)),
	}
	for i, validatorDetails := range trustedValidatorDetails {
		trustedValidators.Validators[i] = validatorDetails.DAppAddress.MarshalPB()
	}

	dposValidators := make([]*types.Validator, len(ts.validatorsDetails))
	for i, _ := range dposValidators {
		dposValidators[i] = &types.Validator{
			PubKey: ts.validatorsDetails[i].DAppPrivKey.PubKey().Bytes(),
			Power:  10,
		}
	}

	_, err = deployDPOSV2Contract(fakeCtx, dposValidators)
	require.NoError(err)

	validators := make([]*loom.Validator, len(ts.validatorsDetails))
	for i, _ := range validators {
		validators[i] = &loom.Validator{
			PubKey: ts.validatorsDetails[i].DAppPrivKey.PubKey().Bytes(),
			Power:  10,
		}
	}
	fakeCtx = fakeCtx.WithValidators(validators)

	require.NoError(gwHelper.Contract.UpdateTrustedValidators(gwHelper.ContractCtx(fakeCtx.WithSender(ownerAddr)), &UpdateTrustedValidatorsRequest{
		TrustedValidators: trustedValidators,
	}))

	require.NoError(gwHelper.Contract.UpdateValidatorAuthStrategy(gwHelper.ContractCtx(fakeCtx.WithSender(ownerAddr)), &UpdateValidatorAuthStrategyRequest{
		AuthStrategy: tgtypes.ValidatorAuthStrategy_USE_TRUSTED_VALIDATORS,
	}))

	// Mint some tokens/ETH and distribute to users
	token1 := big.NewInt(123)
	token2 := big.NewInt(456)
	token3 := big.NewInt(789)
	ethAmt := big.NewInt(999)
	erc721 := newERC721Context(gwHelper.ContractCtx(fakeCtx), dappTokenAddr)
	require.NoError(erc721.mintToGateway(token1))
	require.NoError(erc721.safeTransferFrom(gwHelper.Address, ts.dAppAddr, token1))
	require.NoError(erc721.mintToGateway(token2))
	require.NoError(erc721.safeTransferFrom(gwHelper.Address, ts.dAppAddr, token2))
	require.NoError(erc721.mintToGateway(token3))
	require.NoError(erc721.safeTransferFrom(gwHelper.Address, ts.dAppAddr2, token3))
	require.NoError(
		ethHelper.mintToGateway(
			fakeCtx.WithSender(gwHelper.Address),
			big.NewInt(0).Mul(ethAmt, big.NewInt(2)),
		),
	)
	require.NoError(ethHelper.transfer(fakeCtx.WithSender(gwHelper.Address), ts.dAppAddr, ethAmt))
	require.NoError(ethHelper.transfer(fakeCtx.WithSender(gwHelper.Address), ts.dAppAddr2, ethAmt))

	// Authorize Gateway to withdraw tokens from users
	erc721 = newERC721Context(
		// Abusing the contract context here, WithAddress() is really meant for contract addresses.
		// Unfortunately WithSender() has no effect when calling the EVM via the fake context
		// because the caller is always set to the contract address stored in the context.
		contract.WrapPluginContext(fakeCtx.WithAddress(ts.dAppAddr)),
		dappTokenAddr,
	)
	require.NoError(erc721.approve(gwHelper.Address, token1))
	require.NoError(erc721.approve(gwHelper.Address, token2))

	erc721 = newERC721Context(
		contract.WrapPluginContext(fakeCtx.WithAddress(ts.dAppAddr2)),
		dappTokenAddr,
	)
	require.NoError(erc721.approve(gwHelper.Address, token3))

	require.NoError(ethHelper.approve(fakeCtx.WithSender(ts.dAppAddr), gwHelper.Address, ethAmt))
	require.NoError(ethHelper.approve(fakeCtx.WithSender(ts.dAppAddr2), gwHelper.Address, ethAmt))

	// Withdraw to an Ethereum account that isn't mapped to a DAppChain account via Address Mapper
	err = gwHelper.Contract.WithdrawToken(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr)),
		&WithdrawTokenRequest{
			TokenContract: ethTokenAddr.MarshalPB(),
			TokenKind:     TokenKind_ERC721,
			TokenID:       &types.BigUInt{Value: *loom.NewBigUInt(token1)},
			Recipient:     ts.ethAddr2.MarshalPB(),
		},
	)
	require.NoError(err)

	pendingWithdrawalResp, err := gwHelper.Contract.PendingWithdrawalsV2(gwHelper.ContractCtx(fakeCtx), &PendingWithdrawalsRequest{
		MainnetGateway: loom.RootAddress("eth").MarshalPB(),
	})
	require.NoError(err)

	pendingWithdrawal := pendingWithdrawalResp.Withdrawals[0]

	withdrawalReceiptResp, err := gwHelper.Contract.WithdrawalReceipt(gwHelper.ContractCtx(fakeCtx), &WithdrawalReceiptRequest{
		Owner: pendingWithdrawal.TokenOwner,
	})
	require.NoError(err)

	calculatedHash := client.ToEthereumSignedMessage(gwHelper.Contract.calculateHashFromReceiptV2(loom.RootAddress("eth").MarshalPB(), withdrawalReceiptResp.Receipt))
	aggregatedSignature := make([]byte, 0, 65*len(trustedValidatorDetails))
	for _, validatorDetails := range trustedValidatorDetails {
		sig, err := evmcompat.SoliditySign(calculatedHash, validatorDetails.EthPrivKey)
		require.NoError(err)
		aggregatedSignature = append(aggregatedSignature, sig...)
	}

	// Proper signature should work
	err = gwHelper.Contract.ConfirmWithdrawalReceiptV2(gwHelper.ContractCtx(fakeCtx.WithSender(ts.validatorsDetails[2].DAppAddress)), &ConfirmWithdrawalReceiptRequestV2{
		TokenOwner:      pendingWithdrawal.TokenOwner,
		OracleSignature: aggregatedSignature,
		MainnetGateway:  loom.RootAddress("eth").MarshalPB(),
	})
	require.NoError(err)

	// Simulate token withdrawal from Ethereum Gateway to clear out the pending withdrawal
	err = gwHelper.Contract.ProcessEventBatch(gwHelper.ContractCtx(fakeCtx),
		&ProcessEventBatchRequest{
			Events: []*MainnetEvent{
				&MainnetEvent{
					EthBlock: 5,
					Payload: &MainnetWithdrawalEvent{
						Withdrawal: &MainnetTokenWithdrawn{
							TokenOwner:    ts.ethAddr2.MarshalPB(),
							TokenContract: ethTokenAddr.MarshalPB(),
							TokenKind:     TokenKind_ERC721,
							TokenID:       &types.BigUInt{Value: *loom.NewBigUInt(token1)},
						},
					},
				},
			},
		},
	)
	require.NoError(err)

	err = gwHelper.Contract.WithdrawToken(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr2)),
		&WithdrawTokenRequest{
			TokenContract: ethTokenAddr.MarshalPB(),
			TokenKind:     TokenKind_ERC721,
			TokenID:       &types.BigUInt{Value: *loom.NewBigUInt(token3)},
			Recipient:     ts.ethAddr2.MarshalPB(),
		},
	)
	require.NoError(err)

	// Replayed  signature should not work
	err = gwHelper.Contract.ConfirmWithdrawalReceiptV2(gwHelper.ContractCtx(fakeCtx.WithSender(ts.validatorsDetails[2].DAppAddress)), &ConfirmWithdrawalReceiptRequestV2{
		TokenOwner:      ts.dAppAddr2.MarshalPB(),
		OracleSignature: aggregatedSignature,
		MainnetGateway:  loom.RootAddress("eth").MarshalPB(),
	})
	require.EqualError(err, ErrNotEnoughSignatures.Error(), "replayed hash and signature should not work")

	withdrawalReceiptResp, err = gwHelper.Contract.WithdrawalReceipt(gwHelper.ContractCtx(fakeCtx), &WithdrawalReceiptRequest{
		Owner: ts.dAppAddr2.MarshalPB(),
	})
	require.NoError(err)

	calculatedHash = client.ToEthereumSignedMessage(gwHelper.Contract.calculateHashFromReceiptV2(loom.RootAddress("eth").MarshalPB(), withdrawalReceiptResp.Receipt))
	aggregatedSignature = make([]byte, 0, 65*len(trustedValidatorDetails))
	for _, validatorDetails := range trustedValidatorDetails {
		sig, err := evmcompat.SoliditySign(calculatedHash, validatorDetails.EthPrivKey)
		require.NoError(err)
		aggregatedSignature = append(aggregatedSignature, sig...)
	}

	// Proper signature should work
	err = gwHelper.Contract.ConfirmWithdrawalReceiptV2(gwHelper.ContractCtx(fakeCtx.WithSender(ts.validatorsDetails[2].DAppAddress)), &ConfirmWithdrawalReceiptRequestV2{
		TokenOwner:      ts.dAppAddr2.MarshalPB(),
		OracleSignature: aggregatedSignature,
		MainnetGateway:  loom.RootAddress("eth").MarshalPB(),
	})
	require.NoError(err)

	require.NoError(gwHelper.Contract.UpdateValidatorAuthStrategy(gwHelper.ContractCtx(fakeCtx.WithSender(ownerAddr)), &UpdateValidatorAuthStrategyRequest{
		AuthStrategy: tgtypes.ValidatorAuthStrategy_USE_DPOS_VALIDATORS,
	}))

	// Simulate token withdrawal from Ethereum Gateway to clear out the pending withdrawal
	err = gwHelper.Contract.ProcessEventBatch(gwHelper.ContractCtx(fakeCtx),
		&ProcessEventBatchRequest{
			Events: []*MainnetEvent{
				&MainnetEvent{
					EthBlock: 10,
					Payload: &MainnetWithdrawalEvent{
						Withdrawal: &MainnetTokenWithdrawn{
							TokenOwner:    ts.ethAddr2.MarshalPB(),
							TokenContract: ethTokenAddr.MarshalPB(),
							TokenKind:     TokenKind_ERC721,
							TokenID:       &types.BigUInt{Value: *loom.NewBigUInt(token1)},
						},
					},
				},
			},
		},
	)
	require.NoError(err)

	err = gwHelper.Contract.WithdrawToken(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr2)),
		&WithdrawTokenRequest{
			TokenContract: ethTokenAddr.MarshalPB(),
			TokenKind:     TokenKind_ERC721,
			TokenID:       &types.BigUInt{Value: *loom.NewBigUInt(token3)},
			Recipient:     ts.ethAddr2.MarshalPB(),
		},
	)
	require.NoError(err)

	withdrawalReceiptResp, err = gwHelper.Contract.WithdrawalReceipt(gwHelper.ContractCtx(fakeCtx), &WithdrawalReceiptRequest{
		Owner: ts.dAppAddr2.MarshalPB(),
	})
	require.NoError(err)

	calculatedHash = client.ToEthereumSignedMessage(gwHelper.Contract.calculateHashFromReceiptV2(loom.RootAddress("eth").MarshalPB(), withdrawalReceiptResp.Receipt))
	aggregatedSignature = make([]byte, 0, 65*len(trustedValidatorDetails))
	for _, validatorDetails := range trustedValidatorDetails {
		sig, err := evmcompat.SoliditySign(calculatedHash, validatorDetails.EthPrivKey)
		require.NoError(err)
		aggregatedSignature = append(aggregatedSignature, sig...)
	}

	// Due to strategy change this should not work
	err = gwHelper.Contract.ConfirmWithdrawalReceiptV2(gwHelper.ContractCtx(fakeCtx.WithSender(ts.validatorsDetails[2].DAppAddress)), &ConfirmWithdrawalReceiptRequestV2{
		TokenOwner:      ts.dAppAddr2.MarshalPB(),
		OracleSignature: aggregatedSignature,
		MainnetGateway:  loom.RootAddress("eth").MarshalPB(),
	})
	require.EqualError(err, ErrNotAuthorized.Error())

	calculatedHash = client.ToEthereumSignedMessage(gwHelper.Contract.calculateHashFromReceiptV2(loom.RootAddress("eth").MarshalPB(), withdrawalReceiptResp.Receipt))
	aggregatedSignature = make([]byte, 0, 65*len(ts.validatorsDetails))
	for _, validatorDetails := range ts.validatorsDetails {
		sig, err := evmcompat.SoliditySign(calculatedHash, validatorDetails.EthPrivKey)
		require.NoError(err)
		aggregatedSignature = append(aggregatedSignature, sig...)
	}

	// Signature prepared accordance with new strategy should work
	err = gwHelper.Contract.ConfirmWithdrawalReceiptV2(gwHelper.ContractCtx(fakeCtx.WithSender(ts.validatorsDetails[2].DAppAddress)), &ConfirmWithdrawalReceiptRequestV2{
		TokenOwner:      ts.dAppAddr2.MarshalPB(),
		OracleSignature: aggregatedSignature,
		MainnetGateway:  loom.RootAddress("eth").MarshalPB(),
	})
	require.NoError(err)
}

func (ts *GatewayTestSuite) TestOutOfOrderEventBatchProcessing() {
	require := ts.Require()
	fakeCtx := plugin.CreateFakeContextWithEVM(ts.dAppAddr /*caller*/, loom.RootAddress("chain") /*contract*/)

	addressMapper, err := deployAddressMapperContract(fakeCtx)
	require.NoError(err)

	oracleAddr := ts.dAppAddr
	ownerAddr := ts.dAppAddr2

	gwHelper, err := deployGatewayContract(fakeCtx, &InitRequest{
		Owner:   ownerAddr.MarshalPB(),
		Oracles: []*types.Address{oracleAddr.MarshalPB()},
	}, EthereumGateway)
	require.NoError(err)

	// Deploy ERC721 Solidity contract to DAppChain EVM
	dappTokenAddr, err := deployTokenContract(fakeCtx, "SampleERC721Token", gwHelper.Address, ts.dAppAddr)
	require.NoError(err)

	require.NoError(gwHelper.AddContractMapping(fakeCtx, ethTokenAddr, dappTokenAddr))
	sig, err := address_mapper.SignIdentityMapping(ts.ethAddr, ts.dAppAddr, ts.ethKey, sigType)
	require.NoError(err)
	require.NoError(addressMapper.AddIdentityMapping(fakeCtx, ts.ethAddr, ts.dAppAddr, sig))

	// Batch must have events ordered by block (lowest to highest)
	err = gwHelper.Contract.ProcessEventBatch(gwHelper.ContractCtx(fakeCtx), &ProcessEventBatchRequest{
		Events: genERC721Deposits(ethTokenAddr, ts.ethAddr, []uint64{10, 9}, nil),
	})
	require.Equal(ErrInvalidEventBatch, err, "Should fail because events in batch are out of order")
}

// TODO: Re-enable when ETH transfers are supported
/*
func TestEthDeposit(t *testing.T) {
	callerAddr := addr1
	contractAddr := loom.Address{}
	fakeCtx := lp.CreateFakeContext(callerAddr, contractAddr)
	gw := &Gateway{}
	gwAddr := fakeCtx.CreateContract(contract.MakePluginContract(gw))
	gwCtx := contract.WrapPluginContext(fakeCtx.WithAddress(gwAddr))

	coinContract, err := deployCoinContract(fakeCtx, gwAddr, 100000)
	err = gw.Init(gwCtx, &GatewayInitRequest{
		Oracles: []*types.Address{addr1.MarshalPB()},
		Tokens: []*GatewayTokenMapping{&GatewayTokenMapping{
			FromToken: ethTokenAddr.MarshalPB(),
			ToToken:   coinContract.Address.MarshalPB(),
		}},
	})
	require.Nil(t, err)

	bal, err := coinContract.getBalance(fakeCtx, dappAccAddr1)
	require.Nil(t, err)
	assert.Equal(t, uint64(0), bal.Uint64(), "receiver account balance should be zero")

	gwBal, err := coinContract.getBalance(fakeCtx, gwAddr)
	require.Nil(t, err)

	depositAmount := int64(10)
	err = gw.ProcessEventBatch(gwCtx, &ProcessEventBatchRequest{
		FtDeposits: []*TokenDeposit{
			&TokenDeposit{
				Token:    ethTokenAddr.MarshalPB(),
				From:     ethAccAddr1.MarshalPB(),
				To:       dappAccAddr1.MarshalPB(),
				Amount:   &types.BigUInt{Value: *loom.NewBigUIntFromInt(depositAmount)},
				EthBlock: 5,
			},
		},
	})
	require.Nil(t, err)

	bal2, err := coinContract.getBalance(fakeCtx, dappAccAddr1)
	require.Nil(t, err)
	assert.Equal(t, depositAmount, bal2.Int64(), "receiver account balance should match deposit amount")

	gwBal2, err := coinContract.getBalance(fakeCtx, gwAddr)
	require.Nil(t, err)
	assert.Equal(t, depositAmount, gwBal.Sub(gwBal, gwBal2).Int64(), "gateway account balance reduced by deposit amount")
}
*/

func (ts *GatewayTestSuite) TestGatewayERC721Deposit() {
	require := ts.Require()
	fakeCtx := plugin.CreateFakeContextWithEVM(ts.dAppAddr, loom.RootAddress("chain"))

	addressMapper, err := deployAddressMapperContract(fakeCtx)
	require.NoError(err)

	gwHelper, err := deployGatewayContract(fakeCtx, &InitRequest{
		Owner:   ts.dAppAddr2.MarshalPB(),
		Oracles: []*types.Address{ts.dAppAddr.MarshalPB()},
	}, EthereumGateway)
	require.NoError(err)

	// Deploy ERC721 Solidity contract to DAppChain EVM
	dappTokenAddr, err := deployTokenContract(fakeCtx, "SampleERC721Token", gwHelper.Address, ts.dAppAddr)
	require.NoError(err)

	require.NoError(gwHelper.AddContractMapping(fakeCtx, ethTokenAddr, dappTokenAddr))
	sig, err := address_mapper.SignIdentityMapping(ts.ethAddr, ts.dAppAddr, ts.ethKey, sigType)
	require.NoError(err)
	require.NoError(addressMapper.AddIdentityMapping(fakeCtx, ts.ethAddr, ts.dAppAddr, sig))

	// Send token to Gateway Go contract
	err = gwHelper.Contract.ProcessEventBatch(gwHelper.ContractCtx(fakeCtx), &ProcessEventBatchRequest{
		Events: []*MainnetEvent{
			&MainnetEvent{
				EthBlock: 5,
				Payload: &MainnetDepositEvent{
					Deposit: &MainnetTokenDeposited{
						TokenKind:     TokenKind_ERC721,
						TokenContract: ethTokenAddr.MarshalPB(),
						TokenOwner:    ts.ethAddr.MarshalPB(),
						TokenID:       &types.BigUInt{Value: *loom.NewBigUIntFromInt(123)},
					},
				},
			},
		},
	})
	require.NoError(err)

	erc721 := newERC721StaticContext(gwHelper.ContractCtx(fakeCtx), dappTokenAddr)
	ownerAddr, err := erc721.ownerOf(big.NewInt(123))
	require.NoError(err)
	require.Equal(ts.dAppAddr, ownerAddr)
}

func (ts *GatewayTestSuite) TestWithdrawalRestrictions() {
	require := ts.Require()
	fakeCtx := plugin.CreateFakeContextWithEVM(ts.dAppAddr, loom.RootAddress("chain"))

	addressMapper, err := deployAddressMapperContract(fakeCtx)
	require.NoError(err)

	gwHelper, err := deployGatewayContract(fakeCtx, &InitRequest{
		Owner:   ts.dAppAddr2.MarshalPB(),
		Oracles: []*types.Address{ts.dAppAddr.MarshalPB()},
	}, EthereumGateway)
	require.NoError(err)

	ethHelper, err := deployETHContract(fakeCtx)
	require.NoError(err)

	// Deploy ERC721 Solidity contract to DAppChain EVM
	dappTokenAddr, err := deployTokenContract(fakeCtx, "SampleERC721Token", gwHelper.Address, ts.dAppAddr)
	require.NoError(err)

	require.NoError(gwHelper.AddContractMapping(fakeCtx, ethTokenAddr, dappTokenAddr))
	sig, err := address_mapper.SignIdentityMapping(ts.ethAddr, ts.dAppAddr, ts.ethKey, sigType)
	require.NoError(err)
	require.NoError(addressMapper.AddIdentityMapping(fakeCtx, ts.ethAddr, ts.dAppAddr, sig))

	// Mint some tokens/ETH and distribute to users
	token1 := big.NewInt(123)
	token2 := big.NewInt(456)
	token3 := big.NewInt(789)
	ethAmt := big.NewInt(999)
	erc721 := newERC721Context(gwHelper.ContractCtx(fakeCtx), dappTokenAddr)
	require.NoError(erc721.mintToGateway(token1))
	require.NoError(erc721.safeTransferFrom(gwHelper.Address, ts.dAppAddr, token1))
	require.NoError(erc721.mintToGateway(token2))
	require.NoError(erc721.safeTransferFrom(gwHelper.Address, ts.dAppAddr, token2))
	require.NoError(erc721.mintToGateway(token3))
	require.NoError(erc721.safeTransferFrom(gwHelper.Address, ts.dAppAddr2, token3))
	require.NoError(
		ethHelper.mintToGateway(
			fakeCtx.WithSender(gwHelper.Address),
			big.NewInt(0).Mul(ethAmt, big.NewInt(2)),
		),
	)
	require.NoError(ethHelper.transfer(fakeCtx.WithSender(gwHelper.Address), ts.dAppAddr, ethAmt))
	require.NoError(ethHelper.transfer(fakeCtx.WithSender(gwHelper.Address), ts.dAppAddr2, ethAmt))

	// Authorize Gateway to withdraw tokens from users
	erc721 = newERC721Context(
		// Abusing the contract context here, WithAddress() is really meant for contract addresses.
		// Unfortunately WithSender() has no effect when calling the EVM via the fake context
		// because the caller is always set to the contract address stored in the context.
		contract.WrapPluginContext(fakeCtx.WithAddress(ts.dAppAddr)),
		dappTokenAddr,
	)
	require.NoError(erc721.approve(gwHelper.Address, token1))
	require.NoError(erc721.approve(gwHelper.Address, token2))

	erc721 = newERC721Context(
		contract.WrapPluginContext(fakeCtx.WithAddress(ts.dAppAddr2)),
		dappTokenAddr,
	)
	require.NoError(erc721.approve(gwHelper.Address, token3))

	require.NoError(ethHelper.approve(fakeCtx.WithSender(ts.dAppAddr), gwHelper.Address, ethAmt))
	require.NoError(ethHelper.approve(fakeCtx.WithSender(ts.dAppAddr2), gwHelper.Address, ethAmt))

	// Withdraw to an Ethereum account that isn't mapped to a DAppChain account via Address Mapper
	err = gwHelper.Contract.WithdrawToken(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr)),
		&WithdrawTokenRequest{
			TokenContract: ethTokenAddr.MarshalPB(),
			TokenKind:     TokenKind_ERC721,
			TokenID:       &types.BigUInt{Value: *loom.NewBigUInt(token1)},
			Recipient:     ts.ethAddr2.MarshalPB(),
		},
	)
	require.NoError(err)

	// Shouldn't be possible to have more than one pending withdrawal from any one DAppChain account
	err = gwHelper.Contract.WithdrawToken(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr)),
		&WithdrawTokenRequest{
			TokenContract: ethTokenAddr.MarshalPB(),
			TokenKind:     TokenKind_ERC721,
			TokenID:       &types.BigUInt{Value: *loom.NewBigUInt(token2)},
		},
	)
	require.Equal(ErrPendingWithdrawalExists, err)

	// ETH should be treated like any other token, it shouldn't be possible to have more than
	// one pending withdrawal from any one DAppChain account
	err = gwHelper.Contract.WithdrawETH(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr)),
		&WithdrawETHRequest{
			Amount:         &types.BigUInt{Value: *loom.NewBigUInt(ethAmt)},
			MainnetGateway: ethTokenAddr3.MarshalPB(), // doesn't matter for this test
		},
	)
	require.Equal(ErrPendingWithdrawalExists, err)

	// Shouldn't be possible to have more than one pending withdrawal to any one Ethereum account
	err = gwHelper.Contract.WithdrawToken(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr2)),
		&WithdrawTokenRequest{
			TokenContract: ethTokenAddr.MarshalPB(),
			TokenKind:     TokenKind_ERC721,
			TokenID:       &types.BigUInt{Value: *loom.NewBigUInt(token3)},
			Recipient:     ts.ethAddr2.MarshalPB(),
		},
	)
	require.Equal(ErrPendingWithdrawalExists, err)

	// Same restriction should apply to ETH withdrawals
	err = gwHelper.Contract.WithdrawETH(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr2)),
		&WithdrawETHRequest{
			Amount:         &types.BigUInt{Value: *loom.NewBigUInt(ethAmt)},
			MainnetGateway: ethTokenAddr3.MarshalPB(), // doesn't matter for this test
			Recipient:      ts.ethAddr2.MarshalPB(),
		},
	)
	require.Equal(ErrPendingWithdrawalExists, err)

	// Simulate token withdrawal from Ethereum Gateway to clear out the pending withdrawal
	err = gwHelper.Contract.ProcessEventBatch(gwHelper.ContractCtx(fakeCtx),
		&ProcessEventBatchRequest{
			Events: []*MainnetEvent{
				&MainnetEvent{
					EthBlock: 5,
					Payload: &MainnetWithdrawalEvent{
						Withdrawal: &MainnetTokenWithdrawn{
							TokenOwner:    ts.ethAddr2.MarshalPB(),
							TokenContract: ethTokenAddr.MarshalPB(),
							TokenKind:     TokenKind_ERC721,
							TokenID:       &types.BigUInt{Value: *loom.NewBigUInt(token1)},
						},
					},
				},
			},
		},
	)
	require.NoError(err)

	// Retry the last failed ERC721 withdrawal, should work this time because no pending withdrawal
	// to the Ethereum account should exist...
	err = gwHelper.Contract.WithdrawToken(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr2)),
		&WithdrawTokenRequest{
			TokenContract: ethTokenAddr.MarshalPB(),
			TokenKind:     TokenKind_ERC721,
			TokenID:       &types.BigUInt{Value: *loom.NewBigUInt(token3)},
			Recipient:     ts.ethAddr2.MarshalPB(),
		},
	)
	require.NoError(err)

	// Simulate token withdrawal from Ethereum Gateway to clear out the pending withdrawal
	err = gwHelper.Contract.ProcessEventBatch(gwHelper.ContractCtx(fakeCtx),
		&ProcessEventBatchRequest{
			Events: []*MainnetEvent{
				&MainnetEvent{
					EthBlock: 10,
					Payload: &MainnetWithdrawalEvent{
						Withdrawal: &MainnetTokenWithdrawn{
							TokenOwner:    ts.ethAddr2.MarshalPB(),
							TokenContract: ethTokenAddr.MarshalPB(),
							TokenKind:     TokenKind_ERC721,
							TokenID:       &types.BigUInt{Value: *loom.NewBigUInt(token3)},
						},
					},
				},
			},
		},
	)
	require.NoError(err)

	// Retry the last failed ETH withdrawal
	err = gwHelper.Contract.WithdrawETH(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr2)),
		&WithdrawETHRequest{
			Amount:         &types.BigUInt{Value: *loom.NewBigUInt(ethAmt)},
			MainnetGateway: ethTokenAddr3.MarshalPB(), // doesn't matter for this test
			Recipient:      ts.ethAddr2.MarshalPB(),
		},
	)
	require.NoError(err)

	fakeCtx = fakeCtx.WithFeature(features.TGCheckZeroAmount, true)
	require.True(fakeCtx.FeatureEnabled(features.TGCheckZeroAmount, false))

	// ERC20 withdrawal restriction test
	// Deploy ERC20 Solidity contract to DAppChain EVM, mint some ERC20 and transfer to ts.dAppAddr
	erc20Addr, err := deployTokenContract(fakeCtx, "SampleERC20Token", gwHelper.Address, ts.dAppAddr3)
	require.NoError(err)
	require.NoError(gwHelper.AddContractMapping(fakeCtx, ethTokenAddr2, erc20Addr))
	erc20 := newERC20Context(gwHelper.ContractCtx(fakeCtx), erc20Addr)
	initialAmount := big.NewInt(200)
	zeroAmount := big.NewInt(0)
	require.NoError(erc20.mintToGateway(initialAmount))
	require.NoError(erc20.transfer(ts.dAppAddr3, initialAmount))

	//Withdraw ERC20 with zero amount
	err = gwHelper.Contract.WithdrawToken(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr3)),
		&WithdrawTokenRequest{
			TokenContract: ethTokenAddr2.MarshalPB(),
			TokenKind:     TokenKind_ERC20,
			TokenAmount:   &types.BigUInt{Value: *loom.NewBigUInt(zeroAmount)},
			Recipient:     ts.ethAddr3.MarshalPB(),
		},
	)
	require.Equal(ErrInvalidRequest, err)

	//Withdraw ERC721X with zero amount
	err = gwHelper.Contract.WithdrawToken(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr3)),
		&WithdrawTokenRequest{
			TokenContract: ethTokenAddr.MarshalPB(),
			TokenKind:     TokenKind_ERC721X,
			TokenID:       &types.BigUInt{Value: *loom.NewBigUInt(token3)},
			TokenAmount:   &types.BigUInt{Value: *loom.NewBigUInt(zeroAmount)},
			Recipient:     ts.ethAddr3.MarshalPB(),
		},
	)
	require.Equal(ErrInvalidRequest, err)

	//Withdraw TRX with zero amount
	err = gwHelper.Contract.WithdrawToken(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr3)),
		&WithdrawTokenRequest{
			TokenContract: ethTokenAddr.MarshalPB(),
			TokenKind:     TokenKind_TRX,
			TokenID:       &types.BigUInt{Value: *loom.NewBigUInt(token3)},
			TokenAmount:   &types.BigUInt{Value: *loom.NewBigUInt(zeroAmount)},
			Recipient:     ts.ethAddr3.MarshalPB(),
		},
	)
	require.Equal(ErrInvalidRequest, err)

	//Withdraw TRC20 with zero amount
	err = gwHelper.Contract.WithdrawToken(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr3)),
		&WithdrawTokenRequest{
			TokenContract: ethTokenAddr.MarshalPB(),
			TokenKind:     TokenKind_TRC20,
			TokenID:       &types.BigUInt{Value: *loom.NewBigUInt(token3)},
			TokenAmount:   &types.BigUInt{Value: *loom.NewBigUInt(zeroAmount)},
			Recipient:     ts.ethAddr3.MarshalPB(),
		},
	)
	require.Equal(ErrInvalidRequest, err)
}

func (ts *GatewayTestSuite) TestReclaimTokensAfterIdentityMapping() {
	require := ts.Require()
	fakeCtx := plugin.CreateFakeContextWithEVM(ts.dAppAddr, loom.RootAddress("chain"))

	addressMapper, err := deployAddressMapperContract(fakeCtx)
	require.NoError(err)

	gwHelper, err := deployGatewayContract(fakeCtx, &InitRequest{
		Owner:   ts.dAppAddr2.MarshalPB(),
		Oracles: []*types.Address{ts.dAppAddr.MarshalPB()},
	}, EthereumGateway)
	require.NoError(err)

	// Deploy ERC721 Solidity contract to DAppChain EVM
	dappTokenAddr, err := deployTokenContract(fakeCtx, "SampleERC721Token", gwHelper.Address, ts.dAppAddr)
	require.NoError(err)
	require.NoError(gwHelper.AddContractMapping(fakeCtx, ethTokenAddr, dappTokenAddr))

	// Don't add the identity mapping between the depositor's Mainnet & DAppChain addresses...

	// Send tokens to Gateway Go contract
	// 7 TOKENS IN TOTAL
	tokensByBlock := [][]int64{
		[]int64{485, 437, 223},
		[]int64{643, 234},
		[]int64{968},
		[]int64{942},
	}
	deposits := genERC721Deposits(
		ethTokenAddr,
		ts.ethAddr,
		[]uint64{5, 9, 11, 13},
		tokensByBlock,
	)

	// None of the tokens will be transferred to their owner because the depositor didn't add an
	// identity mapping
	require.NoError(gwHelper.Contract.ProcessEventBatch(
		gwHelper.ContractCtx(fakeCtx),
		&ProcessEventBatchRequest{Events: deposits}),
	)

	// Since the tokens weren't transferred they shouldn't exist on the DAppChain yet
	erc721 := newERC721StaticContext(gwHelper.ContractCtx(fakeCtx), dappTokenAddr)
	tokenCount := 0
	for _, tokens := range tokensByBlock {
		for _, tokenID := range tokens {
			tokenCount++
			_, err := erc721.ownerOf(big.NewInt(tokenID))
			require.Error(err)
		}
	}
	unclaimedTokens, err := unclaimedTokensByOwner(gwHelper.ContractCtx(fakeCtx), ts.ethAddr)
	require.NoError(err)
	require.Equal(1, len(unclaimedTokens))
	require.Equal(tokenCount, len(unclaimedTokens[0].Amounts))
	depositors, err := unclaimedTokenDepositorsByContract(gwHelper.ContractCtx(fakeCtx), ethTokenAddr)
	require.NoError(err)
	require.Equal(1, len(depositors))

	// The depositor finally add an identity mapping...
	sig, err := address_mapper.SignIdentityMapping(ts.ethAddr, ts.dAppAddr, ts.ethKey, sigType)
	require.NoError(err)
	require.NoError(addressMapper.AddIdentityMapping(fakeCtx, ts.ethAddr, ts.dAppAddr, sig))

	// Check if the depositor has any unclaimed tokens
	resp, err := gwHelper.Contract.GetUnclaimedTokens(
		gwHelper.ContractCtx(fakeCtx), &GetUnclaimedTokensRequest{
			Owner: ts.ethAddr.MarshalPB(),
		},
	)
	require.NoError(err)
	tokens := resp.UnclaimedTokens
	require.Equal(loom.UnmarshalAddressPB(tokens[0].TokenContract), ethTokenAddr)
	require.Len(tokens, 1)
	require.Len(tokens[0].Amounts, 7) // 7 tokens total in tokensByBlock

	// and attempts to reclaim previously deposited tokens...
	require.NoError(gwHelper.Contract.ReclaimDepositorTokens(
		gwHelper.ContractCtx(fakeCtx),
		&ReclaimDepositorTokensRequest{},
	))

	for _, tokens := range tokensByBlock {
		for _, tokenID := range tokens {
			ownerAddr, err := erc721.ownerOf(big.NewInt(tokenID))
			require.NoError(err)
			require.Equal(ts.dAppAddr, ownerAddr)
		}
	}
	unclaimedTokens, err = unclaimedTokensByOwner(gwHelper.ContractCtx(fakeCtx), ts.ethAddr)
	require.NoError(err)
	require.Equal(0, len(unclaimedTokens))
	depositors, err = unclaimedTokenDepositorsByContract(gwHelper.ContractCtx(fakeCtx), ethTokenAddr)
	require.NoError(err)
	require.Equal(0, len(depositors))
}

func (ts *GatewayTestSuite) TestReclaimTokensAfterContractMapping() {
	require := ts.Require()
	fakeCtx := plugin.CreateFakeContextWithEVM(ts.dAppAddr, loom.RootAddress("chain"))

	addressMapper, err := deployAddressMapperContract(fakeCtx)
	require.NoError(err)

	gwHelper, err := deployGatewayContract(fakeCtx, &InitRequest{
		Owner:   ts.dAppAddr2.MarshalPB(),
		Oracles: []*types.Address{ts.dAppAddr.MarshalPB()},
	}, EthereumGateway)
	require.NoError(err)

	// Deploy token contracts to DAppChain EVM
	erc721Addr, err := deployTokenContract(fakeCtx, "SampleERC721Token", gwHelper.Address, ts.dAppAddr)
	require.NoError(err)
	erc20Addr, err := deployTokenContract(fakeCtx, "SampleERC20Token", gwHelper.Address, ts.dAppAddr)
	require.NoError(err)
	erc721xAddr, err := deployTokenContract(fakeCtx, "SampleERC721XToken", gwHelper.Address, ts.dAppAddr)
	require.NoError(err)

	// Don't add the contract mapping between the Mainnet & DAppChain contracts...

	aliceEthAddr := ts.ethAddr
	aliceDAppAddr := ts.dAppAddr
	bobEthAddr := ts.ethAddr2
	bobDAppAddr := ts.dAppAddr2

	sig, err := address_mapper.SignIdentityMapping(aliceEthAddr, aliceDAppAddr, ts.ethKey, sigType)
	require.NoError(err)
	require.NoError(addressMapper.AddIdentityMapping(fakeCtx, aliceEthAddr, aliceDAppAddr, sig))
	sig, err = address_mapper.SignIdentityMapping(bobEthAddr, bobDAppAddr, ts.ethKey2, sigType)
	require.NoError(err)
	require.NoError(addressMapper.AddIdentityMapping(
		fakeCtx.WithSender(bobDAppAddr),
		bobEthAddr, bobDAppAddr, sig,
	))

	erc721tokensByBlock := [][]int64{
		[]int64{485, 437, 223},
		[]int64{643, 234},
		[]int64{968},
		[]int64{942},
	}
	erc721deposits := genERC721Deposits(
		ethTokenAddr,
		aliceEthAddr,
		[]uint64{5, 9, 11, 13},
		erc721tokensByBlock,
	)
	erc721tokensByBlock2 := [][]int64{
		[]int64{1485, 1437, 1223},
		[]int64{2643, 2234},
		[]int64{3968},
	}
	erc721deposits2 := genERC721Deposits(
		ethTokenAddr,
		bobEthAddr,
		[]uint64{15, 19, 23},
		erc721tokensByBlock2,
	)
	erc20amountsByBlock := []int64{150, 238, 580}
	erc20deposits := genERC20Deposits(
		ethTokenAddr2,
		aliceEthAddr,
		[]uint64{24, 27, 29},
		erc20amountsByBlock,
	)
	erc20amountsByBlock2 := []int64{389}
	erc20deposits2 := genERC20Deposits(
		ethTokenAddr2,
		bobEthAddr,
		[]uint64{49},
		erc20amountsByBlock2,
	)
	erc721xTokensByBlock := [][]*erc721xToken{
		[]*erc721xToken{
			&erc721xToken{ID: 345, Amount: 20},
			&erc721xToken{ID: 37, Amount: 10},
			&erc721xToken{ID: 40, Amount: 4},
			&erc721xToken{ID: 0, Amount: 15},
		},
		[]*erc721xToken{
			&erc721xToken{ID: 40, Amount: 2},
			&erc721xToken{ID: 345, Amount: 5},
		},
		[]*erc721xToken{
			&erc721xToken{ID: 37, Amount: 3},
			&erc721xToken{ID: 78, Amount: 300},
			&erc721xToken{ID: 0, Amount: 15},
		},
	}
	erc721xDeposits, erc721xTotals := genERC721XDeposits(
		ethTokenAddr3,
		aliceEthAddr,
		[]uint64{54, 58, 61},
		erc721xTokensByBlock,
	)

	// Send tokens to Gateway Go contract...
	// None of the tokens will be transferred to their owners because the contract mapping
	// doesn't exist.
	require.NoError(gwHelper.Contract.ProcessEventBatch(
		gwHelper.ContractCtx(fakeCtx),
		&ProcessEventBatchRequest{Events: erc721deposits}),
	)
	require.NoError(gwHelper.Contract.ProcessEventBatch(
		gwHelper.ContractCtx(fakeCtx),
		&ProcessEventBatchRequest{Events: erc721deposits2}),
	)
	require.NoError(gwHelper.Contract.ProcessEventBatch(
		gwHelper.ContractCtx(fakeCtx),
		&ProcessEventBatchRequest{Events: erc20deposits}),
	)
	require.NoError(gwHelper.Contract.ProcessEventBatch(
		gwHelper.ContractCtx(fakeCtx),
		&ProcessEventBatchRequest{Events: erc20deposits2}),
	)
	require.NoError(gwHelper.Contract.ProcessEventBatch(
		gwHelper.ContractCtx(fakeCtx),
		&ProcessEventBatchRequest{Events: erc721xDeposits}),
	)

	// Since the tokens weren't transferred they shouldn't exist on the DAppChain yet
	erc721 := newERC721StaticContext(gwHelper.ContractCtx(fakeCtx), erc721Addr)
	for _, tokens := range erc721tokensByBlock {
		for _, tokenID := range tokens {
			_, err := erc721.ownerOf(big.NewInt(tokenID))
			require.Error(err)
		}
	}
	for _, tokens := range erc721tokensByBlock2 {
		for _, tokenID := range tokens {
			_, err := erc721.ownerOf(big.NewInt(tokenID))
			require.Error(err)
		}
	}

	erc20 := newERC20StaticContext(gwHelper.ContractCtx(fakeCtx), erc20Addr)
	bal, err := erc20.balanceOf(aliceDAppAddr)
	require.NoError(err)
	require.Equal(int64(0), bal.Int64())
	bal, err = erc20.balanceOf(bobDAppAddr)
	require.NoError(err)
	require.Equal(int64(0), bal.Int64())

	erc721x := newERC721XStaticContext(gwHelper.ContractCtx(fakeCtx), erc721xAddr)
	for _, token := range erc721xTotals {
		bal, err := erc721x.balanceOf(aliceDAppAddr, big.NewInt(token.ID))
		require.NoError(err)
		require.Equal(int64(0), bal.Int64())
	}

	unclaimedTokens, err := unclaimedTokensByOwner(gwHelper.ContractCtx(fakeCtx), aliceEthAddr)
	require.NoError(err)
	require.Equal(3, len(unclaimedTokens))
	unclaimedTokens, err = unclaimedTokensByOwner(gwHelper.ContractCtx(fakeCtx), bobEthAddr)
	require.NoError(err)
	require.Equal(2, len(unclaimedTokens))
	depositors, err := unclaimedTokenDepositorsByContract(gwHelper.ContractCtx(fakeCtx), ethTokenAddr)
	require.NoError(err)
	require.Equal(2, len(depositors))
	depositors, err = unclaimedTokenDepositorsByContract(gwHelper.ContractCtx(fakeCtx), ethTokenAddr2)
	require.NoError(err)
	require.Equal(2, len(depositors))
	depositors, err = unclaimedTokenDepositorsByContract(gwHelper.ContractCtx(fakeCtx), ethTokenAddr3)
	require.NoError(err)
	require.Equal(1, len(depositors))

	// The contract creator finally adds contract mappings...
	require.NoError(gwHelper.AddContractMapping(fakeCtx, ethTokenAddr, erc721Addr))
	require.NoError(gwHelper.AddContractMapping(fakeCtx, ethTokenAddr2, erc20Addr))
	require.NoError(gwHelper.AddContractMapping(fakeCtx, ethTokenAddr3, erc721xAddr))

	// Only the token contract creator should be able to reclaim tokens per contract
	require.Error(gwHelper.Contract.ReclaimContractTokens(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr3)),
		&ReclaimContractTokensRequest{
			TokenContract: ethTokenAddr.MarshalPB(),
		},
	))
	require.NoError(gwHelper.Contract.ReclaimContractTokens(
		gwHelper.ContractCtx(fakeCtx),
		&ReclaimContractTokensRequest{
			TokenContract: ethTokenAddr.MarshalPB(),
		},
	))
	require.NoError(gwHelper.Contract.ReclaimContractTokens(
		gwHelper.ContractCtx(fakeCtx),
		&ReclaimContractTokensRequest{
			TokenContract: ethTokenAddr2.MarshalPB(),
		},
	))
	require.NoError(gwHelper.Contract.ReclaimContractTokens(
		gwHelper.ContractCtx(fakeCtx),
		&ReclaimContractTokensRequest{
			TokenContract: ethTokenAddr3.MarshalPB(),
		},
	))

	for _, tokens := range erc721tokensByBlock {
		for _, tokenID := range tokens {
			ownerAddr, err := erc721.ownerOf(big.NewInt(tokenID))
			require.NoError(err)
			require.Equal(aliceDAppAddr, ownerAddr)
		}
	}
	for _, tokens := range erc721tokensByBlock2 {
		for _, tokenID := range tokens {
			ownerAddr, err := erc721.ownerOf(big.NewInt(tokenID))
			require.NoError(err)
			require.Equal(bobDAppAddr, ownerAddr)
		}
	}

	expectedBal := int64(0)
	for _, amount := range erc20amountsByBlock {
		expectedBal = expectedBal + amount
	}
	bal, err = erc20.balanceOf(aliceDAppAddr)
	require.NoError(err)
	require.Equal(expectedBal, bal.Int64())

	expectedBal = 0
	for _, amount := range erc20amountsByBlock2 {
		expectedBal = expectedBal + amount
	}
	bal, err = erc20.balanceOf(bobDAppAddr)
	require.NoError(err)
	require.Equal(expectedBal, bal.Int64())

	for _, token := range erc721xTotals {
		bal, err := erc721x.balanceOf(aliceDAppAddr, big.NewInt(token.ID))
		require.NoError(err)
		require.Equal(token.Amount, bal.Int64(), "wrong balance for token %d", token.ID)
	}

	// Check all tokens have been claimed...
	unclaimedTokens, err = unclaimedTokensByOwner(gwHelper.ContractCtx(fakeCtx), aliceEthAddr)
	require.NoError(err)
	require.Equal(0, len(unclaimedTokens))
	unclaimedTokens, err = unclaimedTokensByOwner(gwHelper.ContractCtx(fakeCtx), bobEthAddr)
	require.NoError(err)
	require.Equal(0, len(unclaimedTokens))

	depositors, err = unclaimedTokenDepositorsByContract(gwHelper.ContractCtx(fakeCtx), ethTokenAddr)
	require.NoError(err)
	require.Equal(0, len(depositors))
	depositors, err = unclaimedTokenDepositorsByContract(gwHelper.ContractCtx(fakeCtx), ethTokenAddr2)
	require.NoError(err)
	require.Equal(0, len(depositors))
	depositors, err = unclaimedTokenDepositorsByContract(gwHelper.ContractCtx(fakeCtx), ethTokenAddr3)
	require.NoError(err)
	require.Equal(0, len(depositors))
}

func (ts *GatewayTestSuite) TestGetUnclaimedContractTokens() {
	require := ts.Require()
	fakeCtx := plugin.CreateFakeContextWithEVM(ts.dAppAddr, loom.RootAddress("chain"))

	addressMapper, err := deployAddressMapperContract(fakeCtx)
	require.NoError(err)

	gwHelper, err := deployGatewayContract(fakeCtx, &InitRequest{
		Owner:   ts.dAppAddr2.MarshalPB(),
		Oracles: []*types.Address{ts.dAppAddr.MarshalPB()},
	}, EthereumGateway)
	require.NoError(err)

	LoomCoinGwHelper, err := deployGatewayContract(fakeCtx, &InitRequest{
		Owner:   ts.dAppAddr2.MarshalPB(),
		Oracles: []*types.Address{ts.dAppAddr.MarshalPB()},
	}, LoomCoinGateway)
	require.NoError(err)

	// Deploy token contracts to DAppChain EVM
	erc721Addr, err := deployTokenContract(fakeCtx, "SampleERC721Token", gwHelper.Address, ts.dAppAddr)
	require.NoError(err)
	erc20Addr, err := deployTokenContract(fakeCtx, "SampleERC20Token", gwHelper.Address, ts.dAppAddr)
	require.NoError(err)
	erc721xAddr, err := deployTokenContract(fakeCtx, "SampleERC721XToken", gwHelper.Address, ts.dAppAddr)
	require.NoError(err)
	loomAddr, err := deployLoomCoinContract(fakeCtx)
	require.NoError(err)
	// Don't add the contract mapping between the Mainnet & DAppChain contracts...

	aliceEthAddr := ts.ethAddr
	aliceDAppAddr := ts.dAppAddr
	bobEthAddr := ts.ethAddr2
	bobDAppAddr := ts.dAppAddr2
	carolEthAddr := ts.ethAddr3
	carolDAppAddr := ts.dAppAddr3
	charlieEthAddr := ts.ethAddr4
	charlieDAppAddr := ts.dAppAddr4

	sig, err := address_mapper.SignIdentityMapping(aliceEthAddr, aliceDAppAddr, ts.ethKey, sigType)
	require.NoError(err)
	require.NoError(addressMapper.AddIdentityMapping(fakeCtx, aliceEthAddr, aliceDAppAddr, sig))
	sig, err = address_mapper.SignIdentityMapping(bobEthAddr, bobDAppAddr, ts.ethKey2, sigType)
	require.NoError(err)
	require.NoError(addressMapper.AddIdentityMapping(
		fakeCtx.WithSender(bobDAppAddr),
		bobEthAddr, bobDAppAddr, sig,
	))

	erc721tokensByBlock := [][]int64{
		[]int64{485, 437, 223},
		[]int64{643, 234},
		[]int64{968},
		[]int64{942},
	}
	erc721deposits := genERC721Deposits(
		ethTokenAddr,
		aliceEthAddr,
		[]uint64{5, 9, 11, 13},
		erc721tokensByBlock,
	)
	erc721tokensByBlock2 := [][]int64{
		[]int64{1485, 1437, 1223},
		[]int64{2643, 2234},
		[]int64{3968},
	}
	erc721deposits2 := genERC721Deposits(
		ethTokenAddr,
		bobEthAddr,
		[]uint64{15, 19, 23},
		erc721tokensByBlock2,
	)
	erc20amountsByBlock := []int64{150, 238, 580}
	erc20deposits := genERC20Deposits(
		ethTokenAddr2,
		aliceEthAddr,
		[]uint64{24, 27, 29},
		erc20amountsByBlock,
	)
	erc20amountsByBlock2 := []int64{389}
	erc20deposits2 := genERC20Deposits(
		ethTokenAddr2,
		bobEthAddr,
		[]uint64{49},
		erc20amountsByBlock2,
	)
	erc721xTokensByBlock := [][]*erc721xToken{
		[]*erc721xToken{
			&erc721xToken{ID: 345, Amount: 20},
			&erc721xToken{ID: 37, Amount: 10},
			&erc721xToken{ID: 40, Amount: 4},
			&erc721xToken{ID: 0, Amount: 15},
		},
		[]*erc721xToken{
			&erc721xToken{ID: 40, Amount: 2},
			&erc721xToken{ID: 345, Amount: 5},
		},
		[]*erc721xToken{
			&erc721xToken{ID: 37, Amount: 3},
			&erc721xToken{ID: 78, Amount: 300},
			&erc721xToken{ID: 0, Amount: 15},
		},
	}
	erc721xDeposits, erc721xTotals := genERC721XDeposits(
		ethTokenAddr3,
		aliceEthAddr,
		[]uint64{54, 58, 61},
		erc721xTokensByBlock,
	)

	loomamountsByBlock := []int64{160, 239, 581}
	loomdeposits := genLoomCoinDeposits(
		loomAddr.Address,
		carolEthAddr,
		[]uint64{71, 73, 75},
		loomamountsByBlock,
	)

	loomamountsByBlock2 := []int64{390}
	loomdeposits2 := genLoomCoinDeposits(
		loomAddr.Address,
		charlieEthAddr,
		[]uint64{79},
		loomamountsByBlock2,
	)

	// Send tokens to Gateway Go contract...
	// None of the tokens will be transferred to their owners because the contract mapping
	// doesn't exist.
	// Loom Tokens will not be transferred to their owners as identity mapping does not exist, contract mapping does not apply here
	require.NoError(gwHelper.Contract.ProcessEventBatch(
		gwHelper.ContractCtx(fakeCtx),
		&ProcessEventBatchRequest{Events: erc721deposits}),
	)
	require.NoError(gwHelper.Contract.ProcessEventBatch(
		gwHelper.ContractCtx(fakeCtx),
		&ProcessEventBatchRequest{Events: erc721deposits2}),
	)
	require.NoError(gwHelper.Contract.ProcessEventBatch(
		gwHelper.ContractCtx(fakeCtx),
		&ProcessEventBatchRequest{Events: erc20deposits}),
	)
	require.NoError(gwHelper.Contract.ProcessEventBatch(
		gwHelper.ContractCtx(fakeCtx),
		&ProcessEventBatchRequest{Events: erc20deposits2}),
	)
	require.NoError(gwHelper.Contract.ProcessEventBatch(
		gwHelper.ContractCtx(fakeCtx),
		&ProcessEventBatchRequest{Events: erc721xDeposits}),
	)
	require.NoError(LoomCoinGwHelper.Contract.ProcessEventBatch(
		LoomCoinGwHelper.ContractCtx(fakeCtx),
		&ProcessEventBatchRequest{Events: loomdeposits}),
	)
	require.NoError(LoomCoinGwHelper.Contract.ProcessEventBatch(
		LoomCoinGwHelper.ContractCtx(fakeCtx),
		&ProcessEventBatchRequest{Events: loomdeposits2}),
	)

	// Since the tokens weren't transferred they shouldn't exist on the DAppChain yet
	erc721 := newERC721StaticContext(gwHelper.ContractCtx(fakeCtx), erc721Addr)
	for _, tokens := range erc721tokensByBlock {
		for _, tokenID := range tokens {
			_, err := erc721.ownerOf(big.NewInt(tokenID))
			require.Error(err)
		}
	}
	for _, tokens := range erc721tokensByBlock2 {
		for _, tokenID := range tokens {
			_, err := erc721.ownerOf(big.NewInt(tokenID))
			require.Error(err)
		}
	}

	erc20 := newERC20StaticContext(gwHelper.ContractCtx(fakeCtx), erc20Addr)
	bal, err := erc20.balanceOf(aliceDAppAddr)
	require.NoError(err)
	require.Equal(int64(0), bal.Int64())
	bal, err = erc20.balanceOf(bobDAppAddr)
	require.NoError(err)
	require.Equal(int64(0), bal.Int64())

	loomcoin := newcoinStaticContext(LoomCoinGwHelper.ContractCtx(fakeCtx))
	bal, err = loomcoin.balanceOf(carolDAppAddr)
	require.NoError(err)
	require.Equal(int64(0), bal.Int64())
	bal, err = loomcoin.balanceOf(charlieDAppAddr)
	require.NoError(err)
	require.Equal(int64(0), bal.Int64())

	erc721x := newERC721XStaticContext(gwHelper.ContractCtx(fakeCtx), erc721xAddr)
	for _, token := range erc721xTotals {
		bal, err := erc721x.balanceOf(aliceDAppAddr, big.NewInt(token.ID))
		require.NoError(err)
		require.Equal(int64(0), bal.Int64())
	}
	resp, err := gwHelper.Contract.GetUnclaimedContractTokens(gwHelper.ContractCtx(fakeCtx), &GetUnclaimedContractTokensRequest{TokenAddress: ethTokenAddr.MarshalPB()})
	require.NoError(err)
	require.Equal(loom.NewBigUIntFromInt(13), &resp.UnclaimedAmount.Value)
	resp, err = gwHelper.Contract.GetUnclaimedContractTokens(gwHelper.ContractCtx(fakeCtx), &GetUnclaimedContractTokensRequest{TokenAddress: ethTokenAddr2.MarshalPB()})
	require.NoError(err)
	require.Equal(loom.NewBigUIntFromInt(1357), &resp.UnclaimedAmount.Value)
	resp, err = gwHelper.Contract.GetUnclaimedContractTokens(gwHelper.ContractCtx(fakeCtx), &GetUnclaimedContractTokensRequest{TokenAddress: ethTokenAddr3.MarshalPB()})
	require.NoError(err)
	require.Equal(loom.NewBigUIntFromInt(374), &resp.UnclaimedAmount.Value)
	resp, err = LoomCoinGwHelper.Contract.GetUnclaimedContractTokens(LoomCoinGwHelper.ContractCtx(fakeCtx), &GetUnclaimedContractTokensRequest{TokenAddress: loomAddr.Address.MarshalPB()})
	require.NoError(err)
	require.Equal(loom.NewBigUIntFromInt(1370), &resp.UnclaimedAmount.Value)
}

func (ts *GatewayTestSuite) TestGetOracles() {
	require := ts.Require()
	fakeCtx := plugin.CreateFakeContextWithEVM(ts.dAppAddr, loom.RootAddress("chain"))

	ownerAddr := ts.dAppAddr2
	oracleAddr := ts.dAppAddr
	oracle2Addr := ts.dAppAddr3

	gwHelper, err := deployGatewayContract(fakeCtx, &InitRequest{
		Owner:   ownerAddr.MarshalPB(),
		Oracles: []*types.Address{oracleAddr.MarshalPB()},
	}, EthereumGateway)
	require.NoError(err)

	resp, err := gwHelper.Contract.GetOracles(gwHelper.ContractCtx(fakeCtx), &GetOraclesRequest{})
	require.NoError(err)
	require.Len(resp.Oracles, 1)
	require.Equal(oracleAddr, loom.UnmarshalAddressPB(resp.Oracles[0].Address))

	require.NoError(gwHelper.Contract.AddOracle(
		gwHelper.ContractCtx(fakeCtx.WithSender(ownerAddr)),
		&AddOracleRequest{
			Oracle: oracle2Addr.MarshalPB(),
		},
	))

	resp, err = gwHelper.Contract.GetOracles(gwHelper.ContractCtx(fakeCtx), &GetOraclesRequest{})
	require.NoError(err)
	require.Len(resp.Oracles, 2)
	addr1 := loom.UnmarshalAddressPB(resp.Oracles[0].Address)
	addr2 := loom.UnmarshalAddressPB(resp.Oracles[1].Address)
	if addr1.Compare(oracleAddr) == 0 {
		require.Equal(oracle2Addr, addr2)
	} else if addr2.Compare(oracleAddr) == 0 {
		require.Equal(oracle2Addr, addr1)
	} else {
		require.Fail("unexpected set of oracles")
	}

	require.NoError(gwHelper.Contract.RemoveOracle(
		gwHelper.ContractCtx(fakeCtx.WithSender(ownerAddr)),
		&RemoveOracleRequest{
			Oracle: oracleAddr.MarshalPB(),
		},
	))

	resp, err = gwHelper.Contract.GetOracles(gwHelper.ContractCtx(fakeCtx), &GetOraclesRequest{})
	require.NoError(err)
	require.Len(resp.Oracles, 1)
	require.Equal(oracle2Addr, loom.UnmarshalAddressPB(resp.Oracles[0].Address))
}

func (ts *GatewayTestSuite) TestAddRemoveTokenWithdrawer() {
	require := ts.Require()
	ownerAddr := ts.dAppAddr
	oracleAddr := ts.dAppAddr2
	withdrawerAddr := ts.dAppAddr3
	fakeCtx := plugin.CreateFakeContextWithEVM(ownerAddr, loom.RootAddress("chain"))

	gwContract := &Gateway{}
	require.NoError(gwContract.Init(
		contract.WrapPluginContext(fakeCtx),
		&InitRequest{
			Owner:   ownerAddr.MarshalPB(),
			Oracles: []*types.Address{oracleAddr.MarshalPB()},
		},
	))
	ctx := contract.WrapPluginContext(fakeCtx)

	s, err := loadState(ctx)
	require.NoError(err)

	require.NoError(addTokenWithdrawer(ctx, s, withdrawerAddr))
	require.Len(s.TokenWithdrawers, 1)
	require.Equal(loom.UnmarshalAddressPB(s.TokenWithdrawers[0]), withdrawerAddr)

	require.NoError(removeTokenWithdrawer(ctx, s, withdrawerAddr))
	require.NoError(err)
	require.Len(s.TokenWithdrawers, 0)
}

func (ts *GatewayTestSuite) TestAddNewContractMapping() {
	require := ts.Require()

	ownerAddr := ts.dAppAddr
	oracleAddr := ts.dAppAddr2
	userAddr := ts.dAppAddr3
	foreignCreatorAddr := ts.ethAddr
	ethTokenAddr := loom.MustParseAddress("eth:0xb16a379ec18d4093666f8f38b11a3071c920207d")
	ethTokenAddr2 := loom.MustParseAddress("eth:0xfa4c7920accfd66b86f5fd0e69682a79f762d49e")

	fakeCtx := plugin.CreateFakeContextWithEVM(userAddr, loom.RootAddress("chain"))

	gwHelper, err := deployGatewayContract(fakeCtx, &InitRequest{
		Owner:   ownerAddr.MarshalPB(),
		Oracles: []*types.Address{oracleAddr.MarshalPB()},
	}, EthereumGateway)
	require.NoError(err)

	// Deploy ERC721 Solidity contract to DAppChain EVM
	dappTokenAddr, err := deployTokenContract(fakeCtx, "SampleERC721Token", gwHelper.Address, userAddr)
	require.NoError(err)

	dappTokenAddr2, err := deployTokenContract(fakeCtx, "SampleERC721Token", gwHelper.Address, userAddr)
	require.NoError(err)
	require.NotEqual(dappTokenAddr, dappTokenAddr2)

	hash := ssha.SoliditySHA3(
		ssha.Address(common.BytesToAddress(ethTokenAddr.Local)),
		ssha.Address(common.BytesToAddress(dappTokenAddr.Local)),
	)

	sig, err := evmcompat.GenerateTypedSig(hash, ts.ethKey, evmcompat.SignatureType_EIP712)
	require.NoError(err)

	// When a user adds a contract mapping a pending contract mapping should be created
	require.NoError(gwHelper.Contract.AddContractMapping(
		gwHelper.ContractCtx(fakeCtx.WithSender(userAddr)),
		&AddContractMappingRequest{
			ForeignContract:           ethTokenAddr.MarshalPB(),
			LocalContract:             dappTokenAddr.MarshalPB(),
			ForeignContractCreatorSig: sig,
			ForeignContractTxHash:     []byte("0xdeadbeef"),
		},
	))

	// Verify pending mappings can't be overwritten
	err = gwHelper.Contract.AddContractMapping(
		gwHelper.ContractCtx(fakeCtx.WithSender(userAddr)),
		&AddContractMappingRequest{
			ForeignContract:           ethTokenAddr.MarshalPB(),
			LocalContract:             dappTokenAddr.MarshalPB(),
			ForeignContractCreatorSig: sig,
			ForeignContractTxHash:     []byte("0xdeadbeef"),
		},
	)
	require.Equal(ErrContractMappingExists, err, "AddContractMapping should not allow duplicate mapping")

	hash = ssha.SoliditySHA3(
		ssha.Address(common.BytesToAddress(ethTokenAddr.Local)),
		ssha.Address(common.BytesToAddress(dappTokenAddr2.Local)),
	)

	sig2, err := evmcompat.GenerateTypedSig(hash, ts.ethKey, evmcompat.SignatureType_EIP712)
	require.NoError(err)

	err = gwHelper.Contract.AddContractMapping(
		gwHelper.ContractCtx(fakeCtx.WithSender(userAddr)),
		&AddContractMappingRequest{
			ForeignContract:           ethTokenAddr.MarshalPB(),
			LocalContract:             dappTokenAddr2.MarshalPB(),
			ForeignContractCreatorSig: sig2,
			ForeignContractTxHash:     []byte("0xdeadbeef"),
		},
	)
	require.Equal(ErrContractMappingExists, err, "AddContractMapping should not allow re-mapping")

	hash = ssha.SoliditySHA3(
		ssha.Address(common.BytesToAddress(ethTokenAddr2.Local)),
		ssha.Address(common.BytesToAddress(dappTokenAddr.Local)),
	)

	sig3, err := evmcompat.GenerateTypedSig(hash, ts.ethKey, evmcompat.SignatureType_EIP712)
	require.NoError(err)

	err = gwHelper.Contract.AddContractMapping(
		gwHelper.ContractCtx(fakeCtx.WithSender(userAddr)),
		&AddContractMappingRequest{
			ForeignContract:           ethTokenAddr2.MarshalPB(),
			LocalContract:             dappTokenAddr.MarshalPB(),
			ForeignContractCreatorSig: sig3,
			ForeignContractTxHash:     []byte("0xdeadbeef"),
		},
	)
	require.Equal(ErrContractMappingExists, err, "AddContractMapping should not allow re-mapping")

	// Oracle retrieves the tx hash from the pending contract mapping
	unverifiedCreatorsResp, err := gwHelper.Contract.UnverifiedContractCreators(
		gwHelper.ContractCtx(fakeCtx.WithSender(oracleAddr)),
		&UnverifiedContractCreatorsRequest{})
	require.NoError(err)
	require.Len(unverifiedCreatorsResp.Creators, 1)

	// Oracle extracts the contract and creator address from the tx matching the hash, and sends
	// them back to the contract
	require.NoError(gwHelper.Contract.VerifyContractCreators(
		gwHelper.ContractCtx(fakeCtx.WithSender(oracleAddr)),
		&VerifyContractCreatorsRequest{
			Creators: []*VerifiedContractCreator{
				&VerifiedContractCreator{
					ContractMappingID: unverifiedCreatorsResp.Creators[0].ContractMappingID,
					Creator:           foreignCreatorAddr.MarshalPB(),
					Contract:          ethTokenAddr.MarshalPB(),
				},
			},
		}))

	// The contract and creator address provided by the Oracle should match the pending contract
	// mapping so the Gateway contract should've finalized the bi-directional contract mapping...
	resolvedAddr, err := resolveToLocalContractAddr(
		gwHelper.ContractCtx(fakeCtx.WithSender(gwHelper.Address)),
		ethTokenAddr)
	require.NoError(err)
	require.True(resolvedAddr.Compare(dappTokenAddr) == 0)

	resolvedAddr, err = resolveToForeignContractAddr(
		gwHelper.ContractCtx(fakeCtx.WithSender(gwHelper.Address)),
		dappTokenAddr)
	require.NoError(err)
	require.True(resolvedAddr.Compare(ethTokenAddr) == 0)

	// Verify confirmed mappings can't be overwritten
	err = gwHelper.Contract.AddContractMapping(
		gwHelper.ContractCtx(fakeCtx.WithSender(userAddr)),
		&AddContractMappingRequest{
			ForeignContract:           ethTokenAddr.MarshalPB(),
			LocalContract:             dappTokenAddr.MarshalPB(),
			ForeignContractCreatorSig: sig,
			ForeignContractTxHash:     []byte("0xdeadbeef"),
		},
	)
	require.Equal(ErrContractMappingExists, err, "AddContractMapping should not allow duplicate mapping")

	err = gwHelper.Contract.AddContractMapping(
		gwHelper.ContractCtx(fakeCtx.WithSender(userAddr)),
		&AddContractMappingRequest{
			ForeignContract:           ethTokenAddr.MarshalPB(),
			LocalContract:             dappTokenAddr2.MarshalPB(),
			ForeignContractCreatorSig: sig2,
			ForeignContractTxHash:     []byte("0xdeadbeef"),
		},
	)
	require.Equal(ErrContractMappingExists, err, "AddContractMapping should not allow re-mapping")

	err = gwHelper.Contract.AddContractMapping(
		gwHelper.ContractCtx(fakeCtx.WithSender(userAddr)),
		&AddContractMappingRequest{
			ForeignContract:           ethTokenAddr2.MarshalPB(),
			LocalContract:             dappTokenAddr.MarshalPB(),
			ForeignContractCreatorSig: sig3,
			ForeignContractTxHash:     []byte("0xdeadbeef"),
		},
	)
	require.Equal(ErrContractMappingExists, err, "AddContractMapping should not allow re-mapping")
}

func (ts *GatewayTestSuite) TestAddNewAuthorizedContractMapping() {
	require := ts.Require()

	ownerAddr := ts.dAppAddr
	oracleAddr := ts.dAppAddr2
	userAddr := ts.dAppAddr3
	ethTokenAddr := loom.MustParseAddress("eth:0xb16a379ec18d4093666f8f38b11a3071c920207d")
	ethTokenAddr2 := loom.MustParseAddress("eth:0xfa4c7920accfd66b86f5fd0e69682a79f762d49e")

	fakeCtx := plugin.CreateFakeContextWithEVM(userAddr, loom.RootAddress("chain"))

	gwHelper, err := deployGatewayContract(fakeCtx, &InitRequest{
		Owner:   ownerAddr.MarshalPB(),
		Oracles: []*types.Address{oracleAddr.MarshalPB()},
	}, EthereumGateway)
	require.NoError(err)

	// Deploy ERC721 Solidity contract to DAppChain EVM
	dappTokenAddr, err := deployTokenContract(fakeCtx, "SampleERC721Token", gwHelper.Address, userAddr)
	require.NoError(err)

	dappTokenAddr2, err := deployTokenContract(fakeCtx, "SampleERC721Token", gwHelper.Address, userAddr)
	require.NoError(err)
	require.NotEqual(dappTokenAddr, dappTokenAddr2)

	// Only gateway owner should be able to add authorized contract mapping, so this should fail
	// because the caller isn't the owner
	err = gwHelper.Contract.AddAuthorizedContractMapping(
		gwHelper.ContractCtx(fakeCtx.WithSender(userAddr)),
		&AddContractMappingRequest{
			ForeignContract: ethTokenAddr.MarshalPB(),
			LocalContract:   dappTokenAddr.MarshalPB(),
		},
	)

	require.Equal(ErrNotAuthorized, err, "Only Gateway Owner can add authorized contract mapping")

	// Should work now that the gateway owner makes the call
	require.NoError(gwHelper.Contract.AddAuthorizedContractMapping(
		gwHelper.ContractCtx(fakeCtx.WithSender(ownerAddr)),
		&AddContractMappingRequest{
			ForeignContract: ethTokenAddr.MarshalPB(),
			LocalContract:   dappTokenAddr.MarshalPB(),
		},
	))

	// Shouldn't be possible to overwrite existing contract mapping
	err = gwHelper.Contract.AddAuthorizedContractMapping(
		gwHelper.ContractCtx(fakeCtx.WithSender(ownerAddr)),
		&AddContractMappingRequest{
			ForeignContract: ethTokenAddr.MarshalPB(),
			LocalContract:   dappTokenAddr.MarshalPB(),
		},
	)
	require.Equal(ErrContractMappingExists, err, "Duplicate contract mapping shouldn't be allowed")

	// Shouldn't be possible to change existing contract mapping
	err = gwHelper.Contract.AddAuthorizedContractMapping(
		gwHelper.ContractCtx(fakeCtx.WithSender(ownerAddr)),
		&AddContractMappingRequest{
			ForeignContract: ethTokenAddr.MarshalPB(),
			LocalContract:   dappTokenAddr2.MarshalPB(),
		},
	)
	require.Equal(ErrContractMappingExists, err, "Contract re-mapping shouldn't be allowed")

	err = gwHelper.Contract.AddAuthorizedContractMapping(
		gwHelper.ContractCtx(fakeCtx.WithSender(ownerAddr)),
		&AddContractMappingRequest{
			ForeignContract: ethTokenAddr2.MarshalPB(),
			LocalContract:   dappTokenAddr.MarshalPB(),
		},
	)
	require.Equal(ErrContractMappingExists, err, "Contract re-mapping shouldn't be allowed")
}

func (ts *GatewayTestSuite) TestFetchContractMapping() {
	require := ts.Require()

	ownerAddr := ts.dAppAddr
	oracleAddr := ts.dAppAddr2
	userAddr := ts.dAppAddr3
	foreignCreatorAddr := ts.ethAddr
	ethTokenAddr := loom.MustParseAddress("eth:0xb16a379ec18d4093666f8f38b11a3071c920207d")
	fakeCtx := plugin.CreateFakeContextWithEVM(userAddr, loom.RootAddress("chain"))

	gwHelper, err := deployGatewayContract(fakeCtx, &InitRequest{
		Owner:   ownerAddr.MarshalPB(),
		Oracles: []*types.Address{oracleAddr.MarshalPB()},
	}, EthereumGateway)
	require.NoError(err)

	// Deploy ERC721 Solidity contract to DAppChain EVM
	dappTokenAddr, err := deployTokenContract(fakeCtx, "SampleERC721Token", gwHelper.Address, userAddr)
	require.NoError(err)

	hash := ssha.SoliditySHA3(
		ssha.Address(common.BytesToAddress(ethTokenAddr.Local)),
		ssha.Address(common.BytesToAddress(dappTokenAddr.Local)),
	)

	sig, err := evmcompat.GenerateTypedSig(hash, ts.ethKey, evmcompat.SignatureType_EIP712)
	require.NoError(err)

	// When a user adds a contract mapping a pending contract mapping should be created
	require.NoError(gwHelper.Contract.AddContractMapping(
		gwHelper.ContractCtx(fakeCtx.WithSender(userAddr)),
		&AddContractMappingRequest{
			ForeignContract:           ethTokenAddr.MarshalPB(),
			LocalContract:             dappTokenAddr.MarshalPB(),
			ForeignContractCreatorSig: sig,
			ForeignContractTxHash:     []byte("0xdeadbeef"),
		},
	))

	resp, err := gwHelper.Contract.ListContractMapping(
		gwHelper.ContractCtx(fakeCtx.WithSender(userAddr)),
		&ListContractMappingRequest{})
	//Creates 1 Pending mapping
	require.Equal(1, len(resp.PendingMappings))

	// Oracle retrieves the tx hash from the pending contract mapping
	unverifiedCreatorsResp, err := gwHelper.Contract.UnverifiedContractCreators(
		gwHelper.ContractCtx(fakeCtx.WithSender(oracleAddr)),
		&UnverifiedContractCreatorsRequest{})
	require.NoError(err)
	require.Len(unverifiedCreatorsResp.Creators, 1)

	// Oracle extracts the contract and creator address from the tx matching the hash, and sends
	// them back to the contract
	require.NoError(gwHelper.Contract.VerifyContractCreators(
		gwHelper.ContractCtx(fakeCtx.WithSender(oracleAddr)),
		&VerifyContractCreatorsRequest{
			Creators: []*VerifiedContractCreator{
				&VerifiedContractCreator{
					ContractMappingID: unverifiedCreatorsResp.Creators[0].ContractMappingID,
					Creator:           foreignCreatorAddr.MarshalPB(),
					Contract:          ethTokenAddr.MarshalPB(),
				},
			},
		}))

	resp1, err := gwHelper.Contract.ListContractMapping(
		gwHelper.ContractCtx(fakeCtx.WithSender(userAddr)),
		&ListContractMappingRequest{})

	require.Equal(0, len(resp1.PendingMappings))
	//Unique confirmed mappings are created
	require.Equal(1, len(resp1.ConfimedMappings))

	resp3, err := gwHelper.Contract.GetContractMapping(
		gwHelper.ContractCtx(fakeCtx.WithSender(userAddr)),
		&GetContractMappingRequest{From: ethTokenAddr.MarshalPB()})

	require.Equal(resp3.MappedAddress, dappTokenAddr.MarshalPB())
	require.Equal(resp3.IsPending, false)

}

// A little sanity check to verify TokenID == 0 doesn't get unmarshalled to TokenID == nil
func (ts *GatewayTestSuite) TestUnclaimedTokenMarshalling() {
	require := ts.Require()

	original := UnclaimedToken{
		TokenKind: TokenKind_ERC721X,
		Amounts: []*TokenAmount{
			&TokenAmount{
				TokenID:     &types.BigUInt{Value: *loom.NewBigUIntFromInt(0)},
				TokenAmount: &types.BigUInt{Value: *loom.NewBigUIntFromInt(1)},
			},
			&TokenAmount{
				TokenID:     &types.BigUInt{Value: *loom.NewBigUIntFromInt(0)},
				TokenAmount: &types.BigUInt{Value: *loom.NewBigUIntFromInt(0)},
			},
		},
	}
	bytes, err := proto.Marshal(&original)
	require.NoError(err)
	unmarshalled := &UnclaimedToken{}
	require.NoError(proto.Unmarshal(bytes, unmarshalled))

	require.Equal(original.Amounts[0].TokenID.Value, unmarshalled.Amounts[0].TokenID.Value)
	require.Equal(original.Amounts[1].TokenID.Value, unmarshalled.Amounts[1].TokenID.Value)
	require.Equal(original.Amounts[1].TokenAmount.Value, unmarshalled.Amounts[1].TokenAmount.Value)
}

func (ts *GatewayTestSuite) TestLoomCoinTG() {
	require := ts.Require()

	ownerAddr := ts.dAppAddr
	oracleAddr := ts.dAppAddr2
	userAddr := ts.dAppAddr3
	foreignCreatorAddr := ts.ethAddr

	ethTokenAddr := loom.MustParseAddress("eth:0xb16a379ec18d4093666f8f38b11a3071c920207d")

	fakeCtx := plugin.CreateFakeContextWithEVM(userAddr, loom.RootAddress("chain"))

	loomCoinGwHelper, err := deployGatewayContract(fakeCtx, &InitRequest{
		Owner:   ownerAddr.MarshalPB(),
		Oracles: []*types.Address{oracleAddr.MarshalPB()},
	}, LoomCoinGateway)
	require.NoError(err)

	require.EqualError(loomCoinGwHelper.Contract.WithdrawETH(loomCoinGwHelper.ContractCtx(fakeCtx.WithSender(userAddr)), &WithdrawETHRequest{
		Amount:         &types.BigUInt{Value: *loom.NewBigUIntFromInt(0)},
		MainnetGateway: foreignCreatorAddr.MarshalPB(),
	}), ErrInvalidRequest.Error(), "WithdrawEth shouldnt happen in loomcoin TG contract")

	require.EqualError(loomCoinGwHelper.Contract.ProcessEventBatch(loomCoinGwHelper.ContractCtx(fakeCtx.WithSender(oracleAddr)), &ProcessEventBatchRequest{
		Events: genERC721Deposits(ethTokenAddr, ts.ethAddr, []uint64{9, 10}, nil),
	}), ErrInvalidRequest.Error(), "ProcessEventBatch wont entertain events other than loomcoin in loomcoin TG contract")

	require.Nil(loomCoinGwHelper.Contract.ProcessEventBatch(loomCoinGwHelper.ContractCtx(fakeCtx.WithSender(oracleAddr)), &ProcessEventBatchRequest{
		Events: genLoomCoinDeposits(ethTokenAddr, ts.ethAddr, []uint64{9, 10}, []int64{10, 11}),
	}), "ProcessEventBatch should entertain events of loomcoin in loomcoin TG")

	gwHelper, err := deployGatewayContract(fakeCtx, &InitRequest{
		Owner:   ownerAddr.MarshalPB(),
		Oracles: []*types.Address{oracleAddr.MarshalPB()},
	}, EthereumGateway)

	require.Nil(gwHelper.Contract.ProcessEventBatch(gwHelper.ContractCtx(fakeCtx.WithSender(oracleAddr)), &ProcessEventBatchRequest{
		Events: genERC721Deposits(ethTokenAddr, ts.ethAddr, []uint64{9, 10}, nil),
	}), "ProcessEventBatch should entertain events other than loomcoin in TG")

	require.EqualError(gwHelper.Contract.ProcessEventBatch(gwHelper.ContractCtx(fakeCtx.WithSender(oracleAddr)), &ProcessEventBatchRequest{
		Events: genLoomCoinDeposits(ethTokenAddr, ts.ethAddr, []uint64{10, 11}, []int64{10, 11}),
	}), ErrInvalidRequest.Error(), "ProcessEventBatch wont entertain events of loomcoin in TG comtract")

}

func (ts *GatewayTestSuite) TestCheckSeenTxHash() {
	require := ts.Require()
	fakeCtx := plugin.CreateFakeContextWithEVM(ts.dAppAddr, loom.RootAddress("chain"))

	addressMapper, err := deployAddressMapperContract(fakeCtx)
	require.NoError(err)

	gwHelper, err := deployGatewayContract(fakeCtx, &InitRequest{
		Owner:   ts.dAppAddr2.MarshalPB(),
		Oracles: []*types.Address{ts.dAppAddr.MarshalPB()},
	}, EthereumGateway)
	require.NoError(err)

	// Deploy ERC721 Solidity contract to DAppChain EVM
	dappTokenAddr, err := deployTokenContract(fakeCtx, "SampleERC721Token", gwHelper.Address, ts.dAppAddr)
	require.NoError(err)

	require.NoError(gwHelper.AddContractMapping(fakeCtx, ethTokenAddr, dappTokenAddr))
	sig, err := address_mapper.SignIdentityMapping(ts.ethAddr, ts.dAppAddr, ts.ethKey, sigType)
	require.NoError(err)
	require.NoError(addressMapper.AddIdentityMapping(fakeCtx, ts.ethAddr, ts.dAppAddr, sig))

	txHash1 := []byte("txHash1")
	txHash2 := []byte("txHash2")
	txHash3 := []byte("txHash3")

	// Sanity check
	require.False(seenTxHashExist(gwHelper.ContractCtx(fakeCtx), txHash1))
	require.False(seenTxHashExist(gwHelper.ContractCtx(fakeCtx), txHash2))
	require.False(seenTxHashExist(gwHelper.ContractCtx(fakeCtx), txHash3))

	// Send token to Gateway Go contract
	err = gwHelper.Contract.ProcessEventBatch(gwHelper.ContractCtx(fakeCtx), &ProcessEventBatchRequest{
		Events: []*MainnetEvent{
			&MainnetEvent{
				EthBlock: 5,
				Payload: &MainnetDepositEvent{
					Deposit: &MainnetTokenDeposited{
						TokenKind:     TokenKind_ERC721,
						TokenContract: ethTokenAddr.MarshalPB(),
						TokenOwner:    ts.ethAddr.MarshalPB(),
						TokenID:       &types.BigUInt{Value: *loom.NewBigUIntFromInt(123)},
					},
				},
			},
		},
	})
	require.NoError(err)

	// Create fake context with enabled flag set
	fakeCtx = fakeCtx.WithFeature(features.TGCheckTxHashFeature, true)
	require.True(fakeCtx.FeatureEnabled(features.TGCheckTxHashFeature, false))

	err = gwHelper.Contract.ProcessEventBatch(gwHelper.ContractCtx(fakeCtx), &ProcessEventBatchRequest{
		Events: []*MainnetEvent{
			&MainnetEvent{
				EthBlock: 10,
				Payload: &MainnetDepositEvent{
					Deposit: &MainnetTokenDeposited{
						TokenKind:     TokenKind_ERC721,
						TokenContract: ethTokenAddr.MarshalPB(),
						TokenOwner:    ts.ethAddr.MarshalPB(),
						TokenID:       &types.BigUInt{Value: *loom.NewBigUIntFromInt(100)},
						TxHash:        txHash1,
					},
				},
			},
		},
	})
	require.NoError(err)
	require.True(seenTxHashExist(gwHelper.ContractCtx(fakeCtx), txHash1))

	// try to send same tx hash
	err = gwHelper.Contract.ProcessEventBatch(gwHelper.ContractCtx(fakeCtx), &ProcessEventBatchRequest{
		Events: []*MainnetEvent{
			&MainnetEvent{
				EthBlock: 15,
				Payload: &MainnetDepositEvent{
					Deposit: &MainnetTokenDeposited{
						TokenKind:     TokenKind_ERC721,
						TokenContract: ethTokenAddr.MarshalPB(),
						TokenOwner:    ts.ethAddr.MarshalPB(),
						TokenID:       &types.BigUInt{Value: *loom.NewBigUIntFromInt(100)},
						TxHash:        txHash1,
					},
				},
			},
		},
	})
	require.NoError(err)
	require.True(seenTxHashExist(gwHelper.ContractCtx(fakeCtx), txHash1))
	// TODO: Need to verify that the deposit wasn't processed, probably sufficient to check the last
	//       processed eth block tracked by the Gateway contract hasn't changed.

	fakeCtx = fakeCtx.WithFeature(features.TGVersion1_2, true)
	require.True(fakeCtx.FeatureEnabled(features.TGVersion1_2, false))

	erc721 := newERC721Context(contract.WrapPluginContext(fakeCtx.WithAddress(ts.dAppAddr)), dappTokenAddr)
	erc721.approve(gwHelper.Address, big.NewInt(123))

	err = gwHelper.Contract.WithdrawToken(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr)),
		&WithdrawTokenRequest{
			TokenContract: dappTokenAddr.MarshalPB(),
			TokenKind:     TokenKind_ERC721,
			TokenID:       &types.BigUInt{Value: *loom.NewBigUIntFromInt(123)},
			Recipient:     ts.ethAddr.MarshalPB(),
		},
	)
	require.NoError(err)

	err = gwHelper.Contract.ProcessEventBatch(gwHelper.ContractCtx(fakeCtx), &ProcessEventBatchRequest{
		Events: []*MainnetEvent{
			&MainnetEvent{
				EthBlock: 20,
				Payload: &MainnetDepositEvent{
					Deposit: &MainnetTokenDeposited{
						TokenKind:     TokenKind_ERC721,
						TokenContract: ethTokenAddr.MarshalPB(),
						TokenOwner:    ts.ethAddr.MarshalPB(),
						TokenID:       &types.BigUInt{Value: *loom.NewBigUIntFromInt(200)},
						TxHash:        txHash2,
					},
				},
			},
			&MainnetEvent{
				EthBlock: 30,
				Payload: &MainnetWithdrawalEvent{
					Withdrawal: &MainnetTokenWithdrawn{
						TokenKind:     TokenKind_ERC721,
						TokenContract: ethTokenAddr.MarshalPB(),
						TokenOwner:    ts.ethAddr.MarshalPB(),
						TokenID:       &types.BigUInt{Value: *loom.NewBigUIntFromInt(123)},
						TxHash:        txHash3,
					},
				},
			},
		},
	})

	require.NoError(err)
	require.True(seenTxHashExist(gwHelper.ContractCtx(fakeCtx), txHash2))
	require.True(seenTxHashExist(gwHelper.ContractCtx(fakeCtx), txHash3))
}

func (ts *GatewayTestSuite) TestGatewayTRC20Deposit() {
	require := ts.Require()
	fakeCtx := plugin.CreateFakeContextWithEVM(ts.dAppAddr, loom.RootAddress("tron"))

	addressMapper, err := deployAddressMapperContract(fakeCtx)
	require.NoError(err)

	gwHelper, err := deployGatewayContract(fakeCtx, &InitRequest{
		Owner:   ts.dAppAddr2.MarshalPB(),
		Oracles: []*types.Address{ts.dAppAddr.MarshalPB()},
	}, TronGateway)
	require.NoError(err)

	// Deploy ERC20 Solidity contract to DAppChain EVM
	// TRC20 is ERC20 compatible so using ERC20 on DAppChain would be suffice
	dappTokenAddr, err := deployTokenContract(fakeCtx, "SampleERC20Token", gwHelper.Address, ts.dAppAddr)
	require.NoError(err)

	require.NoError(gwHelper.AddContractMapping(fakeCtx, tronTokenAddr, dappTokenAddr))
	sig, err := address_mapper.SignIdentityMapping(ts.tronAddr, ts.dAppAddr, ts.tronKey, sigType)
	require.NoError(err)
	require.NoError(addressMapper.AddIdentityMapping(fakeCtx, ts.tronAddr, ts.dAppAddr, sig))

	// Send token to Gateway Go contract
	err = gwHelper.Contract.ProcessEventBatch(gwHelper.ContractCtx(fakeCtx), &ProcessEventBatchRequest{
		Events: []*MainnetEvent{
			&MainnetEvent{
				EthBlock: 5,
				Payload: &MainnetDepositEvent{
					Deposit: &MainnetTokenDeposited{
						TokenKind:     TokenKind_TRC20,
						TokenContract: tronTokenAddr.MarshalPB(),
						TokenOwner:    ts.tronAddr.MarshalPB(),
						TokenAmount:   &types.BigUInt{Value: *loom.NewBigUIntFromInt(123)},
					},
				},
			},
		},
	})
	require.NoError(err)

	erc20 := newERC20StaticContext(gwHelper.ContractCtx(fakeCtx), dappTokenAddr)
	balance, err := erc20.balanceOf(ts.dAppAddr)
	require.NoError(err)
	require.Equal(big.NewInt(123), balance)
}

func (ts *GatewayTestSuite) TestTronGateway() {
	require := ts.Require()
	ownerAddr := ts.dAppAddr
	oracleAddr := ts.dAppAddr2
	justinTRXTronAddr := ts.tronAddr
	justinTRC20TronAddr := ts.tronAddr2
	justinTRXdAppAddr := ts.dAppAddr3
	justinTRC20dAppAddr := ts.dAppAddr4

	fakeCtx := plugin.CreateFakeContextWithEVM(oracleAddr, loom.RootAddress("chain"))
	addressMapper, err := deployAddressMapperContract(fakeCtx)
	require.NoError(err)

	gwHelper, err := deployGatewayContract(fakeCtx, &InitRequest{
		Owner:   ownerAddr.MarshalPB(),
		Oracles: []*types.Address{oracleAddr.MarshalPB()},
	}, TronGateway)
	require.NoError(err)

	// Deploy TRX as TRC20 Solidity contract to DAppChain EVM
	dappTRXTokenAddr, err := deployTokenContract(fakeCtx, "TRXToken", gwHelper.Address, ownerAddr)
	require.NoError(err)
	// Deploy TRC20 Solidity contract to DAppChain EVM
	dappTRC20TokenAddr, err := deployTokenContract(fakeCtx, "SampleERC20Token", gwHelper.Address, ownerAddr)
	require.NoError(err)

	require.NoError(gwHelper.AddContractMapping(fakeCtx, TRXTokenAddr, dappTRXTokenAddr))
	require.NoError(gwHelper.AddContractMapping(fakeCtx, tronTokenAddr2, dappTRC20TokenAddr))

	sig, err := address_mapper.SignIdentityMapping(justinTRXTronAddr, justinTRXdAppAddr, ts.tronKey, sigType)
	require.NoError(err)
	require.NoError(addressMapper.AddIdentityMapping(fakeCtx.WithSender(justinTRXdAppAddr), justinTRXTronAddr, justinTRXdAppAddr, sig))

	sig, err = address_mapper.SignIdentityMapping(justinTRC20TronAddr, justinTRC20dAppAddr, ts.tronKey2, sigType)
	require.NoError(err)
	require.NoError(addressMapper.AddIdentityMapping(fakeCtx.WithSender(justinTRC20dAppAddr), justinTRC20TronAddr, justinTRC20dAppAddr, sig))

	// Send token to Gateway Go contract
	err = gwHelper.Contract.ProcessEventBatch(gwHelper.ContractCtx(fakeCtx), &ProcessEventBatchRequest{
		Events: []*MainnetEvent{
			&MainnetEvent{
				EthBlock: 5,
				Payload: &MainnetDepositEvent{
					Deposit: &MainnetTokenDeposited{
						TokenKind:     TokenKind_TRX,
						TokenContract: TRXTokenAddr.MarshalPB(),
						TokenOwner:    justinTRXTronAddr.MarshalPB(),
						TokenAmount:   &types.BigUInt{Value: *loom.NewBigUIntFromInt(123)},
					},
				},
			},
			&MainnetEvent{
				EthBlock: 10,
				Payload: &MainnetDepositEvent{
					Deposit: &MainnetTokenDeposited{
						TokenKind:     TokenKind_TRC20,
						TokenContract: tronTokenAddr2.MarshalPB(),
						TokenOwner:    justinTRC20TronAddr.MarshalPB(),
						TokenAmount:   &types.BigUInt{Value: *loom.NewBigUIntFromInt(456)},
					},
				},
			},
		},
	})
	require.NoError(err)

	trcx := newERC20StaticContext(gwHelper.ContractCtx(fakeCtx), dappTRXTokenAddr)
	balance, err := trcx.balanceOf(justinTRXdAppAddr)
	require.NoError(err)
	require.Equal(big.NewInt(123), balance)

	// justin approves gateway to transfer the amount
	trctx := newERC20Context(contract.WrapPluginContext(fakeCtx.WithAddress(justinTRXdAppAddr)), dappTRXTokenAddr)
	require.NoError(trctx.approve(gwHelper.Address, big.NewInt(123)))

	trc20 := newERC20StaticContext(gwHelper.ContractCtx(fakeCtx), dappTRC20TokenAddr)
	balance, err = trc20.balanceOf(justinTRC20dAppAddr)
	require.NoError(err)
	require.Equal(big.NewInt(456), balance)

	// justin withdraw from dAppChain Gateway
	err = gwHelper.Contract.WithdrawToken(
		gwHelper.ContractCtx(fakeCtx.WithSender(justinTRXdAppAddr)),
		&WithdrawTokenRequest{
			TokenKind:     TokenKind_TRX,
			TokenContract: TRXTokenAddr.MarshalPB(),
			TokenAmount:   &types.BigUInt{Value: *loom.NewBigUIntFromInt(99)},
		},
	)
	require.NoError(err)

	err = gwHelper.Contract.ProcessEventBatch(gwHelper.ContractCtx(fakeCtx), &ProcessEventBatchRequest{
		Events: []*MainnetEvent{
			&MainnetEvent{
				EthBlock: 15,
				Payload: &MainnetWithdrawalEvent{
					Withdrawal: &MainnetTokenWithdrawn{
						TokenKind:     TokenKind_TRX,
						TokenContract: tronTokenAddr.MarshalPB(),
						TokenOwner:    justinTRXTronAddr.MarshalPB(),
						TokenAmount:   &types.BigUInt{Value: *loom.NewBigUIntFromInt(99)},
					},
				},
			},
		},
	})
	require.NoError(err)
}

// Test Deposit and Withdraw LOOM token between plasma chain and binance chain
func (ts *GatewayTestSuite) TestBinanceGateway() {

	require := ts.Require()
	ownerAddr := ts.dAppAddr
	oracleAddr := ts.dAppAddr2
	czBinanceAddr := ts.binanceAddr
	czBinanceDappAddr := ts.dAppAddr5

	fakeCtx := plugin.CreateFakeContextWithEVM(oracleAddr, loom.RootAddress("chain"))
	fakeCtx = fakeCtx.WithFeature(features.CoinVersion1_3Feature, true)
	fakeCtx = fakeCtx.WithFeature(features.TGVersion1_3, true)
	fakeCtx.FakeContext.SetFeature(features.TGVersion1_3, true)
	fakeCtx.FakeContext.SetFeature(features.CoinVersion1_3Feature, true)
	fakeCtx.FakeContext.SetFeature(features.TGVersion1_4, true)

	addressMapper, err := deployAddressMapperContract(fakeCtx)
	require.NoError(err)

	sig, err := address_mapper.SignIdentityMapping(czBinanceAddr, czBinanceDappAddr, ts.binanceKey, sigType)
	require.NoError(err)

	require.NoError(addressMapper.AddIdentityMapping(fakeCtx.WithSender(czBinanceDappAddr), czBinanceAddr, czBinanceDappAddr, sig))

	transferFee := &types.BigUInt{Value: *loom.NewBigUIntFromInt(37500)}

	gwHelper, err := deployGatewayContract(fakeCtx, &InitRequest{
		Owner:   ownerAddr.MarshalPB(),
		Oracles: []*types.Address{oracleAddr.MarshalPB()},
	}, BinanceGateway)
	require.NoError(err)

	req := &UpdateBinanceTransferFeeRequest{
		TransferFee: transferFee,
	}
	err = gwHelper.Contract.SetTransferFee(gwHelper.ContractCtx(fakeCtx.WithSender(ownerAddr)), req)
	require.NoError(err)

	// deploy erc20 coin for sampleBNBToken
	dappTokenAddr2, err := deployTokenContract(fakeCtx, "SampleBNBToken", gwHelper.Address, ts.dAppAddr2)
	require.NoError(err)
	require.NoError(gwHelper.AddContractMapping(fakeCtx, binanceBNBAddr, dappTokenAddr2))

	// deploy LOOM coin
	loomCoinContract, err := deployLoomCoinContract(fakeCtx)

	require.NoError(err)
	// depositing from binance we put Dapp
	loomamountsByBlock := []int64{160, 239, 581}
	loomdeposits := genLoomDepositsFromBinance(
		loomCoinContract.Address,
		czBinanceDappAddr,
		[]uint64{71, 73, 75},
		loomamountsByBlock,
	)
	err = gwHelper.Contract.ProcessEventBatch(gwHelper.ContractCtx(fakeCtx), &ProcessEventBatchRequest{
		Events: loomdeposits,
	})
	require.NoError(err)

	// depositing BNB from binance
	bep2BNBamountsByBlock := []int64{37500}
	bep2BNBdeposits := genBEP2DepositsFromBinance(
		binanceBNBAddr,
		czBinanceDappAddr,
		[]uint64{78},
		bep2BNBamountsByBlock,
	)

	err = gwHelper.Contract.ProcessEventBatch(gwHelper.ContractCtx(fakeCtx), &ProcessEventBatchRequest{
		Events: bep2BNBdeposits,
	})
	require.NoError(err)

	loomcoin := newcoinStaticContext(gwHelper.ContractCtx(fakeCtx))
	bal, err := loomcoin.balanceOf(czBinanceDappAddr)
	require.NoError(err)
	require.Equal(int64(9800000000000), bal.Int64()) // we gain 10**10 from precision adjustment
	resp, err := gwHelper.Contract.GetUnclaimedContractTokens(gwHelper.ContractCtx(fakeCtx), &GetUnclaimedContractTokensRequest{TokenAddress: loomCoinContract.Address.MarshalPB()})
	require.NoError(err)
	require.Equal(loom.NewBigUIntFromInt(0), &resp.UnclaimedAmount.Value)

	erc20bnb := newERC20Context(contract.WrapPluginContext(fakeCtx.WithAddress(czBinanceDappAddr)), dappTokenAddr2)
	balbnb, err := erc20bnb.balanceOf(czBinanceDappAddr)
	require.NoError(err)
	require.Equal(int64(37500), balbnb.Int64()) // we gain no decimals as this erc20 bnb token contract has 8 decimals

	require.NoError(erc20bnb.approve(gwHelper.Address, big.NewInt(37500)))
	// cz withdraw LOOM coin from dAppChain Gateway
	err = gwHelper.Contract.WithdrawLoomCoin(
		gwHelper.ContractCtx(fakeCtx.WithSender(czBinanceDappAddr)),
		&WithdrawLoomCoinRequest{
			TokenContract: loomcoin.contractAddr.MarshalPB(),
			Amount:        &types.BigUInt{Value: *loom.NewBigUIntFromInt(1000000000000)},
			Recipient:     czBinanceAddr.MarshalPB(),
		},
	)
	require.NoError(err)

	receipt, err := gwHelper.Contract.WithdrawalReceipt(
		gwHelper.ContractCtx(fakeCtx.WithSender(czBinanceDappAddr)),
		&WithdrawalReceiptRequest{
			Owner: czBinanceDappAddr.MarshalPB(),
		},
	)
	require.NoError(err)
	// When TGVersion1_5 feature flag is disabled TokenWithdrawer should be written to the receipt
	require.NotNil(receipt.Receipt.TokenWithdrawer)

	err = gwHelper.Contract.ProcessEventBatch(gwHelper.ContractCtx(fakeCtx), &ProcessEventBatchRequest{
		Events: []*MainnetEvent{
			&MainnetEvent{
				EthBlock: 80,
				Payload: &MainnetWithdrawalEvent{
					Withdrawal: &MainnetTokenWithdrawn{
						TokenKind:     TokenKind_BNBLoomToken,
						TokenContract: loomcoin.contractAddr.MarshalPB(),
						TokenOwner:    czBinanceAddr.MarshalPB(),
						TokenAmount:   &types.BigUInt{Value: *loom.NewBigUIntFromInt(1000000000000)},
					},
				},
			},
		},
	})
	require.NoError(err)

	balanceAfter, err := loomcoin.balanceOf(czBinanceDappAddr)
	require.NoError(err)
	require.Equal(int64(8800000000000), balanceAfter.Int64())

	err = gwHelper.Contract.WithdrawLoomCoin(
		gwHelper.ContractCtx(fakeCtx.WithSender(czBinanceDappAddr).WithFeature(features.TGVersion1_5, true)),
		&WithdrawLoomCoinRequest{
			TokenContract: loomcoin.contractAddr.MarshalPB(),
			Amount:        &types.BigUInt{Value: *loom.NewBigUIntFromInt(1000000000000)},
			Recipient:     czBinanceAddr.MarshalPB(),
		},
	)
	require.NoError(err)

	receipt, err = gwHelper.Contract.WithdrawalReceipt(
		gwHelper.ContractCtx(fakeCtx.WithSender(czBinanceDappAddr)),
		&WithdrawalReceiptRequest{
			Owner: czBinanceDappAddr.MarshalPB(),
		},
	)
	require.NoError(err)
	// When TGVersion1_5 feature flag is enabled TokenWithdrawer shouldn't be written to the receipt
	require.Nil(receipt.Receipt.TokenWithdrawer)
}

func (ts *GatewayTestSuite) TestBinanceBEP2Gateway() {
	require := ts.Require()
	ownerAddr := ts.dAppAddr
	oracleAddr := ts.dAppAddr2
	czBinanceAddr := ts.binanceAddr
	czBinanceDappAddr := ts.dAppAddr5 // owner of bep2 token on dappchain
	fakeCtx := plugin.CreateFakeContextWithEVM(oracleAddr, loom.RootAddress("chain"))
	_, err := deployAddressMapperContract(fakeCtx)
	require.NoError(err)

	transferFee := &types.BigUInt{Value: *loom.NewBigUIntFromInt(37500)}

	gwHelper, err := deployGatewayContract(fakeCtx, &InitRequest{
		Owner:   ownerAddr.MarshalPB(),
		Oracles: []*types.Address{oracleAddr.MarshalPB()},
	}, BinanceGateway)
	require.NoError(err)

	req := &UpdateBinanceTransferFeeRequest{
		TransferFee: transferFee,
	}

	err = gwHelper.Contract.SetTransferFee(gwHelper.ContractCtx(fakeCtx.WithSender(ownerAddr)), req)
	require.NoError(err)

	// deploy erc20 coin for MOOL token
	dappTokenAddr, err := deployTokenContract(fakeCtx, "SampleBEP2Token", gwHelper.Address, ts.dAppAddr)
	require.NoError(err)
	require.NoError(gwHelper.AddContractMapping(fakeCtx, binanceTokenAddr2, dappTokenAddr))

	// deploy erc20 coin for sampleBNBToken
	dappTokenAddr2, err := deployTokenContract(fakeCtx, "SampleBNBToken", gwHelper.Address, ts.dAppAddr2)
	require.NoError(err)
	require.NoError(gwHelper.AddContractMapping(fakeCtx, binanceBNBAddr, dappTokenAddr2))

	// depositing from binance we put Dapp
	bep2amountsByBlock := []int64{160, 239, 581}
	bep2deposits := genBEP2DepositsFromBinance(
		binanceTokenAddr2,
		czBinanceDappAddr,
		[]uint64{71, 73, 75},
		bep2amountsByBlock,
	)

	err = gwHelper.Contract.ProcessEventBatch(gwHelper.ContractCtx(fakeCtx), &ProcessEventBatchRequest{
		Events: bep2deposits,
	})
	require.NoError(err)

	// depositing BNB from binance
	bep2BNBamountsByBlock := []int64{37500}
	bep2BNBdeposits := genBEP2DepositsFromBinance(
		binanceBNBAddr,
		czBinanceDappAddr,
		[]uint64{78},
		bep2BNBamountsByBlock,
	)

	err = gwHelper.Contract.ProcessEventBatch(gwHelper.ContractCtx(fakeCtx), &ProcessEventBatchRequest{
		Events: bep2BNBdeposits,
	})

	require.NoError(err)
	erc20 := newERC20Context(contract.WrapPluginContext(fakeCtx.WithAddress(czBinanceDappAddr)), dappTokenAddr)
	bal, err := erc20.balanceOf(czBinanceDappAddr)

	require.NoError(err)
	require.Equal(int64(980), bal.Int64())

	erc20bnb := newERC20Context(contract.WrapPluginContext(fakeCtx.WithAddress(czBinanceDappAddr)), dappTokenAddr2)
	balbnb, err := erc20bnb.balanceOf(czBinanceDappAddr)

	require.NoError(err)
	require.Equal(int64(37500), balbnb.Int64())

	resp, err := gwHelper.Contract.GetUnclaimedContractTokens(gwHelper.ContractCtx(fakeCtx), &GetUnclaimedContractTokensRequest{TokenAddress: dappTokenAddr.MarshalPB()})
	require.NoError(err)
	require.Equal(loom.NewBigUIntFromInt(0), &resp.UnclaimedAmount.Value)

	// approve erc20 token to be transferred to gateway otherwise the test fail
	require.NoError(erc20.approve(gwHelper.Address, big.NewInt(180)))
	require.NoError(erc20bnb.approve(gwHelper.Address, big.NewInt(37500)))
	// cz withdraw MOOL coin from dAppChain Gateway
	err = gwHelper.Contract.WithdrawToken(
		gwHelper.ContractCtx(fakeCtx.WithSender(czBinanceDappAddr)),
		&WithdrawTokenRequest{
			TokenKind:     TokenKind_BEP2,
			TokenContract: dappTokenAddr.MarshalPB(),
			TokenAmount:   &types.BigUInt{Value: *loom.NewBigUIntFromInt(180)},
			Recipient:     czBinanceAddr.MarshalPB(),
		},
	)
	require.NoError(err)

	err = gwHelper.Contract.ProcessEventBatch(gwHelper.ContractCtx(fakeCtx), &ProcessEventBatchRequest{
		Events: []*MainnetEvent{
			&MainnetEvent{
				EthBlock: 90,
				Payload: &MainnetWithdrawalEvent{
					Withdrawal: &MainnetTokenWithdrawn{
						TokenKind:     TokenKind_BEP2,
						TokenContract: dappTokenAddr.MarshalPB(),
						TokenOwner:    czBinanceAddr.MarshalPB(),
						TokenAmount:   &types.BigUInt{Value: *loom.NewBigUIntFromInt(180)},
					},
				},
			},
		},
	})
	require.NoError(err)

	balanceAfter, err := erc20.balanceOf(czBinanceDappAddr)
	require.NoError(err)
	require.Equal(int64(800), balanceAfter.Int64())
}

func (ts *GatewayTestSuite) TestBinanceBNBTokenBEP2Gateway() {
	require := ts.Require()
	ownerAddr := ts.dAppAddr
	oracleAddr := ts.dAppAddr2
	czBinanceAddr := ts.binanceAddr
	czBinanceDappAddr := ts.dAppAddr5
	fakeCtx := plugin.CreateFakeContextWithEVM(oracleAddr, loom.RootAddress("chain"))
	_, err := deployAddressMapperContract(fakeCtx)
	require.NoError(err)

	transferFee := &types.BigUInt{Value: *loom.NewBigUIntFromInt(37500)}

	gwHelper, err := deployGatewayContract(fakeCtx, &InitRequest{
		Owner:   ownerAddr.MarshalPB(),
		Oracles: []*types.Address{oracleAddr.MarshalPB()},
	}, BinanceGateway)
	require.NoError(err)

	req := &UpdateBinanceTransferFeeRequest{
		TransferFee: transferFee,
	}

	err = gwHelper.Contract.SetTransferFee(gwHelper.ContractCtx(fakeCtx.WithSender(ownerAddr)), req)
	require.NoError(err)

	// deploy erc20 coin for sampleBNBToken
	dappTokenAddr, err := deployTokenContract(fakeCtx, "SampleBNBToken", gwHelper.Address, ts.dAppAddr2)
	require.NoError(err)
	require.NoError(gwHelper.AddContractMapping(fakeCtx, binanceBNBAddr, dappTokenAddr))

	// depositing BNB from binance
	bep2BNBamountsByBlock := []int64{100000000}
	bep2BNBdeposits := genBEP2DepositsFromBinance(
		binanceBNBAddr,
		czBinanceDappAddr,
		[]uint64{78},
		bep2BNBamountsByBlock,
	)

	err = gwHelper.Contract.ProcessEventBatch(gwHelper.ContractCtx(fakeCtx), &ProcessEventBatchRequest{
		Events: bep2BNBdeposits,
	})

	erc20bnb := newERC20Context(contract.WrapPluginContext(fakeCtx.WithAddress(czBinanceDappAddr)), dappTokenAddr)
	balbnb, err := erc20bnb.balanceOf(czBinanceDappAddr)

	require.NoError(err)
	require.Equal(int64(100000000), balbnb.Int64())

	// approve erc20 token to be transferred to gateway otherwise the test fail
	require.NoError(erc20bnb.approve(gwHelper.Address, big.NewInt(100000000)))

	// cz withdraw BNB coin from dAppChain Gateway
	err = gwHelper.Contract.WithdrawToken(
		gwHelper.ContractCtx(fakeCtx.WithSender(czBinanceDappAddr)),
		&WithdrawTokenRequest{
			TokenKind:     TokenKind_BEP2,
			TokenContract: dappTokenAddr.MarshalPB(),
			TokenAmount:   &types.BigUInt{Value: *loom.NewBigUIntFromInt(9962500)},
			Recipient:     czBinanceAddr.MarshalPB(),
		},
	)
	require.NoError(err)

	receipt, err := gwHelper.Contract.WithdrawalReceipt(
		gwHelper.ContractCtx(fakeCtx.WithSender(czBinanceDappAddr)),
		&WithdrawalReceiptRequest{
			Owner: czBinanceDappAddr.MarshalPB(),
		},
	)
	require.NoError(err)
	// When TGVersion1_5 feature flag is disabled TokenWithdrawer should be written to the receipt
	require.NotNil(receipt.Receipt.TokenWithdrawer)

	// Oracle calls gateway to process the event
	err = gwHelper.Contract.ProcessEventBatch(gwHelper.ContractCtx(fakeCtx), &ProcessEventBatchRequest{
		Events: []*MainnetEvent{
			&MainnetEvent{
				EthBlock: 90,
				Payload: &MainnetWithdrawalEvent{
					Withdrawal: &MainnetTokenWithdrawn{
						TokenKind:     TokenKind_BEP2,
						TokenContract: binanceBNBAddr.MarshalPB(),
						TokenOwner:    czBinanceAddr.MarshalPB(),
						TokenAmount:   &types.BigUInt{Value: *loom.NewBigUIntFromInt(9962500)},
					},
				},
			},
		},
	})
	require.NoError(err)

	balanceAfter, err := erc20bnb.balanceOf(czBinanceDappAddr)
	require.NoError(err)
	// remaining_balance = total_balance - (transfer_amount + fee)
	// 90000000          = 100000000     - (    9962500     + 37500)
	require.Equal(int64(90000000), balanceAfter.Int64())

	// Fail case: Insufficient fund
	// approve erc20 token to be transferred to gateway otherwise the test fail
	require.NoError(erc20bnb.approve(gwHelper.Address, big.NewInt(100000000)))

	// cz withdraw BNB coin from dAppChain Gateway

	err = gwHelper.Contract.WithdrawToken(
		gwHelper.ContractCtx(fakeCtx.WithSender(czBinanceDappAddr)),
		&WithdrawTokenRequest{
			TokenKind:     TokenKind_BEP2,
			TokenContract: dappTokenAddr.MarshalPB(),
			TokenAmount:   &types.BigUInt{Value: *loom.NewBigUIntFromInt(100000000)},
			Recipient:     czBinanceAddr.MarshalPB(),
		},
	)
	require.Error(err, "this should return `Insufficient dappchain binance:0x0000000000000000000000000000000000424E42 balance`")

	require.Error(gwHelper.Contract.ProcessEventBatch(gwHelper.ContractCtx(fakeCtx), &ProcessEventBatchRequest{
		Events: []*MainnetEvent{
			&MainnetEvent{
				EthBlock: 90,
				Payload: &MainnetWithdrawalEvent{
					Withdrawal: &MainnetTokenWithdrawn{
						TokenKind:     TokenKind_BEP2,
						TokenContract: binanceBNBAddr.MarshalPB(),
						TokenOwner:    czBinanceAddr.MarshalPB(),
						TokenAmount:   &types.BigUInt{Value: *loom.NewBigUIntFromInt(100000000)},
					},
				},
			},
		},
	}), "this process event batch should have no pending withdrawal thus return nil")

	balanceAfter, err = erc20bnb.balanceOf(czBinanceDappAddr)
	require.NoError(err)
	require.Equal(int64(90000000), balanceAfter.Int64())

	err = gwHelper.Contract.WithdrawToken(
		gwHelper.ContractCtx(fakeCtx.WithSender(czBinanceDappAddr).WithFeature(features.TGVersion1_5, true)),
		&WithdrawTokenRequest{
			TokenKind:     TokenKind_BEP2,
			TokenContract: dappTokenAddr.MarshalPB(),
			TokenAmount:   &types.BigUInt{Value: *loom.NewBigUIntFromInt(9962500)},
			Recipient:     czBinanceAddr.MarshalPB(),
		},
	)
	require.NoError(err)

	receipt, err = gwHelper.Contract.WithdrawalReceipt(
		gwHelper.ContractCtx(fakeCtx.WithSender(czBinanceDappAddr)),
		&WithdrawalReceiptRequest{
			Owner: czBinanceDappAddr.MarshalPB(),
		},
	)
	require.NoError(err)
	// When TGVersion1_5 feature flag is disabled TokenWithdrawer should be written to the receipt
	require.Nil(receipt.Receipt.TokenWithdrawer)
}

func (ts *GatewayTestSuite) TestGatewayHotWalletDepositWithdrawal() {
	require := ts.Require()
	fakeCtx := plugin.CreateFakeContextWithEVM(ts.dAppAddr, loom.RootAddress("chain"))
	// Create fake context with enabled flag set
	fakeCtx = fakeCtx.WithFeature(features.TGCheckTxHashFeature, true)
	require.True(fakeCtx.FeatureEnabled(features.TGCheckTxHashFeature, false))

	addressMapper, err := deployAddressMapperContract(fakeCtx)
	require.NoError(err)

	gwHelper, err := deployGatewayContract(fakeCtx, &InitRequest{
		Owner:   ts.dAppAddr2.MarshalPB(),
		Oracles: []*types.Address{ts.dAppAddr.MarshalPB()},
	}, EthereumGateway)
	require.NoError(err)

	// Deploy ERC20 Solidity contract to DAppChain EVM
	dappTokenAddr, err := deployTokenContract(fakeCtx, "SampleERC20Token", gwHelper.Address, ts.dAppAddr)
	require.NoError(err)

	require.NoError(gwHelper.AddContractMapping(fakeCtx, ethTokenAddr, dappTokenAddr))
	sig, err := address_mapper.SignIdentityMapping(ts.ethAddr, ts.dAppAddr, ts.ethKey, sigType)
	require.NoError(err)
	require.NoError(addressMapper.AddIdentityMapping(fakeCtx, ts.ethAddr, ts.dAppAddr, sig))

	txHash := []byte("0xdeadbeef")
	tokenAmount := &types.BigUInt{Value: *loom.NewBigUIntFromInt(123)}
	// Send token to Gateway Go contract
	err = gwHelper.Contract.ProcessHotWalletEventBatch(gwHelper.ContractCtx(fakeCtx), &ProcessEventBatchRequest{
		Events: []*MainnetEvent{
			&MainnetEvent{
				EthBlock: 5,
				Payload: &MainnetDepositEvent{
					Deposit: &MainnetTokenDeposited{
						TokenKind:     TokenKind_ERC20,
						TokenContract: ethTokenAddr.MarshalPB(),
						TokenOwner:    ts.ethAddr.MarshalPB(),
						TokenAmount:   tokenAmount,
						TxHash:        txHash,
					},
				},
			},
		},
		MainnetHotWalletAddress: ethTokenAddr4.MarshalPB(),
	})
	require.EqualError(err, ErrHotWalletFeatureDisabled.Error())

	fakeCtx = fakeCtx.WithFeature(features.TGHotWalletFeature, true)
	require.True(fakeCtx.FeatureEnabled(features.TGHotWalletFeature, false))
	// Make Gateway happy about the address validation
	require.NoError(gwHelper.UpdateMainnetHotWalletAddress(fakeCtx.WithSender(ts.dAppAddr2), ethTokenAddr4))

	// User submits tx hash to Gateway

	err = gwHelper.Contract.SubmitHotWalletDepositTxHash(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr)),
		&SubmitHotWalletDepositTxHashRequest{
			TxHash: txHash,
		},
	)
	require.NoError(err)

	owner := ts.ethAddr

	gotTxHashes, err := loadHotWalletDepositTxHashes(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr)),
		owner,
	)
	require.NoError(err)
	require.Contains(gotTxHashes.TxHashes, txHash,
		"Gateway should save hot wallet deposit tx hash using eth address")

	err = gwHelper.Contract.SubmitHotWalletDepositTxHash(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr)),
		&SubmitHotWalletDepositTxHashRequest{
			TxHash: txHash,
		},
	)
	require.Error(err, "user should not be able to resubmit the same pending tx hash")

	// User submits another tx hash to Gateway
	txHash2 := []byte("0xbadbeef")
	err = gwHelper.Contract.SubmitHotWalletDepositTxHash(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr)),
		&SubmitHotWalletDepositTxHashRequest{
			TxHash: txHash2,
		},
	)
	require.NoError(err, "user should be able to submit different tx hash")

	pendingDeposits, err := gwHelper.Contract.PendingHotWalletDepositTxHashes(
		gwHelper.ContractCtx(fakeCtx),
		&PendingHotWalletDepositTxHashesRequest{},
	)
	require.NoError(err)
	require.Contains(pendingDeposits.TxHashes, txHash,
		"Gateway should return valid pending deposits")

	err = gwHelper.Contract.ProcessHotWalletEventBatch(gwHelper.ContractCtx(fakeCtx), &ProcessEventBatchRequest{
		Events: []*MainnetEvent{
			&MainnetEvent{
				EthBlock: 5,
				Payload: &MainnetDepositEvent{
					Deposit: &MainnetTokenDeposited{
						TokenKind:     TokenKind_ERC20,
						TokenContract: ethTokenAddr.MarshalPB(),
						TokenOwner:    ts.ethAddr.MarshalPB(),
						TokenAmount:   tokenAmount,
						TxHash:        txHash,
					},
				},
			},
			&MainnetEvent{
				EthBlock: 10,
				Payload: &MainnetDepositEvent{
					Deposit: &MainnetTokenDeposited{
						TokenKind:     TokenKind_ERC20,
						TokenContract: ethTokenAddr.MarshalPB(),
						TokenOwner:    ts.ethAddr.MarshalPB(),
						TokenAmount:   tokenAmount,
						TxHash:        txHash2,
					},
				},
			},
		},
		MainnetHotWalletAddress: ethTokenAddr4.MarshalPB(),
	})

	erc20 := newERC20StaticContext(gwHelper.ContractCtx(fakeCtx), dappTokenAddr)
	amount, err := erc20.balanceOf(ts.dAppAddr)
	require.NoError(err)
	require.Equal(new(big.Int).Add(tokenAmount.Value.Int, tokenAmount.Value.Int).String(), amount.String(),
		"user should have token amount on Dapp the same amount he deposits to Gateway")

	gotTxHashes, err = loadHotWalletDepositTxHashes(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr)),
		owner,
	)
	require.NoError(err)
	require.NotContains(gotTxHashes.TxHashes, txHash,
		"Gateway contract should clear deposit tx hash that has already processed")
	require.Equal(0, len(gotTxHashes.TxHashes),
		"Gateway contract should clear deposit tx hash that has already processed")

	// Now test submit invalid tx hash
	// Start from owner submit a new tx hash
	txHash3 := []byte("0xaaaa")
	err = gwHelper.Contract.SubmitHotWalletDepositTxHash(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr)),
		&SubmitHotWalletDepositTxHashRequest{
			TxHash: txHash3,
		},
	)
	require.NoError(err, "user should be able to submit different tx hash")
	// More hashes
	err = gwHelper.Contract.SubmitHotWalletDepositTxHash(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr)),
		&SubmitHotWalletDepositTxHashRequest{
			TxHash: []byte("0xdeadbeef3"),
		},
	)
	require.NoError(err, "user should be able to submit tx hash")
	err = gwHelper.Contract.SubmitHotWalletDepositTxHash(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr)),
		&SubmitHotWalletDepositTxHashRequest{
			TxHash: []byte("0xdeadbeef4"),
		},
	)
	require.NoError(err, "user should be able to submit tx hash")
	err = gwHelper.Contract.SubmitHotWalletDepositTxHash(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr)),
		&SubmitHotWalletDepositTxHashRequest{
			TxHash: []byte("0xdeadbeef5"),
		},
	)
	require.NoError(err, "user should be able to submit tx hash")

	gotTxHashes, err = loadHotWalletDepositTxHashes(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr)),
		owner,
	)
	require.NoError(err)
	require.Contains(gotTxHashes.TxHashes, txHash3,
		"Gateway should save hot wallet deposit tx hash using eth address")
	require.Contains(gotTxHashes.TxHashes, []byte("0xdeadbeef3"),
		"Gateway should contain tx hash")
	require.Contains(gotTxHashes.TxHashes, []byte("0xdeadbeef4"),
		"Gateway should contain tx hash")
	require.Contains(gotTxHashes.TxHashes, []byte("0xdeadbeef5"),
		"Gateway should contain tx hash")

	// Oracle submits the event
	err = gwHelper.Contract.ClearInvalidHotWalletDepositTxHash(gwHelper.ContractCtx(fakeCtx), &ClearInvalidHotWalletDepositTxHashRequest{
		TxHashes:                [][]byte{txHash3},
		MainnetHotWalletAddress: ethTokenAddr4.MarshalPB(),
	})
	require.NoError(err)

	gotTxHashes, err = loadHotWalletDepositTxHashes(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr)),
		owner,
	)
	require.NoError(err)
	require.NotContains(gotTxHashes.TxHashes, txHash3,
		"Gateway should not contain tx hash the is cleared")
	require.Contains(gotTxHashes.TxHashes, []byte("0xdeadbeef3"),
		"Gateway should contain tx hash")
	require.Contains(gotTxHashes.TxHashes, []byte("0xdeadbeef4"),
		"Gateway should contain tx hash")
	require.Contains(gotTxHashes.TxHashes, []byte("0xdeadbeef5"),
		"Gateway should contain tx hash")
}

func (ts *GatewayTestSuite) TestGatewayHotWalletDepositAndApproveTransfer() {
	require := ts.Require()
	fakeCtx := plugin.CreateFakeContextWithEVM(ts.dAppAddr, loom.RootAddress("chain"))
	// Create fake context with enabled flag set
	fakeCtx = fakeCtx.WithFeature(features.TGCheckTxHashFeature, true)
	require.True(fakeCtx.FeatureEnabled(features.TGCheckTxHashFeature, false))
	fakeCtx = fakeCtx.WithFeature(features.TGHotWalletFeature, true)
	require.True(fakeCtx.FeatureEnabled(features.TGHotWalletFeature, false))
	fakeCtx = fakeCtx.WithFeature(features.TGVersion1_1, true)
	require.True(fakeCtx.FeatureEnabled(features.TGVersion1_1, false))

	addressMapper, err := deployAddressMapperContract(fakeCtx)
	require.NoError(err)

	gwHelper, err := deployGatewayContract(fakeCtx, &InitRequest{
		Owner:   ts.dAppAddr2.MarshalPB(),
		Oracles: []*types.Address{ts.dAppAddr.MarshalPB()},
	}, EthereumGateway)
	require.NoError(err)

	// Make Gateway happy about the address validation
	// This case Mainnet Gateway == Hot Wallet address
	require.NoError(gwHelper.UpdateMainnetGatewayAddress(fakeCtx.WithSender(ts.dAppAddr2), ethTokenAddr4))
	require.NoError(gwHelper.UpdateMainnetHotWalletAddress(fakeCtx.WithSender(ts.dAppAddr2), ethTokenAddr4))

	// Deploy ERC20 Solidity contract to DAppChain EVM
	dappTokenAddr, err := deployTokenContract(fakeCtx, "SampleERC20Token", gwHelper.Address, ts.dAppAddr)
	require.NoError(err)
	erc20 := newERC20StaticContext(gwHelper.ContractCtx(fakeCtx), dappTokenAddr)

	require.NoError(gwHelper.AddContractMapping(fakeCtx, ethTokenAddr, dappTokenAddr))
	sig, err := address_mapper.SignIdentityMapping(ts.ethAddr, ts.dAppAddr, ts.ethKey, sigType)
	require.NoError(err)
	require.NoError(addressMapper.AddIdentityMapping(fakeCtx, ts.ethAddr, ts.dAppAddr, sig))

	tokenAmount := &types.BigUInt{Value: *loom.NewBigUIntFromInt(123)}
	txHash := []byte("0xdeadbeef")

	// # Use Case 1
	// User does approve transfer and also submits tx hash via Hot Wallet
	// Oracle submit event batch first and hot wallet event batch second

	// 1. User does ApproveTransfer via Gateway but submits same tx hash to Gateway via Hot Wallet
	err = gwHelper.Contract.SubmitHotWalletDepositTxHash(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr)),
		&SubmitHotWalletDepositTxHashRequest{
			TxHash: txHash,
		},
	)
	require.NoError(err, "user should be able to submit tx hash")

	// 2. Oracle fetches tx hash and submit to Gateway
	err = gwHelper.Contract.ProcessEventBatch(gwHelper.ContractCtx(fakeCtx), &ProcessEventBatchRequest{
		Events: []*MainnetEvent{
			&MainnetEvent{
				EthBlock: 5,
				Payload: &MainnetDepositEvent{
					Deposit: &MainnetTokenDeposited{
						TokenKind:     TokenKind_ERC20,
						TokenContract: ethTokenAddr.MarshalPB(),
						TokenOwner:    ts.ethAddr.MarshalPB(),
						TokenAmount:   tokenAmount,
						TxHash:        txHash,
					},
				},
			},
		},
		MainnetGatewayAddress: ethTokenAddr4.MarshalPB(),
	})
	require.NoError(err)

	// 3. Oracle fetches same tx hash and submit to Gateway via Hot Wallet
	err = gwHelper.Contract.ProcessHotWalletEventBatch(gwHelper.ContractCtx(fakeCtx), &ProcessEventBatchRequest{
		Events: []*MainnetEvent{
			&MainnetEvent{
				EthBlock: 6,
				Payload: &MainnetDepositEvent{
					Deposit: &MainnetTokenDeposited{
						TokenKind:     TokenKind_ERC20,
						TokenContract: ethTokenAddr.MarshalPB(),
						TokenOwner:    ts.ethAddr.MarshalPB(),
						TokenAmount:   tokenAmount,
						TxHash:        txHash,
					},
				},
			},
		},
		MainnetHotWalletAddress: ethTokenAddr4.MarshalPB(),
	})
	require.NoError(err)

	amount, err := erc20.balanceOf(ts.dAppAddr)
	require.NoError(err)
	require.Equal(tokenAmount.Value.Int.String(), amount.String(),
		"user should have token amount on Dapp the same amount he deposits to Gateway")

	owner := ts.ethAddr

	gotTxHashes, err := loadHotWalletDepositTxHashes(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr)),
		owner,
	)
	require.NoError(err)
	require.NotContains(gotTxHashes.TxHashes, txHash,
		"Gateway should clear tx hash once Gateway processes tx")

	// # Use Case 2
	// User does approve transfer and also submits tx hash via Hot Wallet
	// Oracle submit hot wallet event batch first and event batch second

	txHash = []byte("0xdeadbeef2")

	// 1. User does ApproveTransfer via Gateway but submits same tx hash to Gateway via Hot Wallet
	err = gwHelper.Contract.SubmitHotWalletDepositTxHash(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr)),
		&SubmitHotWalletDepositTxHashRequest{
			TxHash: txHash,
		},
	)
	require.NoError(err, "user should be able to submit tx hash")

	// 2. Oracle fetches tx hash and submit to Gateway via Hot Wallet
	err = gwHelper.Contract.ProcessHotWalletEventBatch(gwHelper.ContractCtx(fakeCtx), &ProcessEventBatchRequest{
		Events: []*MainnetEvent{
			&MainnetEvent{
				EthBlock: 7,
				Payload: &MainnetDepositEvent{
					Deposit: &MainnetTokenDeposited{
						TokenKind:     TokenKind_ERC20,
						TokenContract: ethTokenAddr.MarshalPB(),
						TokenOwner:    ts.ethAddr.MarshalPB(),
						TokenAmount:   tokenAmount,
						TxHash:        txHash,
					},
				},
			},
		},
		MainnetHotWalletAddress: ethTokenAddr4.MarshalPB(),
	})
	require.NoError(err)

	// 3. Oracle fetches same tx hash and submit to Gateway
	err = gwHelper.Contract.ProcessEventBatch(gwHelper.ContractCtx(fakeCtx), &ProcessEventBatchRequest{
		Events: []*MainnetEvent{
			&MainnetEvent{
				EthBlock: 8,
				Payload: &MainnetDepositEvent{
					Deposit: &MainnetTokenDeposited{
						TokenKind:     TokenKind_ERC20,
						TokenContract: ethTokenAddr.MarshalPB(),
						TokenOwner:    ts.ethAddr.MarshalPB(),
						TokenAmount:   tokenAmount,
						TxHash:        txHash,
					},
				},
			},
		},
		MainnetGatewayAddress: ethTokenAddr4.MarshalPB(),
	})
	require.NoError(err)

	amount, err = erc20.balanceOf(ts.dAppAddr)
	require.NoError(err)
	// total amountt should be sum up from tx1 and tx2
	require.Equal(amount.String(), new(big.Int).Add(tokenAmount.Value.Int, tokenAmount.Value.Int).String(),
		"user should have token amount on Dapp the same amount he deposits to Gateway")

	gotTxHashes, err = loadHotWalletDepositTxHashes(
		gwHelper.ContractCtx(fakeCtx.WithSender(ts.dAppAddr)),
		owner,
	)
	require.NoError(err)
	require.NotContains(gotTxHashes.TxHashes, txHash,
		"Gateway should clear tx hash once Gateway processes tx")
}

func (ts *GatewayTestSuite) TestLoomCoinGatewayWithdrawalLimit() {
	require := ts.Require()
	ownerAddr := ts.dAppAddr
	oracleAddr := ts.dAppAddr2
	userEthAddr := ts.ethAddr3
	userDappAddr := ts.dAppAddr3
	user2EthAddr := ts.ethAddr4
	user2DappAddr := ts.dAppAddr4

	// fixed date
	now := time.Date(2019, 9, 26, 10, 0, 0, 0, time.UTC)
	block := types.BlockHeader{
		ChainID: "chain",
		Height:  int64(34),
		Time:    now.Unix(),
	}

	fakeCtx := plugin.CreateFakeContextWithEVM(oracleAddr, loom.RootAddress("chain")).WithBlock(block)
	fakeCtx = fakeCtx.WithFeature(features.TGWithdrawalLimitFeature, true)
	require.True(fakeCtx.FeatureEnabled(features.TGWithdrawalLimitFeature, false))

	addressMapper, err := deployAddressMapperContract(fakeCtx)
	require.NoError(err)

	// map user
	sig, err := address_mapper.SignIdentityMapping(userEthAddr, userDappAddr, ts.ethKey3, sigType)
	require.NoError(err)
	require.NoError(addressMapper.AddIdentityMapping(fakeCtx.WithSender(userDappAddr), userEthAddr, userDappAddr, sig))

	// map user2
	sig, err = address_mapper.SignIdentityMapping(user2EthAddr, user2DappAddr, ts.ethKey4, sigType)
	require.NoError(err)
	require.NoError(addressMapper.AddIdentityMapping(fakeCtx.WithSender(user2DappAddr), user2EthAddr, user2DappAddr, sig))

	gwHelper, err := deployGatewayContract(fakeCtx, &InitRequest{
		Owner:   ownerAddr.MarshalPB(),
		Oracles: []*types.Address{oracleAddr.MarshalPB()},
	}, LoomCoinGateway)
	require.NoError(err)

	// set max withdrawal limit amounts
	err = gwHelper.Contract.SetMaxWithdrawalLimit(
		gwHelper.ContractCtx(fakeCtx.WithSender(ownerAddr)),
		&SetMaxWithdrawalLimitRequest{
			MaxTotalDailyWithdrawalAmount:      &types.BigUInt{Value: *sciNot(150, 18)},
			MaxPerAccountDailyWithdrawalAmount: &types.BigUInt{Value: *sciNot(100, 18)},
		},
	)
	require.NoError(err)

	// deploy LOOM coin
	loomCoinContract, err := deployLoomCoinContract(fakeCtx)
	require.NoError(err)
	// depositing some loom coin to user address
	loomdeposits := genLoomCoinDepositsBigInt(
		loomCoinContract.Address,
		userEthAddr,
		[]uint64{71, 73, 75},
		[]int64{160, 239, 581},
	)
	err = gwHelper.Contract.ProcessEventBatch(
		gwHelper.ContractCtx(fakeCtx),
		&ProcessEventBatchRequest{
			Events: loomdeposits,
		})
	require.NoError(err)

	// depositing some loom coin to user2 address
	loomdeposits = genLoomCoinDepositsBigInt(
		loomCoinContract.Address,
		user2EthAddr,
		[]uint64{76, 77, 78},
		[]int64{100, 200, 300},
	)
	err = gwHelper.Contract.ProcessEventBatch(
		gwHelper.ContractCtx(fakeCtx),
		&ProcessEventBatchRequest{
			Events: loomdeposits,
		})
	require.NoError(err)

	// check balance user
	loomcoin := newcoinStaticContext(gwHelper.ContractCtx(fakeCtx))
	bal, err := loomcoin.balanceOf(userDappAddr)
	require.NoError(err)
	require.Equal(sciNot(160+239+581, 18).String(), bal.String(), "user should have deposited amount loomcoin")
	// check balance user2
	bal, err = loomcoin.balanceOf(user2DappAddr)
	require.NoError(err)
	require.Equal(sciNot(100+200+300, 18).String(), bal.String(), "user2 should have deposited amount loomcoin")

	// make sure we don't have unclaimed tokens
	resp, err := gwHelper.Contract.GetUnclaimedContractTokens(
		gwHelper.ContractCtx(fakeCtx),
		&GetUnclaimedContractTokensRequest{
			TokenAddress: loomCoinContract.Address.MarshalPB(),
		})
	require.NoError(err)
	require.Equal(loom.NewBigUIntFromInt(0), &resp.UnclaimedAmount.Value)

	// user withdraw the first amount
	withdrawalAmount := sciNot(50, 18)
	err = gwHelper.Contract.WithdrawLoomCoin(
		gwHelper.ContractCtx(fakeCtx.WithSender(userDappAddr)),
		&WithdrawLoomCoinRequest{
			TokenContract: loomcoin.contractAddr.MarshalPB(),
			Amount:        &types.BigUInt{Value: *withdrawalAmount},
			Recipient:     userEthAddr.MarshalPB(),
		})
	require.NoError(err, "user should be able to withdraw loomcoin if limit is not reached")

	// clear out pending withdrawal reciept
	err = gwHelper.Contract.ProcessEventBatch(
		gwHelper.ContractCtx(fakeCtx),
		&ProcessEventBatchRequest{
			Events: []*MainnetEvent{
				&MainnetEvent{
					EthBlock: 80,
					Payload: &MainnetWithdrawalEvent{
						Withdrawal: &MainnetTokenWithdrawn{
							TokenOwner:    userEthAddr.MarshalPB(),
							TokenContract: ethTokenAddr.MarshalPB(),
							TokenKind:     TokenKind_LoomCoin,
							TokenAmount:   &types.BigUInt{Value: *withdrawalAmount},
						},
					},
				},
			},
		})
	require.NoError(err)

	// user withdrawal the second amount
	// this should fail because the amount exceeds the account limit
	withdrawalAmount = sciNot(100, 18)
	err = gwHelper.Contract.WithdrawLoomCoin(
		gwHelper.ContractCtx(fakeCtx.WithSender(userDappAddr)),
		&WithdrawLoomCoinRequest{
			TokenContract: loomcoin.contractAddr.MarshalPB(),
			Amount:        &types.BigUInt{Value: *withdrawalAmount},
			Recipient:     userEthAddr.MarshalPB(),
		})
	require.EqualError(err, ErrAccountDailyWithdrawalLimitReached.Error())

	// user withdrawal the second amount
	// this shuould success because the withdrawal amount is still in the limit
	withdrawalAmount = sciNot(50, 18)
	err = gwHelper.Contract.WithdrawLoomCoin(
		gwHelper.ContractCtx(fakeCtx.WithSender(userDappAddr)),
		&WithdrawLoomCoinRequest{
			TokenContract: loomcoin.contractAddr.MarshalPB(),
			Amount:        &types.BigUInt{Value: *withdrawalAmount},
			Recipient:     userEthAddr.MarshalPB(),
		})
	require.NoError(err, "user should be able to withdraw loomcoin if limit is not reached")

	// clear out pending withdrawal reciept
	err = gwHelper.Contract.ProcessEventBatch(
		gwHelper.ContractCtx(fakeCtx),
		&ProcessEventBatchRequest{
			Events: []*MainnetEvent{
				&MainnetEvent{
					EthBlock: 85,
					Payload: &MainnetWithdrawalEvent{
						Withdrawal: &MainnetTokenWithdrawn{
							TokenOwner:    userEthAddr.MarshalPB(),
							TokenContract: ethTokenAddr.MarshalPB(),
							TokenKind:     TokenKind_LoomCoin,
							TokenAmount:   &types.BigUInt{Value: *withdrawalAmount},
						},
					},
				},
			},
		})
	require.NoError(err)

	// user withdrawal the third amount
	// this should fail because the amount exceeds the total limit
	withdrawalAmount = sciNot(100, 18)
	err = gwHelper.Contract.WithdrawLoomCoin(
		gwHelper.ContractCtx(fakeCtx.WithSender(userDappAddr)),
		&WithdrawLoomCoinRequest{
			TokenContract: loomcoin.contractAddr.MarshalPB(),
			Amount:        &types.BigUInt{Value: *withdrawalAmount},
			Recipient:     userEthAddr.MarshalPB(),
		})
	require.EqualError(err, ErrTotalDailyWithdrawalLimitReached.Error())

	// user2 withdrawal the first amount
	// this should fail because the amount exceeds the total limit
	withdrawalAmount = sciNot(100, 18)
	err = gwHelper.Contract.WithdrawLoomCoin(
		gwHelper.ContractCtx(fakeCtx.WithSender(user2DappAddr)),
		&WithdrawLoomCoinRequest{
			TokenContract: loomcoin.contractAddr.MarshalPB(),
			Amount:        &types.BigUInt{Value: *withdrawalAmount},
			Recipient:     user2EthAddr.MarshalPB(),
		})
	require.EqualError(err, ErrTotalDailyWithdrawalLimitReached.Error())

	// user2 withdrawal the second amount
	// this should success because the total/account withdrawal amount is still in the limit
	withdrawalAmount = sciNot(50, 18)
	err = gwHelper.Contract.WithdrawLoomCoin(
		gwHelper.ContractCtx(fakeCtx.WithSender(user2DappAddr)),
		&WithdrawLoomCoinRequest{
			TokenContract: loomcoin.contractAddr.MarshalPB(),
			Amount:        &types.BigUInt{Value: *withdrawalAmount},
			Recipient:     user2EthAddr.MarshalPB(),
		})
	require.NoError(err, "user should be able to withdraw loomcoin if limit is not reached")
	// clear out pending withdrawal reciept
	err = gwHelper.Contract.ProcessEventBatch(
		gwHelper.ContractCtx(fakeCtx),
		&ProcessEventBatchRequest{
			Events: []*MainnetEvent{
				&MainnetEvent{
					EthBlock: 90,
					Payload: &MainnetWithdrawalEvent{
						Withdrawal: &MainnetTokenWithdrawn{
							TokenOwner:    user2EthAddr.MarshalPB(),
							TokenContract: ethTokenAddr.MarshalPB(),
							TokenKind:     TokenKind_LoomCoin,
							TokenAmount:   &types.BigUInt{Value: *withdrawalAmount},
						},
					},
				},
			},
		})
	require.NoError(err)

	// forward the time 1 day
	now = now.Add(24 * time.Hour)
	block = types.BlockHeader{
		ChainID: "chain",
		Height:  int64(200),
		Time:    now.Unix(),
	}
	fakeCtx = fakeCtx.WithBlock(block)

	// user withdrawal the third amount
	// this should success because limit is reset
	withdrawalAmount = sciNot(50, 18)
	err = gwHelper.Contract.WithdrawLoomCoin(
		gwHelper.ContractCtx(fakeCtx.WithSender(userDappAddr)),
		&WithdrawLoomCoinRequest{
			TokenContract: loomcoin.contractAddr.MarshalPB(),
			Amount:        &types.BigUInt{Value: *withdrawalAmount},
			Recipient:     userEthAddr.MarshalPB(),
		})
	require.NoError(err)

	// user2 withdrawal the third amount
	// this should success because limit is reset
	withdrawalAmount = sciNot(50, 18)
	err = gwHelper.Contract.WithdrawLoomCoin(
		gwHelper.ContractCtx(fakeCtx.WithSender(user2DappAddr)),
		&WithdrawLoomCoinRequest{
			TokenContract: loomcoin.contractAddr.MarshalPB(),
			Amount:        &types.BigUInt{Value: *withdrawalAmount},
			Recipient:     user2EthAddr.MarshalPB(),
		})
	require.NoError(err)
}

func (ts *GatewayTestSuite) TestEthGatewayWithdrawalLimit() {
	require := ts.Require()
	ownerAddr := ts.dAppAddr
	oracleAddr := ts.dAppAddr2
	userEthAddr := ts.ethAddr3
	userDappAddr := ts.dAppAddr3
	user2EthAddr := ts.ethAddr4
	user2DappAddr := ts.dAppAddr4

	// fixed date
	now := time.Date(2019, 9, 26, 10, 0, 0, 0, time.UTC)
	block := types.BlockHeader{
		ChainID: "chain",
		Height:  int64(34),
		Time:    now.Unix(),
	}

	fakeCtx := plugin.CreateFakeContextWithEVM(oracleAddr, loom.RootAddress("chain")).WithBlock(block)
	fakeCtx = fakeCtx.WithFeature(features.TGWithdrawalLimitFeature, true)
	require.True(fakeCtx.FeatureEnabled(features.TGWithdrawalLimitFeature, false))

	addressMapper, err := deployAddressMapperContract(fakeCtx)
	require.NoError(err)

	// map user
	sig, err := address_mapper.SignIdentityMapping(userEthAddr, userDappAddr, ts.ethKey3, sigType)
	require.NoError(err)
	require.NoError(addressMapper.AddIdentityMapping(fakeCtx.WithSender(userDappAddr), userEthAddr, userDappAddr, sig))

	// map user2
	sig, err = address_mapper.SignIdentityMapping(user2EthAddr, user2DappAddr, ts.ethKey4, sigType)
	require.NoError(err)
	require.NoError(addressMapper.AddIdentityMapping(fakeCtx.WithSender(user2DappAddr), user2EthAddr, user2DappAddr, sig))

	gwHelper, err := deployGatewayContract(fakeCtx, &InitRequest{
		Owner:   ownerAddr.MarshalPB(),
		Oracles: []*types.Address{oracleAddr.MarshalPB()},
	}, EthereumGateway)
	require.NoError(err)

	// set max withdrawal limit amounts
	err = gwHelper.Contract.SetMaxWithdrawalLimit(
		gwHelper.ContractCtx(fakeCtx.WithSender(ownerAddr)),
		&SetMaxWithdrawalLimitRequest{
			MaxTotalDailyWithdrawalAmount:      &types.BigUInt{Value: *sciNot(150, 18)},
			MaxPerAccountDailyWithdrawalAmount: &types.BigUInt{Value: *sciNot(100, 18)},
		},
	)
	require.NoError(err)

	// deploy Eth coin
	ethCoinContract, err := deployETHContract(fakeCtx)
	require.NoError(err)
	// depositing some loom coin to user address
	loomdeposits := genEthDepositsBigInt(
		ethCoinContract.Address,
		userEthAddr,
		[]uint64{71, 73, 75},
		[]int64{160, 239, 581},
	)
	err = gwHelper.Contract.ProcessEventBatch(
		gwHelper.ContractCtx(fakeCtx),
		&ProcessEventBatchRequest{
			Events: loomdeposits,
		})
	require.NoError(err)

	// depositing some loom coin to user2 address
	loomdeposits = genEthDepositsBigInt(
		ethCoinContract.Address,
		user2EthAddr,
		[]uint64{76, 77, 78},
		[]int64{100, 200, 300},
	)
	err = gwHelper.Contract.ProcessEventBatch(
		gwHelper.ContractCtx(fakeCtx),
		&ProcessEventBatchRequest{
			Events: loomdeposits,
		})
	require.NoError(err)

	// check balance user
	ethcoin := newETHContext(contract.WrapPluginContext(fakeCtx.WithAddress(userDappAddr)))
	bal, err := ethcoin.balanceOf(userDappAddr)
	require.NoError(err)
	require.Equal(sciNot(160+239+581, 18).String(), bal.String(), "user should have deposited amount loomcoin")
	// check balance user2
	bal, err = ethcoin.balanceOf(user2DappAddr)
	require.NoError(err)
	require.Equal(sciNot(100+200+300, 18).String(), bal.String(), "user2 should have deposited amount loomcoin")

	// make sure we don't have unclaimed tokens
	resp, err := gwHelper.Contract.GetUnclaimedContractTokens(
		gwHelper.ContractCtx(fakeCtx),
		&GetUnclaimedContractTokensRequest{
			TokenAddress: ethCoinContract.Address.MarshalPB(),
		})
	require.NoError(err)
	require.Equal(loom.NewBigUIntFromInt(0), &resp.UnclaimedAmount.Value)

	userCoin := newETHContext(contract.WrapPluginContext(fakeCtx.WithAddress(userDappAddr)))
	user2Coin := newETHContext(contract.WrapPluginContext(fakeCtx.WithAddress(user2DappAddr)))

	// user withdraw the first amount
	withdrawalAmount := sciNot(50, 18)
	require.NoError(userCoin.approve(gwHelper.Address, withdrawalAmount.Int))
	err = gwHelper.Contract.WithdrawETH(
		gwHelper.ContractCtx(fakeCtx.WithSender(userDappAddr)),
		&WithdrawETHRequest{
			MainnetGateway: ethcoin.contractAddr.MarshalPB(),
			Amount:         &types.BigUInt{Value: *withdrawalAmount},
			Recipient:      userEthAddr.MarshalPB(),
		})
	require.NoError(err, "user should be able to withdraw loomcoin if limit is not reached")

	// clear out pending withdrawal reciept
	err = gwHelper.Contract.ProcessEventBatch(
		gwHelper.ContractCtx(fakeCtx),
		&ProcessEventBatchRequest{
			Events: []*MainnetEvent{
				&MainnetEvent{
					EthBlock: 80,
					Payload: &MainnetWithdrawalEvent{
						Withdrawal: &MainnetTokenWithdrawn{
							TokenOwner:    userEthAddr.MarshalPB(),
							TokenContract: ethTokenAddr.MarshalPB(),
							TokenKind:     TokenKind_ETH,
							TokenAmount:   &types.BigUInt{Value: *withdrawalAmount},
						},
					},
				},
			},
		})
	require.NoError(err)

	// user withdrawal the second amount
	// this should fail because the amount exceeds the account limit
	withdrawalAmount = sciNot(100, 18)
	require.NoError(userCoin.approve(gwHelper.Address, withdrawalAmount.Int))
	err = gwHelper.Contract.WithdrawETH(
		gwHelper.ContractCtx(fakeCtx.WithSender(userDappAddr)),
		&WithdrawETHRequest{
			MainnetGateway: ethcoin.contractAddr.MarshalPB(),
			Amount:         &types.BigUInt{Value: *withdrawalAmount},
			Recipient:      userEthAddr.MarshalPB(),
		})
	require.EqualError(err, ErrAccountDailyWithdrawalLimitReached.Error())

	// user withdrawal the second amount
	// this shuould success because the withdrawal amount is still in the limit
	withdrawalAmount = sciNot(50, 18)
	require.NoError(userCoin.approve(gwHelper.Address, withdrawalAmount.Int))
	err = gwHelper.Contract.WithdrawETH(
		gwHelper.ContractCtx(fakeCtx.WithSender(userDappAddr)),
		&WithdrawETHRequest{
			MainnetGateway: ethcoin.contractAddr.MarshalPB(),
			Amount:         &types.BigUInt{Value: *withdrawalAmount},
			Recipient:      userEthAddr.MarshalPB(),
		})
	require.NoError(err, "user should be able to withdraw loomcoin if limit is not reached")

	// clear out pending withdrawal reciept
	err = gwHelper.Contract.ProcessEventBatch(
		gwHelper.ContractCtx(fakeCtx),
		&ProcessEventBatchRequest{
			Events: []*MainnetEvent{
				&MainnetEvent{
					EthBlock: 85,
					Payload: &MainnetWithdrawalEvent{
						Withdrawal: &MainnetTokenWithdrawn{
							TokenOwner:    userEthAddr.MarshalPB(),
							TokenContract: ethTokenAddr.MarshalPB(),
							TokenKind:     TokenKind_ETH,
							TokenAmount:   &types.BigUInt{Value: *withdrawalAmount},
						},
					},
				},
			},
		})
	require.NoError(err)

	// user withdrawal the third amount
	// this should fail because the amount exceeds the total limit
	withdrawalAmount = sciNot(100, 18)
	require.NoError(userCoin.approve(gwHelper.Address, withdrawalAmount.Int))
	err = gwHelper.Contract.WithdrawETH(
		gwHelper.ContractCtx(fakeCtx.WithSender(userDappAddr)),
		&WithdrawETHRequest{
			MainnetGateway: ethcoin.contractAddr.MarshalPB(),
			Amount:         &types.BigUInt{Value: *withdrawalAmount},
			Recipient:      userEthAddr.MarshalPB(),
		})
	require.EqualError(err, ErrTotalDailyWithdrawalLimitReached.Error())

	// user2 withdrawal the first amount
	// this should fail because the amount exceeds the total limit
	withdrawalAmount = sciNot(100, 18)
	require.NoError(user2Coin.approve(gwHelper.Address, withdrawalAmount.Int))
	err = gwHelper.Contract.WithdrawETH(
		gwHelper.ContractCtx(fakeCtx.WithSender(user2DappAddr)),
		&WithdrawETHRequest{
			MainnetGateway: ethcoin.contractAddr.MarshalPB(),
			Amount:         &types.BigUInt{Value: *withdrawalAmount},
			Recipient:      user2EthAddr.MarshalPB(),
		})
	require.EqualError(err, ErrTotalDailyWithdrawalLimitReached.Error())

	// user2 withdrawal the second amount
	// this should success because the total/account withdrawal amount is still in the limit
	withdrawalAmount = sciNot(50, 18)
	require.NoError(user2Coin.approve(gwHelper.Address, withdrawalAmount.Int))
	err = gwHelper.Contract.WithdrawETH(
		gwHelper.ContractCtx(fakeCtx.WithSender(user2DappAddr)),
		&WithdrawETHRequest{
			MainnetGateway: ethcoin.contractAddr.MarshalPB(),
			Amount:         &types.BigUInt{Value: *withdrawalAmount},
			Recipient:      user2EthAddr.MarshalPB(),
		})
	require.NoError(err, "user should be able to withdraw loomcoin if limit is not reached")
	// clear out pending withdrawal reciept
	err = gwHelper.Contract.ProcessEventBatch(
		gwHelper.ContractCtx(fakeCtx),
		&ProcessEventBatchRequest{
			Events: []*MainnetEvent{
				&MainnetEvent{
					EthBlock: 90,
					Payload: &MainnetWithdrawalEvent{
						Withdrawal: &MainnetTokenWithdrawn{
							TokenOwner:    user2EthAddr.MarshalPB(),
							TokenContract: ethTokenAddr.MarshalPB(),
							TokenKind:     TokenKind_ETH,
							TokenAmount:   &types.BigUInt{Value: *withdrawalAmount},
						},
					},
				},
			},
		})
	require.NoError(err)

	// forward the time 1 day
	now = now.Add(24 * time.Hour)
	block = types.BlockHeader{
		ChainID: "chain",
		Height:  int64(200),
		Time:    now.Unix(),
	}
	fakeCtx = fakeCtx.WithBlock(block)

	// user withdrawal the third amount
	// this should success because limit is reset
	withdrawalAmount = sciNot(50, 18)
	require.NoError(userCoin.approve(gwHelper.Address, withdrawalAmount.Int))
	err = gwHelper.Contract.WithdrawETH(
		gwHelper.ContractCtx(fakeCtx.WithSender(userDappAddr)),
		&WithdrawETHRequest{
			MainnetGateway: ethcoin.contractAddr.MarshalPB(),
			Amount:         &types.BigUInt{Value: *withdrawalAmount},
			Recipient:      userEthAddr.MarshalPB(),
		})
	require.NoError(err)

	// user2 withdrawal the third amount
	// this should success because limit is reset
	withdrawalAmount = sciNot(50, 18)
	require.NoError(user2Coin.approve(gwHelper.Address, withdrawalAmount.Int))
	err = gwHelper.Contract.WithdrawETH(
		gwHelper.ContractCtx(fakeCtx.WithSender(user2DappAddr)),
		&WithdrawETHRequest{
			MainnetGateway: ethcoin.contractAddr.MarshalPB(),
			Amount:         &types.BigUInt{Value: *withdrawalAmount},
			Recipient:      user2EthAddr.MarshalPB(),
		})
	require.NoError(err)
}

func (ts *GatewayTestSuite) TestBinanceGatewayLoomCoinBEP2PrecisionAdjustment() {
	require := ts.Require()
	ownerAddr := ts.dAppAddr
	oracleAddr := ts.dAppAddr2
	loomcoinOwnerAddr := ts.dAppAddr3
	loomcoinGWOwnerAddr := ts.dAppAddr4
	aliceForeignAddr := ts.binanceAddr
	aliceDappAddr := ts.dAppAddr5

	fakeCtx := plugin.CreateFakeContextWithEVM(oracleAddr, loom.RootAddress("chain"))
	fakeCtx = fakeCtx.WithFeature(features.TGVersion1_3, true)
	require.True(fakeCtx.FeatureEnabled(features.TGVersion1_3, false))
	fakeCtx = fakeCtx.WithFeature(features.CoinVersion1_3Feature, true)
	require.True(fakeCtx.FeatureEnabled(features.CoinVersion1_3Feature, false))
	// TODO: Cleanup this clusterfuck later, FakeContextWithEVM.WithFeature stores features in FakeContext.data,
	//       but FakeContext.SetFeature stores them in FakeContext.features, then at some point the
	//       Coin contract somehow ends up with a reference to the FakeContext instead of the FakeContextWithEVM.
	fakeCtx.FakeContext.SetFeature(features.TGVersion1_3, true)
	fakeCtx.FakeContext.SetFeature(features.CoinVersion1_3Feature, true)
	fakeCtx.FakeContext.SetFeature(features.TGVersion1_4, true)

	addressMapper, err := deployAddressMapperContract(fakeCtx)
	require.NoError(err)

	sig, err := address_mapper.SignIdentityMapping(aliceForeignAddr, aliceDappAddr, ts.binanceKey, sigType)
	require.NoError(err)

	require.NoError(addressMapper.AddIdentityMapping(fakeCtx.WithSender(aliceDappAddr), aliceForeignAddr, aliceDappAddr, sig))

	gwHelper, err := deployGatewayContract(fakeCtx, &InitRequest{
		Owner:   ownerAddr.MarshalPB(),
		Oracles: []*types.Address{oracleAddr.MarshalPB()},
	}, BinanceGateway)
	require.NoError(err)

	loomCoinGwHelper, err := deployGatewayContract(fakeCtx, &InitRequest{
		Owner:   loomcoinGWOwnerAddr.MarshalPB(),
		Oracles: []*types.Address{oracleAddr.MarshalPB()},
	}, LoomCoinGateway)
	require.NoError(err)
	fmt.Println("Loom Coin Gatway At", loomCoinGwHelper.Address)

	acct1 := &coin.InitialAccount{
		Owner:   loomcoinOwnerAddr.MarshalPB(),
		Balance: 1000000000,
	}
	loomcoinContract, err := deployLoomCoinContract(fakeCtx, acct1)
	require.NoError(err)

	// deploy erc20 coin for sampleBNBToken
	dappTokenAddr2, err := deployTokenContract(fakeCtx, "SampleBNBToken", gwHelper.Address, ts.dAppAddr2)
	require.NoError(err)
	require.NoError(gwHelper.AddContractMapping(fakeCtx, binanceBNBAddr, dappTokenAddr2))

	loomcoin := newCoinContext(contract.WrapPluginContext(fakeCtx.WithAddress(loomcoinOwnerAddr)))
	// Transfer some Loom amount from coin creator to Gateway to make sure
	// Gateway has enough money for withdrawals without minting tokens
	startingAmount := sciNot(10000, 18)
	require.NoError(loomcoin.transfer(
		gwHelper.Address,
		startingAmount.Int,
	))

	fmt.Println(loomcoin.balanceOf(loomcoinContract.Address))

	// BEP2 8-digit decimals amount
	depositAmount := sciNot(314, 8)
	adjustedDepositAmount, err := adjustTokenAmount(depositAmount.Int, 8, 18)
	require.NoError(err)

	err = gwHelper.Contract.ProcessEventBatch(gwHelper.ContractCtx(fakeCtx), &ProcessEventBatchRequest{
		Events: []*MainnetEvent{
			&MainnetEvent{
				EthBlock: 50,
				Payload: &MainnetDepositEvent{
					Deposit: &MainnetTokenDeposited{
						TokenKind:     TokenKind_BNBLoomToken,
						TokenContract: loomcoin.contractAddr.MarshalPB(),
						TokenOwner:    aliceDappAddr.MarshalPB(),
						TokenAmount:   &types.BigUInt{Value: *depositAmount},
					},
				},
			},
		},
	})
	require.NoError(err)

	bal, err := loomcoin.balanceOf(aliceDappAddr)
	require.NoError(err)
	require.Equal(
		adjustedDepositAmount.String(),
		bal.String(),
		"LoomCoin deposited amount should be adjusted after depositing")

	resp, err := gwHelper.Contract.GetUnclaimedContractTokens(
		gwHelper.ContractCtx(fakeCtx),
		&GetUnclaimedContractTokensRequest{
			TokenAddress: loomcoinContract.Address.MarshalPB(),
		},
	)
	require.NoError(err)
	require.Equal(loom.NewBigUIntFromInt(0), &resp.UnclaimedAmount.Value)

	// depositing BNB from binance
	bep2BNBamountsByBlock := []int64{37500}
	bep2BNBdeposits := genBEP2DepositsFromBinance(
		binanceBNBAddr,
		aliceDappAddr,
		[]uint64{78},
		bep2BNBamountsByBlock,
	)

	err = gwHelper.Contract.ProcessEventBatch(gwHelper.ContractCtx(fakeCtx), &ProcessEventBatchRequest{
		Events: bep2BNBdeposits,
	})
	require.NoError(err)

	erc20bnb := newERC20Context(contract.WrapPluginContext(fakeCtx.WithAddress(aliceDappAddr)), dappTokenAddr2)
	balbnb, err := erc20bnb.balanceOf(aliceDappAddr)
	require.NoError(err)
	require.Equal(int64(37500), balbnb.Int64()) // we gain no decimals as this erc20 bnb token contract has 8 decimals

	require.NoError(erc20bnb.approve(gwHelper.Address, big.NewInt(37500)))

	invalidWithdrawalAmount := sciNot(314, 8) // 3.14x10^10
	err = gwHelper.Contract.WithdrawLoomCoin(
		gwHelper.ContractCtx(fakeCtx.WithSender(aliceDappAddr)),
		&WithdrawLoomCoinRequest{
			TokenContract: loomcoin.contractAddr.MarshalPB(),
			Amount:        &types.BigUInt{Value: *invalidWithdrawalAmount},
			Recipient:     aliceForeignAddr.MarshalPB(),
		},
	)
	require.Error(err)
	invalidWithdrawalAmount = sciNot(1, 7) // 0.1x10^8
	err = gwHelper.Contract.WithdrawLoomCoin(
		gwHelper.ContractCtx(fakeCtx.WithSender(aliceDappAddr)),
		&WithdrawLoomCoinRequest{
			TokenContract: loomcoin.contractAddr.MarshalPB(),
			Amount:        &types.BigUInt{Value: *invalidWithdrawalAmount},
			Recipient:     aliceForeignAddr.MarshalPB(),
		},
	)
	require.Error(err)

	// LoomCoin 18-digit decimals amount
	withdrawalAmount := sciNot(314, 18)
	// Alice withdraw LoomCoin from dAppChain Gateway
	err = gwHelper.Contract.WithdrawLoomCoin(
		gwHelper.ContractCtx(fakeCtx.WithSender(aliceDappAddr)),
		&WithdrawLoomCoinRequest{
			TokenContract: loomcoin.contractAddr.MarshalPB(),
			Amount:        &types.BigUInt{Value: *withdrawalAmount},
			Recipient:     aliceForeignAddr.MarshalPB(),
		},
	)
	require.NoError(err)

	receipt, err := gwHelper.Contract.WithdrawalReceipt(
		gwHelper.ContractCtx(fakeCtx.WithSender(aliceDappAddr)),
		&WithdrawalReceiptRequest{
			Owner: aliceDappAddr.MarshalPB(),
		},
	)
	require.NoError(err)
	require.Equal(big.NewInt(0).Div(withdrawalAmount.Int, big.NewInt(10000000000)).String(),
		receipt.Receipt.TokenAmount.Value.Int.String(),
		"Token amount in the receipt should be adjusted from LoomCoin to BEP2 decimals",
	)

	err = gwHelper.Contract.ProcessEventBatch(gwHelper.ContractCtx(fakeCtx), &ProcessEventBatchRequest{
		Events: []*MainnetEvent{
			&MainnetEvent{
				EthBlock: 80,
				Payload: &MainnetWithdrawalEvent{
					Withdrawal: &MainnetTokenWithdrawn{
						TokenKind:     TokenKind_BNBLoomToken,
						TokenContract: loomcoin.contractAddr.MarshalPB(),
						TokenOwner:    aliceForeignAddr.MarshalPB(),
						TokenAmount:   &types.BigUInt{Value: *loom.NewBigUInt(withdrawalAmount.Int)},
					},
				},
			},
		},
	})
	require.NoError(err)

	balanceAfter, err := loomcoin.balanceOf(aliceDappAddr)
	require.NoError(err)
	require.Equal(big.NewInt(0).String(),
		balanceAfter.String(),
		"Balance should be zero after withdrawal of full deposited amount")
}

func TestPrecisionAdjustment(t *testing.T) {
	tests := []struct {
		fromDecimals uint8
		toDecimals   uint8
		fromAmount   *big.Int
		toAmount     *big.Int
		expectErr    bool
	}{
		// integral
		{8, 8, sciNot(1, 8).Int, sciNot(1, 8).Int, false},
		{18, 18, sciNot(1, 18).Int, sciNot(1, 18).Int, false},
		{18, 8, sciNot(1, 18).Int, sciNot(1, 8).Int, false},
		{18, 10, sciNot(1, 18).Int, sciNot(1, 10).Int, false},
		{8, 18, sciNot(1, 8).Int, sciNot(1, 18).Int, false},
		{18, 8, sciNot(0, 18).Int, sciNot(0, 8).Int, false},
		// fractional
		{8, 8, sciNot(314, 6).Int, sciNot(314, 6).Int, false},
		{18, 18, sciNot(314, 16).Int, sciNot(314, 16).Int, false},
		{18, 8, sciNot(314, 16).Int, sciNot(314, 6).Int, false},
		{18, 10, sciNot(314, 16).Int, sciNot(314, 8).Int, false},
		{8, 18, sciNot(314, 6).Int, sciNot(314, 16).Int, false},
		// expect error
		{18, 8, sciNot(314, 6).Int, sciNot(0, 0).Int, true}, // 3.14x10^8
		{18, 8, sciNot(1, 7).Int, sciNot(0, 0).Int, true},   // 0.1x10^8
		{18, 8, sciNot(314, 8).Int, sciNot(3, 0).Int, true}, // 3.14x10^8 the fraction loss
	}

	for i, test := range tests {
		toAmount, err := adjustTokenAmount(test.fromAmount, test.fromDecimals, test.toDecimals)
		require.Equal(t, test.expectErr, err != nil)
		require.Equal(t, 0, toAmount.Cmp(test.toAmount),
			"test:%d fromDecimals %d, toDecimals %d, fromAmount %s, toAmount %s -- got %s",
			i+1, test.fromDecimals, test.toDecimals, test.fromAmount, test.toAmount, toAmount)
	}
}

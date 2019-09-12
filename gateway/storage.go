package gateway

import (
	"github.com/gogo/protobuf/proto"
	loom "github.com/loomnetwork/go-loom"
	ltypes "github.com/loomnetwork/go-loom/types"
	"github.com/loomnetwork/go-loom/util"
	"github.com/loomnetwork/loomchain/db"
)

var (
	// Store keys
	stateKey         = []byte("state")
	accountKeyPrefix = []byte("account")
)

func accountKey(owner loom.Address) []byte {
	return util.PrefixKey(accountKeyPrefix, owner.Bytes())
}

func loadState(dbm db.DBWrapper) (*OracleState, error) {
	state := OracleState{
		TotalWithdrawalAmount: &ltypes.BigUInt{Value: *loom.NewBigUIntFromInt(0)},
	}
	data := dbm.Get(stateKey)
	if data == nil {
		return &state, nil
	}
	if err := proto.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

func saveState(dbm db.DBWrapper, state *OracleState) error {
	data, err := proto.Marshal(state)
	if err != nil {
		return err
	}
	dbm.Set(stateKey, data)
	return nil
}

func loadAccount(dbm db.DBWrapper, owner loom.Address) (*Account, error) {
	account := Account{
		Owner:                 owner.MarshalPB(),
		TotalWithdrawalAmount: &ltypes.BigUInt{Value: *loom.NewBigUIntFromInt(0)},
	}
	data := dbm.Get(accountKey(owner))
	if data == nil {
		return &account, nil
	}
	if err := proto.Unmarshal(data, &account); err != nil {
		return nil, err
	}
	return &account, nil
}

func saveAccount(dbm db.DBWrapper, acct *Account) error {
	data, err := proto.Marshal(acct)
	if err != nil {
		return err
	}
	ownerAddr := loom.UnmarshalAddressPB(acct.Owner)
	dbm.Set(accountKey(ownerAddr), data)
	return nil
}

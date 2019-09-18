// +build evm

package gateway

import (
	"os"
	"path"
	"testing"
	"time"

	loom "github.com/loomnetwork/go-loom"
	dbm "github.com/loomnetwork/loomchain/db"
	"github.com/stretchr/testify/require"
)

func TestRecentHashPool(t *testing.T) {
	recentHashPool := newRecentHashPool(4 * time.Second)
	recentHashPool.startCleanupRoutine()

	require.True(t, recentHashPool.addHash([]byte{1, 2, 3}), "adding hash for first time should succed")

	require.False(t, recentHashPool.addHash([]byte{1, 2, 3}), "adding duplicate hash shouldnt be allowed")

	time.Sleep(5 * time.Second)

	require.True(t, recentHashPool.addHash([]byte{1, 2, 3}), "after timeout, hash should be allowed")
}

func TestTransferGatewayOracleMainnetEventSort(t *testing.T) {
	events := []*mainnetEventInfo{
		&mainnetEventInfo{BlockNum: 5, TxIdx: 0},
		&mainnetEventInfo{BlockNum: 5, TxIdx: 1},
		&mainnetEventInfo{BlockNum: 5, TxIdx: 4},
		&mainnetEventInfo{BlockNum: 3, TxIdx: 3},
		&mainnetEventInfo{BlockNum: 3, TxIdx: 7},
		&mainnetEventInfo{BlockNum: 3, TxIdx: 1},
		&mainnetEventInfo{BlockNum: 8, TxIdx: 4},
		&mainnetEventInfo{BlockNum: 8, TxIdx: 1},
		&mainnetEventInfo{BlockNum: 9, TxIdx: 0},
		&mainnetEventInfo{BlockNum: 10, TxIdx: 5},
		&mainnetEventInfo{BlockNum: 1, TxIdx: 2},
	}
	sortedEvents := []*mainnetEventInfo{
		&mainnetEventInfo{BlockNum: 1, TxIdx: 2},
		&mainnetEventInfo{BlockNum: 3, TxIdx: 1},
		&mainnetEventInfo{BlockNum: 3, TxIdx: 3},
		&mainnetEventInfo{BlockNum: 3, TxIdx: 7},
		&mainnetEventInfo{BlockNum: 5, TxIdx: 0},
		&mainnetEventInfo{BlockNum: 5, TxIdx: 1},
		&mainnetEventInfo{BlockNum: 5, TxIdx: 4},
		&mainnetEventInfo{BlockNum: 8, TxIdx: 1},
		&mainnetEventInfo{BlockNum: 8, TxIdx: 4},
		&mainnetEventInfo{BlockNum: 9, TxIdx: 0},
		&mainnetEventInfo{BlockNum: 10, TxIdx: 5},
	}
	sortMainnetEvents(events)
	require.EqualValues(t, sortedEvents, events, "wrong sort order")
}

func TestTransferGatewayOracleConfigWithdrawerAddressBlacklist(t *testing.T) {
	cfg := DefaultConfig(8888)
	addr1 := loom.MustParseAddress("chain:0xb16a379ec18d4093666f8f38b11a3071c920207d")
	addr2 := loom.MustParseAddress("chain:0x5cecd1f7261e1f4c684e297be3edf03b825e01c5")
	cfg.WithdrawerAddressBlacklist = []string{
		addr1.String(),
		addr2.String(),
	}
	blacklist, err := cfg.GetWithdrawerAddressBlacklist()
	require.NoError(t, err)
	require.Equal(t, 2, len(blacklist))
	require.Equal(t, 0, addr1.Compare(blacklist[0]))
	require.Equal(t, 0, addr2.Compare(blacklist[1]))
}

func TestTransferGatewayOracleWithdrawalLimit(t *testing.T) {
	dbName := "oracle-test"
	// make sure we start up wit fresh data
	require.NoError(t, os.RemoveAll(path.Join("testdata", dbName+".db")))

	db, err := dbm.LoadDB(
		"goleveldb",
		dbName,
		"testdata",
		256,
		4,
		false,
	)
	require.NoError(t, err)
	// FIXME: doesn't actually work
	defer os.RemoveAll(path.Join("testdata", dbName+".db"))

	orc := Oracle{
		cfg: TransferGatewayConfig{
			WithdrawalLimitsEnabled: true,
		},
		db:                                 db,
		maxTotalDailyWithdrawalAmount:      sciNot(10, 18),
		maxPerAccountDailyWithdrawalAmount: sciNot(5, 18),
		logger: loom.NewLoomLogger("info", "file://-"),
	}

	t.Run("Total daily withdrawal", func(t *testing.T) {
		state, err := loadState(orc.db)
		require.NoError(t, err)

		// Use fixed time to avoid timing dependency issue
		ts1 := time.Date(2019, 8, 11, 0, 0, 0, 0, time.UTC)
		limitReached := orc.verifyTotalDailyWithdrawal(ts1, state, sciNot(6, 18).Int)
		require.False(t, limitReached)

		limitReached = orc.verifyTotalDailyWithdrawal(ts1, state, sciNot(20, 18).Int)
		require.True(t, limitReached,
			"Oracle should not allow withdrawal with the amount more than max total daily amount")

		ts2 := ts1.Add(4 * time.Hour)
		require.NoError(t, orc.updateOracleState(ts2, state, sciNot(6, 18).Int))

		state, err = loadState(orc.db)
		require.NoError(t, err)
		require.Equal(t,
			sciNot(6, 18).Int.String(),
			state.TotalWithdrawalAmount.Value.Int.String(),
			"Oracle should update the state")

		ts3 := ts1.Add(5 * time.Hour)
		limitReached = orc.verifyTotalDailyWithdrawal(ts3, state, sciNot(7, 18).Int)
		require.True(t, limitReached,
			"Oracle should not allow withdrawal with the amount more than max total daily amount")

		ts4 := ts1.Add(29 * time.Hour) // period should reset
		limitReached = orc.verifyTotalDailyWithdrawal(ts4, state, sciNot(7, 18).Int)
		require.False(t, limitReached)

		limitReached = orc.verifyTotalDailyWithdrawal(ts4, state, sciNot(20, 18).Int)
		require.True(t, limitReached,
			"Oracle should not allow withdrawal with the amount more than max total daily amount")

		require.NoError(t, orc.updateOracleState(ts4, state, sciNot(7, 18).Int))
		state, err = loadState(orc.db)
		require.NoError(t, err)
		require.Equal(t,
			sciNot(7, 18).Int.String(),
			state.TotalWithdrawalAmount.Value.Int.String(),
			"Oracle should update the state")
	})

	t.Run("Total per account (local) withdrawal", func(t *testing.T) {
		addr1 := loom.MustParseAddress("chain:0xb16a379ec18d4093666f8f38b11a3071c920207d")
		addr2 := loom.MustParseAddress("chain:0x5cecd1f7261e1f4c684e297be3edf03b825e01c5")

		// Use fixed time to avoid timing dependency issue
		ts1 := time.Date(2019, 9, 12, 7, 20, 0, 0, time.UTC)
		localAccount, err := loadAccount(orc.db, addr1)
		require.NoError(t, err)
		limitReached := orc.verifyAccountDailyWithdrawal(ts1, localAccount, sciNot(3, 18).Int)
		require.False(t, limitReached)

		localAccount2, err := loadAccount(orc.db, addr2)
		require.NoError(t, err)
		limitReached = orc.verifyAccountDailyWithdrawal(ts1, localAccount2, sciNot(4, 18).Int)
		require.False(t, limitReached)

		limitReached = orc.verifyAccountDailyWithdrawal(ts1, localAccount, sciNot(10, 18).Int)
		require.True(t, limitReached,
			"Oracle should not allow withdrawal with the amount more than max total daily amount")
		limitReached = orc.verifyAccountDailyWithdrawal(ts1, localAccount2, sciNot(20, 18).Int)
		require.True(t, limitReached,
			"Oracle should not allow withdrawal with the amount more than max total daily amount")

		ts2 := ts1.Add(4 * time.Hour)
		require.NoError(t, orc.updateAccountState(ts2, localAccount, sciNot(3, 18).Int))
		require.NoError(t, orc.updateAccountState(ts2, localAccount2, sciNot(4, 18).Int))

		localAccount, err = loadAccount(orc.db, addr1)
		require.NoError(t, err)
		require.Equal(t,
			sciNot(3, 18).Int.String(),
			localAccount.TotalWithdrawalAmount.Value.Int.String(),
			"Total withdrawl amount should've been persisted")
		localAccount2, err = loadAccount(orc.db, addr2)
		require.NoError(t, err)
		require.Equal(t,
			sciNot(4, 18).Int.String(),
			localAccount2.TotalWithdrawalAmount.Value.Int.String(),
			"Total withdrawl amount should've been persisted")

		ts3 := ts1.Add(5 * time.Hour)
		limitReached = orc.verifyAccountDailyWithdrawal(ts3, localAccount, sciNot(3, 18).Int)
		require.True(t, limitReached,
			"Oracle should not allow withdrawal with the amount more than max total daily amount")
		limitReached = orc.verifyAccountDailyWithdrawal(ts3, localAccount2, sciNot(4, 18).Int)
		require.True(t, limitReached,
			"Oracle should not allow withdrawal with the amount more than max total daily amount")

		// Reset time by at the next day from ts1 00:00:01 UTC
		ts4 := ts1.Add(24 * time.Hour).Add(time.Second)
		limitReached = orc.verifyAccountDailyWithdrawal(ts4, localAccount, sciNot(3, 18).Int)
		require.False(t, limitReached)
		limitReached = orc.verifyAccountDailyWithdrawal(ts4, localAccount2, sciNot(4, 18).Int)
		require.False(t, limitReached)

		limitReached = orc.verifyAccountDailyWithdrawal(ts4, localAccount, sciNot(10, 18).Int)
		require.True(t, limitReached,
			"Oracle should not allow withdrawal with the amount more than max total daily amount")
		limitReached = orc.verifyAccountDailyWithdrawal(ts4, localAccount2, sciNot(20, 18).Int)
		require.True(t, limitReached,
			"Oracle should not allow withdrawal with the amount more than max total daily amount")

		require.NoError(t, orc.updateAccountState(ts4, localAccount, sciNot(3, 18).Int))
		localAccount, err = loadAccount(orc.db, addr1)
		require.NoError(t, err)
		require.Equal(t,
			sciNot(3, 18).Int.String(),
			localAccount.TotalWithdrawalAmount.Value.Int.String(),
			"Oracle should update the state")

		require.NoError(t, orc.updateAccountState(ts4, localAccount2, sciNot(4, 18).Int))
		localAccount2, err = loadAccount(orc.db, addr2)
		require.NoError(t, err)
		require.Equal(t,
			sciNot(4, 18).Int.String(),
			localAccount2.TotalWithdrawalAmount.Value.Int.String(),
			"Oracle should update the state")
	})

	t.Run("Total per account (foreign) withdrawal", func(t *testing.T) {
		addr1 := loom.MustParseAddress("chain:0xfa4c7920accfd66b86f5fd0e69682a79f762d49e")
		addr2 := loom.MustParseAddress("eth:0xb16a379ec18d4093666f8f38b11a3071c920207d")

		localAccount, err := loadAccount(orc.db, addr1)
		require.NoError(t, err)
		foreignAccount, err := loadAccount(orc.db, addr2)
		require.NoError(t, err)

		// Use fixed time to avoid timing dependency issue
		ts1 := time.Date(2019, 10, 11, 2, 30, 0, 0, time.UTC)
		limitReached := orc.verifyAccountDailyWithdrawal(ts1, localAccount, sciNot(3, 18).Int)
		require.False(t, limitReached)
		limitReached = orc.verifyAccountDailyWithdrawal(ts1, foreignAccount, sciNot(3, 18).Int)
		require.False(t, limitReached)

		limitReached = orc.verifyAccountDailyWithdrawal(ts1, localAccount, sciNot(10, 18).Int)
		require.True(t, limitReached,
			"Oracle should not allow withdrawal with the amount more than max total daily amount")
		limitReached = orc.verifyAccountDailyWithdrawal(ts1, foreignAccount, sciNot(10, 18).Int)
		require.True(t, limitReached,
			"Oracle should not allow withdrawal with the amount more than max total daily amount")

		ts2 := ts1.Add(4 * time.Hour)
		require.NoError(t, orc.updateAccountState(ts2, localAccount, sciNot(3, 18).Int))
		require.NoError(t, orc.updateAccountState(ts2, foreignAccount, sciNot(3, 18).Int))

		localAccount, err = loadAccount(orc.db, addr1)
		require.NoError(t, err)
		require.Equal(t,
			sciNot(3, 18).Int.String(),
			localAccount.TotalWithdrawalAmount.Value.Int.String(),
			"Oracle should update the state")
		state2, err := loadAccount(orc.db, addr2)
		require.NoError(t, err)
		require.Equal(t,
			sciNot(3, 18).Int.String(),
			state2.TotalWithdrawalAmount.Value.Int.String(),
			"Oracle should update the state")

		ts3 := ts1.Add(5 * time.Hour)
		limitReached = orc.verifyAccountDailyWithdrawal(ts3, localAccount, sciNot(3, 18).Int)
		require.True(t, limitReached,
			"Oracle should not allow withdrawal with the amount more than max total daily amount")
		limitReached = orc.verifyAccountDailyWithdrawal(ts3, foreignAccount, sciNot(3, 18).Int)
		require.True(t, limitReached,
			"Oracle should not allow withdrawal with the amount more than max total daily amount")

		// Reset time by at the next day from ts1 00:00:01 UTC
		ts4 := ts1.Add(24 * time.Hour).Add(time.Second)
		limitReached = orc.verifyAccountDailyWithdrawal(ts4, localAccount, sciNot(3, 18).Int)
		require.False(t, limitReached)
		limitReached = orc.verifyAccountDailyWithdrawal(ts4, foreignAccount, sciNot(3, 18).Int)
		require.False(t, limitReached)

		limitReached = orc.verifyAccountDailyWithdrawal(ts4, localAccount, sciNot(10, 18).Int)
		require.True(t, limitReached,
			"Oracle should not allow withdrawal with the amount more than max total daily amount")
		limitReached = orc.verifyAccountDailyWithdrawal(ts4, foreignAccount, sciNot(10, 18).Int)
		require.True(t, limitReached,
			"Oracle should not allow withdrawal with the amount more than max total daily amount")

		require.NoError(t, orc.updateAccountState(ts4, localAccount, sciNot(3, 18).Int))
		localAccount, err = loadAccount(orc.db, addr1)
		require.NoError(t, err)
		require.Equal(t,
			sciNot(3, 18).Int.String(),
			localAccount.TotalWithdrawalAmount.Value.Int.String(),
			"Oracle should update the state")

		require.NoError(t, orc.updateAccountState(ts4, foreignAccount, sciNot(3, 18).Int))
		state2, err = loadAccount(orc.db, addr2)
		require.NoError(t, err)
		require.Equal(t,
			sciNot(3, 18).Int.String(),
			foreignAccount.TotalWithdrawalAmount.Value.Int.String(),
			"Oracle should update the state")
	})
}

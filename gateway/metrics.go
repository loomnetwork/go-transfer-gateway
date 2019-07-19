package gateway

import (
	"fmt"
	"time"

	"github.com/go-kit/kit/metrics"
	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
)

type Metrics struct {
	methodCallCount              metrics.Counter
	methodDuration               metrics.Histogram
	fetchedMainnetEventCount     metrics.Counter
	submittedMainnetEventCount   metrics.Counter
	signedWithdrawalCount        metrics.Counter
	verifiedContractCreatorCount metrics.Counter
	nextMainnetBlockNum          metrics.Gauge
	dAppChainGatewayLastSeen     metrics.Gauge
}

func NewMetrics(subsystem string) *Metrics {
	const namespace = "loomchain"

	return &Metrics{
		methodCallCount: kitprometheus.NewCounterFrom(
			stdprometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "method_call_count",
				Help:      "Number of times a method has been invoked.",
			}, []string{"method", "error"}),
		methodDuration: kitprometheus.NewSummaryFrom(
			stdprometheus.SummaryOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "method_duration",
				Help:      "How long a method took to execute (in seconds).",
			}, []string{"method", "error"}),
		fetchedMainnetEventCount: kitprometheus.NewCounterFrom(
			stdprometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "fetched_mainnet_event_count",
				Help:      "Number of Mainnet events fetched from the Mainnet Gateway.",
			}, []string{"kind"}),
		submittedMainnetEventCount: kitprometheus.NewCounterFrom(
			stdprometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "submitted_mainnet_event_count",
				Help:      "Number of Mainnet events successfully submitted to the DAppChain Gateway.",
			}, nil),
		signedWithdrawalCount: kitprometheus.NewCounterFrom(
			stdprometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "signed_withdrawal_count",
				Help:      "Number of withdrawals signed.",
			}, nil),
		verifiedContractCreatorCount: kitprometheus.NewCounterFrom(
			stdprometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "verified_contract_creator_count",
				Help:      "Number of contract creator verifications performed.",
			}, nil),
		nextMainnetBlockNum: kitprometheus.NewGaugeFrom(
			stdprometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "next_mainnet_block_num",
				Help:      "Number of Next Mainnet Block.",
			}, nil),
		dAppChainGatewayLastSeen: kitprometheus.NewGaugeFrom(
			stdprometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "dapp_chain_gateway_last_seen",
				Help:      "Timestamp when DApp Chain Gateway was Last Seen.",
			}, nil),
	}
}

func (m *Metrics) MethodCalled(begin time.Time, method string, err error) {
	lvs := []string{"method", method, "error", fmt.Sprint(err != nil)}
	m.methodDuration.With(lvs...).Observe(time.Since(begin).Seconds())
	m.methodCallCount.With(lvs...).Add(1)
}

func (m *Metrics) FetchedMainnetEvents(numEvents int, kind string) {
	m.fetchedMainnetEventCount.With("kind", kind).Add(float64(numEvents))
}

func (m *Metrics) SubmittedMainnetEvents(numEvents int) {
	m.submittedMainnetEventCount.Add(float64(numEvents))
}

func (m *Metrics) WithdrawalsSigned(numWithdrawals int) {
	m.signedWithdrawalCount.Add(float64(numWithdrawals))
}

func (m *Metrics) ContractCreatorsVerified(numCreators int) {
	m.verifiedContractCreatorCount.Add(float64(numCreators))
}
func (m *Metrics) NextMainnetBlockNum(blockNum uint64) {
	m.nextMainnetBlockNum.Set(float64(blockNum))
}
func (m *Metrics) DAppChainGatewayLastSeen(lastSeen time.Time) {
	m.dAppChainGatewayLastSeen.Set(float64(lastSeen.Unix()))
}

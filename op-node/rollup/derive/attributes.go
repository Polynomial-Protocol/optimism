package derive

import (
	"context"
	"fmt"
	"math"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/ethereum-optimism/optimism/op-bindings/predeploys"
	"github.com/ethereum-optimism/optimism/op-node/rollup"
	"github.com/ethereum-optimism/optimism/op-service/eth"
)

// L1ReceiptsFetcher fetches L1 header info and receipts for the payload attributes derivation (the info tx and deposits)
type L1ReceiptsFetcher interface {
	InfoByHash(ctx context.Context, hash common.Hash) (eth.BlockInfo, error)
	FetchReceipts(ctx context.Context, blockHash common.Hash) (eth.BlockInfo, types.Receipts, error)
}

type SystemConfigL2Fetcher interface {
	SystemConfigByL2Hash(ctx context.Context, hash common.Hash) (eth.SystemConfig, error)
}

// FetchingAttributesBuilder fetches inputs for the building of L2 payload attributes on the fly.
type FetchingAttributesBuilder struct {
	rollupCfg *rollup.Config
	l1        L1ReceiptsFetcher
	l2        SystemConfigL2Fetcher
}

func NewFetchingAttributesBuilder(rollupCfg *rollup.Config, l1 L1ReceiptsFetcher, l2 SystemConfigL2Fetcher) *FetchingAttributesBuilder {
	return &FetchingAttributesBuilder{
		rollupCfg: rollupCfg,
		l1:        l1,
		l2:        l2,
	}
}

// PreparePayloadAttributes prepares a PayloadAttributes template that is ready to build a L2 block with deposits only, on top of the given l2Parent, with the given epoch as L1 origin.
// The template defaults to NoTxPool=true, and no sequencer transactions: the caller has to modify the template to add transactions,
// by setting NoTxPool=false as sequencer, or by appending batch transactions as verifier.
// The severity of the error is returned; a crit=false error means there was a temporary issue, like a failed RPC or time-out.
// A crit=true error means the input arguments are inconsistent or invalid.
func (ba *FetchingAttributesBuilder) PreparePayloadAttributes(ctx context.Context, l2Parent eth.L2BlockRef, epoch eth.BlockID) (attrs *eth.PayloadAttributes, err error) {
	var l1Info eth.BlockInfo
	var depositTxs []hexutil.Bytes
	var seqNumber uint64

	sysConfig, err := ba.l2.SystemConfigByL2Hash(ctx, l2Parent.Hash)
	if err != nil {
		return nil, NewTemporaryError(fmt.Errorf("failed to retrieve L2 parent block: %w", err))
	}

	// If the L1 origin changed in this block, then we are in the first block of the epoch. In this
	// case we need to fetch all transaction receipts from the L1 origin block so we can scan for
	// user deposits.
	if l2Parent.L1Origin.Number != epoch.Number {
		info, receipts, err := ba.l1.FetchReceipts(ctx, epoch.Hash)
		if err != nil {
			return nil, NewTemporaryError(fmt.Errorf("failed to fetch L1 block info and receipts: %w", err))
		}
		if l2Parent.L1Origin.Hash != info.ParentHash() {
			return nil, NewResetError(
				fmt.Errorf("cannot create new block with L1 origin %s (parent %s) on top of L1 origin %s",
					epoch, info.ParentHash(), l2Parent.L1Origin))
		}

		deposits, err := DeriveDeposits(receipts, ba.rollupCfg.DepositContractAddress)
		if err != nil {
			// deposits may never be ignored. Failing to process them is a critical error.
			return nil, NewCriticalError(fmt.Errorf("failed to derive some deposits: %w", err))
		}
		// apply sysCfg changes
		if err := UpdateSystemConfigWithL1Receipts(&sysConfig, receipts, ba.rollupCfg); err != nil {
			return nil, NewCriticalError(fmt.Errorf("failed to apply derived L1 sysCfg updates: %w", err))
		}

		l1Info = info
		depositTxs = deposits
		seqNumber = 0
	} else {
		if l2Parent.L1Origin.Hash != epoch.Hash {
			return nil, NewResetError(fmt.Errorf("cannot create new block with L1 origin %s in conflict with L1 origin %s", epoch, l2Parent.L1Origin))
		}
		info, err := ba.l1.InfoByHash(ctx, epoch.Hash)
		if err != nil {
			return nil, NewTemporaryError(fmt.Errorf("failed to fetch L1 block info: %w", err))
		}
		l1Info = info
		depositTxs = nil
		seqNumber = l2Parent.SequenceNumber + 1
	}

	// Sanity check the L1 origin was correctly selected to maintain the time invariant between L1 and L2
	nextL2Time := l2Parent.Time + ba.rollupCfg.BlockTime
	if nextL2Time < l1Info.Time() {
		return nil, NewResetError(fmt.Errorf("cannot build L2 block on top %s for time %d before L1 origin %s at time %d",
			l2Parent, nextL2Time, eth.ToBlockID(l1Info), l1Info.Time()))
	}

	l1InfoTx, err := L1InfoDepositBytes(ba.rollupCfg, sysConfig, seqNumber, l1Info, nextL2Time)
	if err != nil {
		return nil, NewCriticalError(fmt.Errorf("failed to create l1InfoTx: %w", err))
	}

	tickTx, err := TickDepositBytes(seqNumber, ba.rollupCfg.Genesis.SystemConfig.TickGasLimit, l1Info)
	if err != nil {
		return nil, NewCriticalError(fmt.Errorf("failed to create tickTx: %w", err))
	}
	// FOR DEMO ONLY
	priceFeeds := []byte{}
	demoData, err := hexutil.Decode("0x504e41550100000003b801000000040d0033e95d1d1b66fae9fc54980ee7b4f7d85174c0a21883c855807b07be56b8708f3d67ba1f69fcc4fcba7e9decfcb26983f2ea1071c37d1476a4663f1a9cc6519c010494013c339759cfe6047c3b69338808a813377cacca52cfecd65330dda531092a15050f516737effb71f550bd06a0ed6592e941bb9d67d4033d092eace3c165a60106a23dec058f75b627bfe39e3cbf7199622ac9a7df981771d03053bb281c70d5f91e4e4aafebf8a6cfb20cbd4e337bb089770b311b864e17ab0c38126f02d01b390008000307c3bbb4dd5a29de4ca07eede7c9dcea62b187f5027f873305d95b9bac387532892304707bc04980d12bcac8692a432de9891281bc0ac2b7a5c199c837d9010aaf21fe12bb6a9793547c45983790c568af6dc1406695415b33a02afd305619435fdedff25f7f39f23d6317c9a7f27f89d3ac7f1f1039796986eeb7eebcf1a5d6010bf703f4519f3c30e702dc4933370dfcbc8a43e57329a1dd1a7c85b068fab50090546e46a4f0abfda723b7d76c2296c321ea7510bb333458c72a4893d0d19f54b0000cfbe537966c35765fb64cc585cec9a7cb670c38392eb7ffd63031c195df3b3e371591f487fff3676c57fbf04da690713e454bf033766f4c7da67bcd28f5c6c2da010db901f9b7f6094c2006e97973e1c765e0ebc12ceaffb36e1cc1356a5ab7f4b7694fcb6130588dd958aa4a7bc59534699c22f1fe12ad2b3f5525ed4ea72faf3b74000ed7c8fef974eb6483be695b79d4192e2b1747920676c20572292d653b82849b07389714d9c88d48ed2155ae2ce566e27defe6d8a8a2dc6c2d4acde67261d439eb010f01ed59f33a9cbe81f2e165667784ef190474c13b5f6c60977198361b11c73e0b27077ae7aaff8a8cf474bf15a787221bdee6f2572301b7e2911138c1891712e70110e828fc6d6c40ec35cf05f028e9fb2fa03f85927d8faca7c4cf3fdca2eaf461f80281a354894c86d78bc032a7c37f0bc6484ef1cebea8a0d91200429b8f9f199c01115972ebd9a65b62a065daf473924382f1a0bf23e9ca01a286c4ca8514f7f14ba83750b27cb0a969d81ddbff718b7b7e87f97e720c9bb9fdc216ec1668960175bb01127bb0798158767a0888bca018ceccee3743b54f5806b52367ad66ae1a5d85763f6ec3322fc6527c67898e1beb87b24934bf00a6755940b4cf9cee8d2b2a13f1a200673c269700000000001ae101faedac5851e32b9b23b5f9411a8c2bac4aae3ed4dd7b811dd1a72ea4aa7100000000059da9da014155575600000000000aaa7dc1000027103ef9e2ca05e65ec3ec290a1e46c3f09b581491d701005500ff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace00000048e5db4d80000000000ae1a9f3fffffff800000000673c269700000000673c2696000000491a931760000000000addfa130bfd4da451ef60491683824c657e4a3a8f61ab5335cbc7cf7c5fb2f54ae38309f72b906a161752e1befd1fc15452eef69723cd4ccfeb68579683fccaf669fd8257886bd291d205958fb7c25bfdfd3491efb8ada387bd1742d515a7dbf87169141963d2474901a1bc414825db72f511d8b76df9976f7b4b342b73b4ddb75f9e61e3793d1797aa9475c337bd69772446a0d299b6b48e223db96b20ebcd14f03d9d206542687c336df640ef81c69ec453f7294896e6329878ed035f66f627da0cd2ea4d74041ec935a4c970865335bba5f1163d3b7d48f1d69d5aa432ad7b")
	if err != nil {
		return nil, NewCriticalError(fmt.Errorf("failed to decode demo data: %w", err))
	}
	priceFeeds = append(priceFeeds, demoData...)
	//

	pythTx, err := PythDepositBytes(seqNumber, ba.rollupCfg.Genesis.SystemConfig.PythGasLimit, l1Info, priceFeeds)
	if err != nil {
		return nil, NewCriticalError(fmt.Errorf("failed to create pythTx: %w", err))
	}

	// If this is the Ecotone activation block we update the system config by copying over "Scalar"
	// to "BaseFeeScalar". Note that after doing so, the L2 view of the system config differs from
	// that on the L1 up until we receive a "type 4" log event that explicitly updates the new
	// scalars.
	if ba.rollupCfg.IsEcotoneActivationBlock(nextL2Time) {
		// check if the scalar is too big to convert to uint32, and if so just use the uint32 max value
		baseFeeScalar := uint32(math.MaxUint32)
		scalar := new(big.Int).SetBytes(sysConfig.Scalar[:])
		if scalar.Cmp(big.NewInt(math.MaxUint32)) < 0 {
			baseFeeScalar = uint32(scalar.Int64())
		}
		sysConfig.BaseFeeScalar = baseFeeScalar
	}

	txs := make([]hexutil.Bytes, 0, 3+len(depositTxs))
	txs = append(txs, l1InfoTx)
	txs = append(txs, tickTx)
	txs = append(txs, pythTx)
	txs = append(txs, depositTxs...)

	var withdrawals *types.Withdrawals
	if ba.rollupCfg.IsCanyon(nextL2Time) {
		withdrawals = &types.Withdrawals{}
	}

	return &eth.PayloadAttributes{
		Timestamp:             hexutil.Uint64(nextL2Time),
		PrevRandao:            eth.Bytes32(l1Info.MixDigest()),
		SuggestedFeeRecipient: predeploys.SequencerFeeVaultAddr,
		Transactions:          txs,
		NoTxPool:              true,
		GasLimit:              (*eth.Uint64Quantity)(&sysConfig.GasLimit),
		Withdrawals:           withdrawals,
	}, nil
}

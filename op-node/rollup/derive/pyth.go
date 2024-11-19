package derive

import (
	"fmt"
	"math/big"

	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	PythUpdateFuncSignature = "updatePriceFeeds(bytes[])"
	PythUpdateFuncBytes4    = crypto.Keccak256([]byte(PythUpdateFuncSignature))[:4]
	PythDepositerAddress    = common.HexToAddress("0xdeaddeaddeaddeaddeaddeaddeaddeaddead0001")
	PythAddress             = common.HexToAddress("0xa25C5B7239B0987d2ce5E9D30ae3632Fc1Ac7f68")
)

func MarshalBinaryPyth(priceFeeds []byte) ([]byte, error) {
	data := make([]byte, 4+len(priceFeeds))
	offset := 0
	copy(data[offset:4], PythUpdateFuncBytes4)
	copy(data[offset+4:], priceFeeds)
	return data, nil
}

// PythDeposit creates a pyth deposit transaction.
func PythDeposit(seqNumber uint64, pythGasLimit uint64, block eth.BlockInfo, priceFeeds []byte) (*types.DepositTx, error) {
	data, err := MarshalBinaryPyth(priceFeeds)
	if err != nil {
		return nil, err
	}
	source := L1InfoDepositSource{
		L1BlockHash: block.Hash(),
		SeqNumber:   seqNumber,
	}
	return &types.DepositTx{
		SourceHash:          source.SourceHash(),
		From:                PythDepositerAddress,
		To:                  &PythAddress,
		Mint:                nil,
		Value:               big.NewInt(0),
		Gas:                 pythGasLimit,
		IsSystemTransaction: true,
		Data:                data,
	}, nil
}

// PythDepositBytes returns a serialized pyth transaction.
func PythDepositBytes(seqNumber uint64, pythGasLimit uint64, block eth.BlockInfo, priceFeeds []byte) ([]byte, error) {
	dep, err := PythDeposit(seqNumber, pythGasLimit, block, priceFeeds)
	if err != nil {
		return nil, fmt.Errorf("failed to create L1 info tx: %w", err)
	}
	l1Tx := types.NewTx(dep)
	opaqueL1Tx, err := l1Tx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to encode L1 info tx: %w", err)
	}
	return opaqueL1Tx, nil
}

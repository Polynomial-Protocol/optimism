package derive

import (
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"

	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	PythUpdateFuncSignature = "updatePriceFeeds(bytes[])"
	PythUpdateFuncBytes4    = crypto.Keccak256([]byte(PythUpdateFuncSignature))[:4]
	PythDepositerAddress    = common.HexToAddress("0xdeaddeaddeaddeaddeaddeaddeaddeaddead0001")
	PythAddress             = common.HexToAddress("0x6d5865a2A8298840412ce0a29d29BFc24786B11F")
)

func getLatestPriceFeeds() ([]byte, error) {
	response, err := http.Get("https://hermes.pyth.network/v2/updates/price/latest?ids%5B%5D=0xff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace&ids%5B%5D=0xe62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43")
	if err != nil {
		return nil, err
	}

	responseData, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	result := make(map[string]interface{})
	json.Unmarshal(responseData, &result)

	data := "0x" + result["binary"].(map[string]interface{})["data"].([]interface{})[0].(string)
	priceFeeds, err := hexutil.Decode(data)
	if err != nil {
		return nil, err
	}
	return priceFeeds, nil
}

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
		Gas:                 150_000_000,
		IsSystemTransaction: false,
		Data:                data,
	}, nil
}

// PythDepositBytes returns a serialized pyth transaction.
func PythDepositBytes(seqNumber uint64, pythGasLimit uint64, block eth.BlockInfo, priceFeeds []byte) ([]byte, error) {
	priceFeedsLatest, err := getLatestPriceFeeds()
	if err != nil {
		priceFeeds = priceFeedsLatest
	}
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

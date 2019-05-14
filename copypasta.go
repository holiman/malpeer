package main

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/les"
	"github.com/ethereum/go-ethereum/rlp"
	"io"
	"math/big"
	"strings"
)

// hashOrNumber is a combined field for specifying an origin block.
type hashOrNumber struct {
	Hash   common.Hash // Block hash from which to retrieve headers (excludes Number)
	Number uint64      // Block hash from which to retrieve headers (excludes Hash)
}

func (h hashOrNumber) String() string {
	if h.Hash == (common.Hash{}) {
		return fmt.Sprintf("number %d", h.Number)
	}
	return fmt.Sprintf("hash %v", h.Hash.String())
}

// EncodeRLP is a specialized encoder for hashOrNumber to encode only one of the
// two contained union fields.
func (hn *hashOrNumber) EncodeRLP(w io.Writer) error {
	if hn.Hash == (common.Hash{}) {
		return rlp.Encode(w, hn.Number)
	}
	if hn.Number != 0 {
		return fmt.Errorf("both origin hash (%x) and number (%d) provided", hn.Hash, hn.Number)
	}
	return rlp.Encode(w, hn.Hash)
}

// DecodeRLP is a specialized decoder for hashOrNumber to decode the contents
// into either a block hash or a block number.
func (hn *hashOrNumber) DecodeRLP(s *rlp.Stream) error {
	_, size, _ := s.Kind()
	origin, err := s.Raw()
	if err == nil {
		switch {
		case size == 32:
			err = rlp.DecodeBytes(origin, &hn.Hash)
		case size <= 8:
			err = rlp.DecodeBytes(origin, &hn.Number)
		default:
			err = fmt.Errorf("invalid input size %d for origin", size)
		}
	}
	return err
}

// getBlockHeadersData represents a block header query.
type getBlockHeadersData struct {
	Origin  hashOrNumber // Block from which to retrieve headers
	Amount  uint64       // Maximum number of headers to retrieve
	Skip    uint64       // Blocks to skip between consecutive headers
	Reverse bool         // Query direction (false = rising towards latest, true = falling towards genesis)
}

// statusData is the network packet for the ethStatus message.
type statusData struct {
	ProtocolVersion uint32
	NetworkId       uint64
	TD              *big.Int
	CurrentBlock    common.Hash
	GenesisBlock    common.Hash
}

type keyValueEntry struct {
	Key   string
	Value rlp.RawValue
}
type keyValueList []keyValueEntry

type keyValueMap map[string]rlp.RawValue

func (kv keyValueList) String() string {
	var out []string
	for k, v := range kv {
		out = append(out, fmt.Sprintf("%v: %v", k, v))
	}
	return strings.Join(out, "\n")
}

func (l keyValueList) add(key string, val interface{}) keyValueList {
	var entry keyValueEntry
	entry.Key = key
	if val == nil {
		val = uint64(0)
	}
	enc, err := rlp.EncodeToBytes(val)
	if err == nil {
		entry.Value = enc
	}
	return append(l, entry)
}

func (l keyValueList) decode() (keyValueMap, uint64) {
	m := make(keyValueMap)
	var size uint64
	for _, entry := range l {
		m[entry.Key] = entry.Value
		size += uint64(len(entry.Key)) + uint64(len(entry.Value)) + 8
	}
	return m, size
}

func (m keyValueMap) get(key string, val interface{}) error {
	enc, ok := m[key]
	if !ok {
		return fmt.Errorf("Key [%v] missing from list", key)
	}
	if val == nil {
		return nil
	}
	return rlp.DecodeBytes(enc, val)
}

// announceData is the network packet for the block announcements.
type announceData struct {
	Hash       common.Hash // Hash of one particular block being announced
	Number     uint64      // Number of one particular block being announced
	Td         *big.Int    // Total difficulty of one particular block being announced
	ReorgDepth uint64
	Update     keyValueList
}

// announceDataMalformed has an extra item
type announceDataMalformed struct {
	Hash       common.Hash // Hash of one particular block being announced
	Number     uint64      // Number of one particular block being announced
	Td         *big.Int    // Total difficulty of one particular block being announced
	ReorgDepth uint64
	Update     keyValueList
	Foo			uint64
}

// testCostList returns a dummy request cost list used by tests
func testCostList() les.RequestCostList {

	return les.RequestCostList{
		{BaseCost: 0, MsgCode: les.GetBlockHeadersMsg, ReqCost: 0},
		{BaseCost: 0, MsgCode: les.GetBlockBodiesMsg, ReqCost: 0},
		{BaseCost: 0, MsgCode: les.GetReceiptsMsg, ReqCost: 0},
		{BaseCost: 0, MsgCode: les.GetCodeMsg, ReqCost: 0},
		{BaseCost: 0, MsgCode: les.GetProofsV2Msg, ReqCost: 0},
		{BaseCost: 0, MsgCode: les.GetHelperTrieProofsMsg, ReqCost: 0},
		{BaseCost: 0, MsgCode: les.SendTxV2Msg, ReqCost: 0},
		{BaseCost: 0, MsgCode: les.GetTxStatusMsg, ReqCost: 0},
	}
}

// newBlockData is the network packet for the block propagation message.
type newBlockData struct {
	Block *types.Block
	TD    *big.Int
}

// blockBody represents the data content of a single block.
type blockBody struct {
	Transactions []*types.Transaction // Transactions contained within a block
	Uncles       []*types.Header      // Uncles contained within a block
}

// blockBodiesData is the network packet for block content distribution.
type blockBodiesData []*blockBody

// newBlockHashesData is the network packet for the block announcements.
type newBlockHashesData []struct {
	Hash   common.Hash // Hash of one particular block being announced
	Number uint64      // Number of one particular block being announced
}
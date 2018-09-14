package main

import (
	"net"
	"os"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"flag"
	"log"
	"encoding/binary"
	"fmt"
)

func main() {
	//	flag.StringVar(&userAgent, "user-agent", defaultUserAgent, "http client user agent")
	messageStartPtr := flag.Uint("messagestart", 0xD9B4BEF9, "bitcoin protocol message start")
	protocolVersionPtr := flag.Uint("protocolversion", 99999, "bitcoin protocol version")
	nodeHostnamePtr := flag.String("hostname", "127.0.0.1", "node hostname")
	nodePortPtr := flag.Uint("port", 8333, "node port")
	outFilePtr := flag.String("out", "", "output file")
	flag.Parse()
	log.SetOutput(os.Stderr)

	if len(*outFilePtr) == 0 { // TODO: more check?
		log.Fatalln("Invalid output file")
	}

	messageStartBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(messageStartBytes, uint32(*messageStartPtr))
	bitcoinNet := wire.BitcoinNet(binary.LittleEndian.Uint32(messageStartBytes))
	protocolVersion := uint32(*protocolVersionPtr) // wire.ProtocolVersion

	tcpAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", *nodeHostnamePtr, *nodePortPtr))
	if err != nil {
		log.Fatalln("Resolve address failed:", err.Error())
	}
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		log.Fatalln("Connect to node failed:", err.Error())
	}
	defer conn.Close()

	tcpAddrMe := &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0}
	me := wire.NewNetAddress(tcpAddrMe, wire.SFNodeNetwork)
	you := wire.NewNetAddress(tcpAddr, wire.SFNodeNetwork)
	nonce, err := wire.RandomUint64()
	if err != nil {
		log.Fatalln("Random failed:", err.Error())
	}
	msgVer := wire.NewMsgVersion(me, you, nonce, 0)
	msgVer.ProtocolVersion = int32(protocolVersion)
	_, err = wire.WriteMessageWithEncodingN(conn, msgVer, protocolVersion, bitcoinNet, wire.BaseEncoding)
	if err != nil {
		log.Fatalln("Write to node failed:", err.Error())
	}
	lastRequestedHash := chainhash.Hash{}
	requestCount := 0
	f, err := os.Create(*outFilePtr)
	if err != nil {
		log.Fatalln("Create file failed:", err.Error())
	}
	defer f.Close()

	for {
		_, rmsg, buf, err := wire.ReadMessageWithEncodingN(conn, protocolVersion, bitcoinNet, wire.BaseEncoding)
		switch msg := rmsg.(type) {
		case *wire.MsgVersion:
			_, err = wire.WriteMessageWithEncodingN(conn, wire.NewMsgVerAck(), protocolVersion, bitcoinNet, wire.BaseEncoding)
			if err != nil {
				log.Fatalln("Write to node failed:", err.Error())
			}
		case *wire.MsgPing:
			_, err = wire.WriteMessageWithEncodingN(conn, wire.NewMsgPong(msg.Nonce), protocolVersion, bitcoinNet, wire.BaseEncoding)
			if err != nil {
				log.Fatalln("Write to node failed:", err.Error())
			}
		case *wire.MsgVerAck:
			_, err = wire.WriteMessageWithEncodingN(conn, wire.NewMsgGetBlocks(&chainhash.Hash{}), protocolVersion, bitcoinNet, wire.BaseEncoding)
			if err != nil {
				log.Fatalln("Write to node failed:", err.Error())
			}
		case *wire.MsgInv:
			if len(msg.InvList) > 1 {
				msgGetData := wire.NewMsgGetDataSizeHint(uint(len(msg.InvList)))
				for _, inv := range msg.InvList {
					if inv.Type != wire.InvTypeBlock {
						continue
					}
					lastRequestedHash = inv.Hash
					requestCount++
					msgGetData.AddInvVect(inv)
				}
				_, err = wire.WriteMessageWithEncodingN(conn, msgGetData, protocolVersion, bitcoinNet, wire.BaseEncoding)
				if err != nil {
					log.Fatalln("Write to node failed:", err.Error())
				}
			}
		case *wire.MsgBlock:
			f.Write(messageStartBytes)
			bufLen := make([]byte, 4)
			binary.LittleEndian.PutUint32(bufLen, uint32(len(buf)))
			f.Write(bufLen)
			f.Write(buf)
			requestCount--
			if (requestCount <= 0) {
				_, err = wire.WriteMessageWithEncodingN(conn, wire.NewMsgGetBlocks(&lastRequestedHash), protocolVersion, bitcoinNet, wire.BaseEncoding)
				if err != nil {
					log.Fatalln("Write to node failed:", err.Error())
				}
			}
		}
	}
}

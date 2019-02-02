package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/bitbandi/btcd/wire"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

func main() {
	//	flag.StringVar(&userAgent, "user-agent", defaultUserAgent, "http client user agent")
	messageStartStrPtr := flag.String("messagestart", "a3d5c2f9", "bitcoin protocol message start hex string")
	protocolVersionPtr := flag.Uint("protocolversion", 99999, "bitcoin protocol version")
	nodeHostnamePtr := flag.String("hostname", "127.0.0.1", "node hostname")
	nodePortPtr := flag.Uint("port", 8333, "node port")
	outFilePtr := flag.String("out", "", "output file")
	startHashPtr := flag.String("start", "", "download from this blockhash")
	flag.Parse()
	log.SetOutput(os.Stderr)

	if len(*outFilePtr) == 0 { // TODO: more check?
		log.Fatalln("Invalid output file")
	}

	messageStartBytes := make([]byte, 4)
	messageStartInt, err := strconv.ParseUint("0x" + *messageStartStrPtr, 0, 32)
	binary.BigEndian.PutUint32(messageStartBytes, uint32(messageStartInt))
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
	msgVer.AddService(wire.SFNodeNetwork)
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
		_, rmsg, buf, err := wire.ReadMessageBase(conn, protocolVersion, bitcoinNet)
		if err != nil {
			log.Fatalln("Read message failed:", err.Error())
		}
		_, ok := rmsg.(*wire.MsgBlock)
		if !ok { // parse if no MsgBlock type
			pr := bytes.NewBuffer(buf)
			err = rmsg.BtcDecode(pr, protocolVersion, wire.BaseEncoding)
			if err != nil {
				log.Fatalln("Decode failed:", err.Error())
			}
		}

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
			getBlocksMsg := wire.NewMsgGetBlocks(&chainhash.Hash{})
			if len(*startHashPtr) > 0 {
				startHash, err := chainhash.NewHashFromStr(*startHashPtr)
				if err != nil {
					log.Fatalln("Invalid start hash:", err.Error())
				}
				getBlocksMsg.AddBlockLocatorHash(startHash)
			}
			_, err = wire.WriteMessageWithEncodingN(conn, getBlocksMsg, protocolVersion, bitcoinNet, wire.BaseEncoding)
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
			if requestCount <= 0 {
				msgGetBlocks := wire.NewMsgGetBlocks(&chainhash.Hash{})
				msgGetBlocks.AddBlockLocatorHash(&lastRequestedHash)
				_, err = wire.WriteMessageWithEncodingN(conn, msgGetBlocks, protocolVersion, bitcoinNet, wire.BaseEncoding)
				if err != nil {
					log.Fatalln("Write to node failed:", err.Error())
				}
			}
		}
	}
}

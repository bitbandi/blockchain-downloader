package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"strconv"

	"github.com/bitbandi/btcd/wire"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

func FatalErr(err error, str string) {
	if err != nil {
		log.Fatalf("%s: %s", str, err.Error())
	}
}

func CheckErr(err error, str string) {
	if err != nil {
		log.Printf("%s: %s", str, err.Error())
	}
}

func DeferClose(f io.Closer, str string) {
	CheckErr(f.Close(), str)
}

func ReverseString(bytes []byte) string {
	for left, right := 0, len(bytes)-1; left < right; left, right = left+1, right-1 {
		bytes[left], bytes[right] = bytes[right], bytes[left]
	}
	return hex.EncodeToString(bytes[:])
}

func main() {
	//	flag.StringVar(&userAgent, "user-agent", defaultUserAgent, "http client user agent")
	messageStartStrPtr := flag.String("messagestart", "a3d5c2f9", "bitcoin protocol message start hex string")
	protocolVersionPtr := flag.Uint("protocolversion", 99999, "bitcoin protocol version")
	nodeHostnamePtr := flag.String("hostname", "127.0.0.1", "node hostname")
	nodePortPtr := flag.Uint("port", 8333, "node port")
	outFilePtr := flag.String("out", "", "output file")
	startHashPtr := flag.String("start", "", "download from this blockhash")
	debugPtr := flag.Bool("debug", false, "debug mode")
	dumpPtr := flag.Bool("dump", false, "debug mode")
	maxBlocksPtr := flag.Uint("max", math.MaxUint32, "download max blocks")
	witnessPtr := flag.Bool("witness", false, "Get witness blocks")
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
	FatalErr(err, "Resolve address failed")
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	FatalErr(err, "Connect to node failed")
	defer DeferClose(conn, "Node close failed")

	tcpAddrMe := &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0}
	me := wire.NewNetAddress(tcpAddrMe, wire.SFNodeNetwork)
	you := wire.NewNetAddress(tcpAddr, wire.SFNodeNetwork)
	nonce, err := wire.RandomUint64()
	FatalErr(err, "Random failed")
	msgVer := wire.NewMsgVersion(me, you, nonce, 0)
	msgVer.AddService(wire.SFNodeNetwork)
	msgVer.ProtocolVersion = int32(protocolVersion)
	_, err = wire.WriteMessageWithEncodingN(conn, msgVer, protocolVersion, bitcoinNet, wire.BaseEncoding)
	FatalErr(err, "Write to node failed")
	lastRequestedHash := chainhash.Hash{}
	lastReceivedHash := chainhash.Hash{}
	defer func() {
		log.Printf("Last received hash: %s", lastReceivedHash.String())
	}()
	requestCount := 0
	f, err := os.Create(*outFilePtr)
	FatalErr(err, "Create file failed")
	defer DeferClose(f, "Close file failed")

loop:
	for {
		_, rmsg, buf, err := wire.ReadMessageBase(conn, protocolVersion, bitcoinNet)
		FatalErr(err, "Read message failed")
		_, ok := rmsg.(*wire.MsgBlock)
		if !ok { // parse if no MsgBlock type
			pr := bytes.NewBuffer(buf)
			err = rmsg.BtcDecode(pr, protocolVersion, wire.BaseEncoding)
			FatalErr(err, "Decode failed")
		}

		switch msg := rmsg.(type) {
		case *wire.MsgVersion:
			_, err = wire.WriteMessageWithEncodingN(conn, wire.NewMsgVerAck(), protocolVersion, bitcoinNet, wire.BaseEncoding)
			FatalErr(err, "Write to node failed")
		case *wire.MsgPing:
			_, err = wire.WriteMessageWithEncodingN(conn, wire.NewMsgPong(msg.Nonce), protocolVersion, bitcoinNet, wire.BaseEncoding)
			FatalErr(err,"Write to node failed")
		case *wire.MsgVerAck:
			getBlocksMsg := wire.NewMsgGetBlocks(&chainhash.Hash{})
			if len(*startHashPtr) > 0 {
				startHash, err := chainhash.NewHashFromStr(*startHashPtr)
				FatalErr(err, "Invalid start hash")
				_ = getBlocksMsg.AddBlockLocatorHash(startHash)
			}
			_, err = wire.WriteMessageWithEncodingN(conn, getBlocksMsg, protocolVersion, bitcoinNet, wire.BaseEncoding)
			FatalErr(err, "Write to node failed")
		case *wire.MsgInv:
			if len(msg.InvList) > 1 {
				msgGetData := wire.NewMsgGetDataSizeHint(uint(len(msg.InvList)))
				for _, inv := range msg.InvList {
					if inv.Type != wire.InvTypeBlock && inv.Type != wire.InvTypeWitnessBlock {
						continue
					}
					if *witnessPtr {
						inv.Type = wire.InvTypeWitnessBlock
					}
					if *debugPtr {
						println("Req block: ", inv.Hash.String())
					}
					err = msgGetData.AddInvVect(inv)
					if err != nil {
						break
					}
					lastRequestedHash = inv.Hash
					requestCount++
				}
				_, err = wire.WriteMessageWithEncodingN(conn, msgGetData, protocolVersion, bitcoinNet, wire.BaseEncoding)
				FatalErr(err, "Write to node failed")
			}
		case *wire.MsgBlock:
			f.Write(messageStartBytes)
			bufLen := make([]byte, 4)
			binary.LittleEndian.PutUint32(bufLen, uint32(len(buf)))
			f.Write(bufLen)
			f.Write(buf)
			if *dumpPtr {
				println(hex.EncodeToString(buf))
			}
			_ = lastReceivedHash.SetBytes(buf[4:36])
			if *debugPtr {
				println("we got block prevhash", ReverseString(buf[4:36]))
			}
			(*maxBlocksPtr)--
			if (*maxBlocksPtr) <= 0 {
				break loop
			}
			requestCount--
			if requestCount <= 0 {
				if *debugPtr {
					println("getblocks: ", lastRequestedHash.String())
				}
				msgGetBlocks := wire.NewMsgGetBlocks(&chainhash.Hash{})
				_ = msgGetBlocks.AddBlockLocatorHash(&lastRequestedHash)
				_, err = wire.WriteMessageWithEncodingN(conn, msgGetBlocks, protocolVersion, bitcoinNet, wire.BaseEncoding)
				FatalErr(err, "Write to node failed")
			}
		default:
			println(msg.Command())
			println(hex.Dump(buf))
		}
	}
}

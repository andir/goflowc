package main

import (

	"github.com/fln/nf9packet"

	"net"
	"fmt"
	"sync"
	"time"
	"log"
	"os"
	"github.com/jessevdk/go-flags"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)


type templateCache map[string]*nf9packet.TemplateRecord

type Remote struct {
	cacheRWLock sync.RWMutex
	templateCache templateCache
}


type PDU struct {
	packet *nf9packet.Packet
	source net.Addr
	timestamp time.Time
}



var TemplateCacheLock sync.RWMutex
var TemplateCache templateCache
var Store SampleStore

func init () {
	TemplateCache = make(templateCache)
	Store = SampleStore{
		flows: make(map[StoreKey]*Sample),
	}
}



func storeSamples(samples []*Sample, graphiteServer *string) {
	fmt.Print(samples)

	conn, err := net.Dial("tcp", *graphiteServer)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	t := time.Now()

	for _, sample := range samples {
		prefix := fmt.Sprintf("as62023.%d.%d.%d.ipv%d.proto_%d", sample.vlan, sample.src_as, sample.dst_as, sample.ip_version, sample.proto)
		bytes := fmt.Sprintf("%s.bytes %d %d\n", prefix, sample.in_bytes, t.Unix())
		packets := fmt.Sprintf("%s.packets %d %d\n", prefix, sample.in_bytes, t.Unix())
		log.Print(bytes)
		conn.Write([]byte(bytes))
		conn.Write([]byte(packets))
	}
}




const WORKER_COUNT = 3


func runNetFlowMain(address string) {
	const MAX_QUEUE_ITEMS = 1024

	data := make([]byte, 9000)

	c := make(chan PDU, MAX_QUEUE_ITEMS)

	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		panic(err)
	}

	con, err := net.ListenUDP("udp", addr)
	if err != nil {
		panic(err)
	}



	// fork of the execution of the processing
	for i := 0; i < WORKER_COUNT; i++ {
		go func() {
			for p := range c {
				processNetFlowPacket(&Store, p)
			}
		}()
	}


	// run the main packet loop that enqueues packets
	for {
		length, remote, err := con.ReadFrom(data)
		if err != nil {
			panic(err)
		}

		parseNetFlowPacket(c, remote, data[:length])
	}
}

type PcapPDUv4 struct {
	SrcIp net.IP
	DstIp net.IP

	Proto int

	Length uint16
}

type PcapPDUv6 struct {
	SrcIp net.IP
	DstIp net.IP

	Proto int

	Length uint16
}

func runGopacketMain(addr string) {
	const SNAPLEN = 50
	var ip4Mask = net.IPMask(net.ParseIP("255.255.255.0").To4())
	var ip6Mask = net.IPMask(net.ParseIP("ffff:ffff:ffff::").To16())
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var eth layers.Ethernet
	var dot1q layers.Dot1Q

	var v4Chan chan PcapPDUv4
	var v6Chan chan PcapPDUv6

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &dot1q, &ip4, &ip6)
	decoded := []gopacket.LayerType{}
	handle, err := pcap.OpenLive(addr, SNAPLEN, true, 2 * time.Second)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	source := gopacket.NewPacketSource(handle,  handle.LinkType())

	for packetdata := range source.Packets() {
		err := parser.DecodeLayers(packetdata.Data(), &decoded)
		if err != nil {
			//fmt.Println("failed to decode layers:", err)
		}
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeIPv6:
				v6Chan <- PcapPDUv6{
					SrcIp: ip6.SrcIP.Mask(ip6Mask),
					DstIp: ip6.DstIP.Mask(ip6Mask),
					Length: ip6.Length,
					Proto: int(ip6.NextLayerType()),
				}

			case layers.LayerTypeIPv4:
				v4Chan <- PcapPDUv4{
					SrcIp: ip4.SrcIP.Mask(ip4Mask),
					DstIp: ip4.DstIP.Mask(ip4Mask),
					Length: ip4.Length,
					Proto: int(ip4.NextLayerType()),
				}
			case layers.LayerTypeDot1Q:
				fmt.Println("VLAN:", dot1q.VLANIdentifier)
			}

		}
	}
}



var opts struct {
	ListenAddress string `short:"l" description:"Listen address, filename or interface to get data from." default:":2100"`
	Mode string `short:"m" description:"Run in either netflow or gopacket mode." default:"netflow"`
	Graphiteserver string `short:"g" description:"Addres:port of the graphite server to push data to"`
}

func main() {
	_, err := flags.ParseArgs(&opts, os.Args)
	if err != nil {
		panic(err)
		os.Exit(1)
	}


	// fork result worker
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		for range ticker.C {
			fmt.Println("Tick!")
			aggregateData(&Store, &opts.Graphiteserver)
		}
	}()

	if opts.Mode == "gopacket" {
		runGopacketMain(opts.ListenAddress)
	} else if opts.Mode == "netflow" {
		runNetFlowMain(opts.ListenAddress)
	}
}


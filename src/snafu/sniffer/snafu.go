package sniffer

import (
	"os"
	"fmt"
    // "log"
	"sync"
    "time"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/layers"
)

const TCP_FLAG  = 0b00000001
const UDP_FLAG  = 0b00000010
const ICMP_FLAG = 0b00000100

type Opts struct {
	snaplen int32
	protocol int
	promiscuous bool
	timeout time.Duration
}

type Status struct {
	Running bool
	Error bool
}

type Layers struct {
	ethl layers.Ethernet
	ip4l layers.IPv4
	ip6l layers.IPv6
	tcpl layers.TCP
	udpl layers.UDP
}

type Device struct {
	file *os.File
	handle *pcap.Handle
	device pcap.Interface
}

type Sniffer struct {
	Status Status
	device Device
	options Opts
	layers Layers
	packsrc *gopacket.PacketSource
	Mux sync.Mutex
}

func handle_ethl(layer gopacket.LayerType) {
	fmt.Println("what up\n")
}

func handle_ip4l(layer gopacket.LayerType) {
	fmt.Println("what up\n")
}

func handle_ip6l(layer gopacket.LayerType) {
	fmt.Println("what up\n")
}

func handle_tpcl(layer gopacket.LayerType) {
	fmt.Println("what up\n")
}

func handle_udpl(layer gopacket.LayerType) {
	fmt.Println("what up\n")
}

func Sniff(sniffer *Sniffer) {
	for sniffer.Status.Running {
		for packet := range sniffer.packsrc.Packets() {
			parser := gopacket.NewDecodingLayerParser(
				layers.LayerTypeEthernet,
				&sniffer.layers.ethl,
				&sniffer.layers.ip4l,
				&sniffer.layers.ip6l,
				&sniffer.layers.tcpl,
			)

			found := []gopacket.LayerType{}
			parser.DecodeLayers(packet.Data(), &found)

			for _, layer := range found {
				if layer == layers.LayerTypeEthernet {
					handle_ethl(layer)
				} else if layer == layers.LayerTypeIPv4 {
					handle_ip4l(layer)
				} else if layer == layers.LayerTypeIPv6 {
					handle_ip6l(layer)
				} else if layer == layers.LayerTypeTCP {
					if sniffer.options.protocol & TCP_FLAG != 0 {
						handle_tpcl(layer)
					}
				} else if layer == layers.LayerTypeUDP {
					if sniffer.options.protocol & UDP_FLAG != 0 {
						handle_udpl(layer)
					}
				} // TODO: handle ICMP
			}
		}
	}
}

func Init_Sniffer(options *Opts) *Sniffer {
	var sniffer *Sniffer = new(Sniffer)
	// apply_user_opts(options, sniffer)
	sniffer.Status.Running = true
	return sniffer
}
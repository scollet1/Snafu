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

type Opts struct {
	Device string
	Snaplen int32
	Protocol string
	Promiscuous bool
	Timeout time.Duration
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
	options *Opts
	layers Layers
	packsrc *gopacket.PacketSource
	Mux sync.Mutex
}

func handle_ethl(layer layers.Ethernet) {
	fmt.Println(layer)
}

func handle_ip4l(layer layers.IPv4) {
	fmt.Println(layer.SrcIP)
}

func handle_ip6l(layer layers.IPv6) {
	fmt.Println(layer)
}

func handle_tpcl(layer layers.TCP) {
	fmt.Println(layer.SrcPort)
}

func handle_udpl(layer layers.UDP) {
	fmt.Println(layer)
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
				&sniffer.layers.udpl,
			)

			found := []gopacket.LayerType{}
			parser.DecodeLayers(packet.Data(), &found)

			for _, layer := range found {
				if layer == layers.LayerTypeEthernet {
					// handle_ethl(sniffer.layers.ethl)

				} else if layer == layers.LayerTypeIPv4 {
					handle_ip4l(sniffer.layers.ip4l)
				
				} else if layer == layers.LayerTypeIPv6 {
					handle_ip6l(sniffer.layers.ip6l)
				
				} else if layer == layers.LayerTypeTCP {
					handle_tpcl(sniffer.layers.tcpl)
				
				} else if layer == layers.LayerTypeUDP {
					handle_udpl(sniffer.layers.udpl)
				} // TODO: handle ICMP
			}
		}
	}
}

func Init_Sniffer(options *Opts) *Sniffer {
	var sniffer *Sniffer = new(Sniffer)
	sniffer.options = options
	sniffer.Status.Running = true
	return sniffer
}
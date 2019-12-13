package sniffer

import (
    // "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
)

func enumerate_devices(sniffer *Sniffer) {
	// devices, _ := pcap.FindAllDevs()
	// for _, device := range devices {
		handle, err := pcap.OpenLive(
			"wlp1s0",
			sniffer.options.snaplen,
			sniffer.options.promiscuous,
			sniffer.options.timeout,
		)

		if err == nil {
			// fmt.Println(device.Name)
			sniffer.device.handle = handle
		}
	// }
}

func Init_Pacapture(sniffer *Sniffer) {
	enumerate_devices(sniffer);
	sniffer.packsrc = gopacket.NewPacketSource(
		sniffer.device.handle,
		sniffer.device.handle.LinkType(),
	)
}
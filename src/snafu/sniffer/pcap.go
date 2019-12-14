package sniffer

import (
    "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
)

func valid_device(dev string, sniffer *Sniffer) *pcap.Handle {
	handle, err := pcap.OpenLive(
		dev,
		sniffer.options.Snaplen,
		sniffer.options.Promiscuous,
		sniffer.options.Timeout,
	)

	if err == nil {
		return handle
	}

	return nil
}

func enumerate_devices(sniffer *Sniffer) {
	devices, _ := pcap.FindAllDevs()

	for _, device := range devices {
		fmt.Println("found device " + device.Name)
		handle := valid_device(device.Name, sniffer)
		if handle != nil {
			sniffer.device.handle = handle
			break
		}
	}
}

func Init_Pacapture(sniffer *Sniffer) {
	var handle = valid_device(sniffer.options.Device, sniffer)

	if handle == nil {
		fmt.Println("Could not use " + sniffer.options.Device, "enumerating devices")
		enumerate_devices(sniffer);
	} else {
		sniffer.device.handle = handle
	}

	if err := sniffer.device.handle.SetBPFFilter(sniffer.options.Protocol); err != nil {
		fmt.Println("Invalid BPF argument, opening on all ports...")
		sniffer.options.Promiscuous = true
	}

	sniffer.packsrc = gopacket.NewPacketSource(
		sniffer.device.handle,
		sniffer.device.handle.LinkType(),
	)
}
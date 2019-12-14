package main

import (
	"os"
	"fmt"
	"time"
	"flag"
	"bufio"
	"snafu/sniffer"
)

func live(sniffer *sniffer.Sniffer) {
	reader := bufio.NewReader(os.Stdin)
	for sniffer.Status.Running {
		fmt.Print("> ")
		text, _ := reader.ReadString('\n')
		if text == "quit\n" || text == "exit\n" || text == "kill\n" {
			sniffer.Mux.Lock()
			sniffer.Status.Running = false
			sniffer.Mux.Unlock()
		}
	}
}

func configure_opts() *sniffer.Opts {
	var opts *sniffer.Opts = new(sniffer.Opts)

	opts.Snaplen = int32(*flag.Int("sl", 1024, "snapshot length"))

	opts.Promiscuous = *flag.Bool("pi", true, "promiscuous mode")
	
	opts.Device = *flag.String("dev", "wlp1s0", "network device")

	// https://biot.com/capstats/bpf.html
	opts.Protocol = *flag.String("bpf", "", "Packet filter instructions")
	
	opts.Timeout = time.Duration((*flag.Int("time", 3, "time in seconds"))) * time.Second

	return opts
}

func main() {
	var snafu *sniffer.Sniffer
	var opts *sniffer.Opts

	if os.Geteuid() == 0 {
		opts = configure_opts()
		snafu = sniffer.Init_Sniffer(opts)
		sniffer.Init_Pacapture(snafu)

		go sniffer.Sniff(snafu)
		live(snafu)		
	} else {
		fmt.Println("Run as root to gain device access: 'sudo ./snafu <args>'")
	}
}
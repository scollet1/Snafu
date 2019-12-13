package main

import (
	"os"
	"fmt"
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

func main() {
	var snafu *sniffer.Sniffer
	var opts *sniffer.Opts

	snafu = sniffer.Init_Sniffer(opts)
	sniffer.Init_Pacapture(snafu)

	go sniffer.Sniff(snafu)
	live(snafu)
}
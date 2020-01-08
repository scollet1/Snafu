# GoS
Go Packet Sniffer

# What
A generic packet sniffer in Golang

# Why
I am learning Golang

# How

## Install

### Installing Golang

### Installing Snafu
`./install`

## Run
Running Snafu requires root privileges because we are reading promiscuously from raw sockets

`./run` should ask you for those privileges

# Extra
This program uses Google's [gopacket](https://github.com/google/gopacket) library to process packets. This means Snafu is somewhat dependency heavy.

Luckily it's only one package.

Unfortunately it's the whole package.

Snafu runs two threads like a CL server. One thread listens to commands. The other prints information to some file descriptor. Right now it prints nothing of importance to nowhere important but it's quite simple to engineer that functionality.

Snafu can listen with custom configurations including device, promiscuous mode, and even ingest BPF commands.

Snafu works by finding the first valid device (by default I have it set to wireless because my laptop doesn't have an ethernet port) if none is targeted on the command line. It validates the device by returning a device handle, then attempts to apply a BPF command. After that it listens on the device and endlessly enumerates all packets until the end of time (or the user exits the program), stripping relevant headers and doing whatever needs to be done with them.


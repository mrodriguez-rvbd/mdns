package main

import (
	"net"

	"github.com/riverbed-cto/mdns"
	"golang.org/x/net/ipv4"
)

func main() {
	addr, err := net.ResolveUDPAddr("udp", mdns.DefaultAddress)
	if err != nil {
		panic(err)
	}

	l, err := net.ListenUDP("udp4", addr)
	if err != nil {
		panic(err)
	}

	config := &mdns.Config{}
	config.AddARecord("catalog.gibson.local.", nil, true)
	_, err = mdns.Server(ipv4.NewPacketConn(l), config)
	if err != nil {
		panic(err)
	}
	select {}
}

package main

import (
	"context"
	"fmt"
	"net"

	"golang.org/x/net/dns/dnsmessage"

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

	server, err := mdns.Server(ipv4.NewPacketConn(l), &mdns.Config{})
	if err != nil {
		panic(err)
	}
	answer, src, err := server.Query(context.TODO(), "catalog.gibson.local", dnsmessage.TypeA)
	fmt.Println(answer)
	fmt.Println(src) // Where does it come from
	fmt.Println(err)
}

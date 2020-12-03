package main

import (
	"context"
	"fmt"
	"net"

	"github.com/miekg/dns"
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
	//answers, src, err := server.Query(context.TODO(), "catalog.gibson.local", dns.TypeSRV)
	var ip, port string
	answers, _, err := server.Query(context.TODO(), "_catalog._tcp.local", dns.TypeSRV)
	if err == nil {
		for _, a := range *answers {
			if rr, ok := a.(*dns.A); ok {
				//fmt.Printf("%s (A)-> %s\n", rr.Header().Name, rr.A.String())
				ip = rr.A.String()
			}
			if rr, ok := a.(*dns.SRV); ok {
				//fmt.Printf("%s (SRV)-> %s %s %d\n", rr.Header().Name, rr.Hdr.Name, rr.Target, rr.Port)
				port = fmt.Sprintf("%d", rr.Port)
			}
		}
		if ip != "" && port != "" {
			fmt.Printf("Found catalog at %s:%s\n", ip, port)
		}

		//fmt.Println(src) // Where does it come from
	}

}

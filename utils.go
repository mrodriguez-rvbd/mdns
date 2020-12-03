package mdns

import (
	"math/big"
	"net"
)

func ipToBytes(ip net.IP) (out [4]byte) {
	rawIP := ip.To4()
	if rawIP == nil {
		return
	}

	ipInt := big.NewInt(0)
	ipInt.SetBytes(rawIP)
	copy(out[:], ipInt.Bytes())
	return
}

func interfaceForRemote(remote string) (net.IP, error) {
	conn, err := net.Dial("udp", remote)
	if err != nil {
		return nil, err
	}

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	if err := conn.Close(); err != nil {
		return nil, err
	}

	return localAddr.IP, nil
}

func addDot(name string) string {
	x := len(name)
	if name[:x-1] != "." {
		return name + "."
	}
	return name

}

package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ken-schneider/linux-listener/pkg/utils"
	"golang.org/x/net/ipv4"
)

func main() {

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM, syscall.SIGABRT, syscall.SIGKILL)

	// //protocol := "icmp"
	netaddr, err := net.ResolveIPAddr("ip4", "127.0.0.1")
	if err != nil {
		panic(err)
	}

	// icmpConn, err := net.ListenPacket("ip4:icmp", netaddr.IP.String())
	// if err != nil {
	// 	panic(err)
	// }
	// defer icmpConn.Close()
	// // RawConn is necessary to set the TTL and ID fields
	// rawIcmpConn, err := ipv4.NewRawConn(icmpConn)
	// if err != nil {
	// 	panic(err)
	// }

	tcpConn, err := net.ListenPacket("ip4:tcp", netaddr.IP.String())
	if err != nil {
		panic(err)
	}
	defer tcpConn.Close()
	// RawConn is necessary to set the TTL and ID fields
	rawTcpConn, err := ipv4.NewRawConn(tcpConn)
	if err != nil {
		panic(err)
	}

	//go handlePackets(rawIcmpConn, "icmp")
	go handlePackets(rawTcpConn, "tcp")
	//go listenToTheRawestSocket()

	<-stop
	fmt.Println("Received Ctrl-C...")
}

func handlePackets(conn *ipv4.RawConn, listenerType string) error {
	buf := make([]byte, 1024)
	for {
		now := time.Now()
		conn.SetReadDeadline(now.Add(time.Millisecond * 100))
		header, packet, _, err := conn.ReadFrom(buf)
		if err != nil {
			if nerr, ok := err.(*net.OpError); ok {
				if nerr.Timeout() {
					continue
				}
				return err
			}
		}
		if header.TTL == 42 {
			fmt.Printf("Listener: %s\n", listenerType)
			fmt.Printf("Header: %+v\n", header)
			fmt.Printf("Packet: %+v\n\n", packet)

			rawPacket := utils.ReadRawPacket(buf)
			err := utils.LayerCat(rawPacket)
			if err != nil {
				fmt.Printf("failed to cat packet: %s", err.Error())
			}
		}
	}
}

// func handleSynPackets(conn *ipv4.RawConn, listenerType string, port int, flags []byte) error {

// }

// func listenToTheRawestSocket() {
// 	// notes to self. This straight up doesn't work. I also tried AF_INET and IPPROTO_IP and
// 	// failed but with a different error.
// 	//
// 	// I can set it to listen to TCP instead but at that point why bother with the file descriptor?
// 	// If we get to a point with performance where investigating this is necessary again we can revisit.
// 	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
// 	if err != nil {
// 		panic(err)
// 	}
// 	defer syscall.Close(fd)

// 	// Bind the socket to all interfaces
// 	// addr := syscall.SockaddrInet4{Port: 0, Addr: [4]byte{0, 0, 0, 0}}
// 	// if err = syscall.Bind(fd, &addr); err != nil {
// 	// 	panic(err)
// 	// }

// 	// if err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
// 	// 	panic(err)
// 	// }

// 	buf := make([]byte, 1024)
// 	for {
// 		n, from, err := syscall.Recvfrom(fd, buf, 0)
// 		if err != nil {
// 			fmt.Printf("Failed to receive data: %s", err.Error())
// 			continue
// 		}
// 		sa := from.(*syscall.SockaddrLinklayer)
// 		fmt.Printf("Recveived %d bytes from %v\n", n, sa.Addr)

// 		header, err := ipv4.ParseHeader(buf[:n])
// 		if err != nil {
// 			fmt.Printf("failed to parse header: %s", err.Error())
// 			continue
// 		}
// 		fmt.Printf("Header: %+v\n", header)
// 		fmt.Printf("Payload: %x\n\n", buf[header.Len:n])
// 	}
// }

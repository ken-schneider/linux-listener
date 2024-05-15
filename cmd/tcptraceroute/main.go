package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ken-schneider/linux-listener/pkg/utils"
	"golang.org/x/net/ipv4"
)

func main() {
	netaddr, err := net.ResolveIPAddr("ip4", "127.0.0.1")
	if err != nil {
		panic(err)
	}

	icmpConn, err := net.ListenPacket("ip4:icmp", netaddr.IP.String())
	if err != nil {
		panic(err)
	}
	defer icmpConn.Close()
	// RawConn is necessary to set the TTL and ID fields
	rawIcmpConn, err := ipv4.NewRawConn(icmpConn)
	if err != nil {
		panic(err)
	}

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

	start := time.Now()
	listenAnyPacket(rawIcmpConn, rawTcpConn, 10*time.Second)
	fmt.Printf("Duration: %s\n", time.Since(start).String())
}

// listenAnyPacket should start up a listener that returns at the first received packet or
// after the timeout
func listenAnyPacket(icmpConn *ipv4.RawConn, tcpConn *ipv4.RawConn, timeout time.Duration) {
	var err1 error
	var err2 error
	var wg sync.WaitGroup
	wg.Add(2)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	go func() {
		defer wg.Done()
		defer cancel()
		err1 = handlePackets(ctx, tcpConn, "tcp")
	}()
	go func() {
		defer wg.Done()
		defer cancel()
		err2 = handlePackets(ctx, icmpConn, "icmp")
	}()
	wg.Wait()

	if err1 != nil {
		fmt.Printf("tcp listener error: %s\n", err1.Error())
	}
	if err2 != nil {
		fmt.Printf("icmp listener error: %s\n", err2.Error())
	}
}

// handlePackets in its current implementation should listen for the first matching
// packet on the connection and then return. If no packet is received within the
// timeout, it should return a timeout exceeded error
func handlePackets(ctx context.Context, conn *ipv4.RawConn, listener string) error {
	buf := make([]byte, 1024)
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("canceled")
		default:
		}
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
			fmt.Printf("Listener: %+v\n", listener)
			fmt.Printf("Header: %+v\n", header)
			fmt.Printf("Packet: %+v\n\n", packet)

			rawPacket := utils.ReadRawPacket(buf)
			err := utils.LayerCat(rawPacket)
			if err != nil {
				fmt.Printf("failed to cat packet: %s", err.Error())
			}
			return nil
		}
	}
}

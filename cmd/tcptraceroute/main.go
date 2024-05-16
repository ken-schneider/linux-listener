package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/ken-schneider/linux-listener/pkg/utils"
	"golang.org/x/net/ipv4"
)

type (
	CanceledError string
)

const (
	destHost = "172.253.63.101"
	destPort = 80
)

func main() {
	destIP := net.ParseIP(destHost)
	tcpAddr, err := utils.LocalAddrForTCP4Host(destIP, destPort)
	if err != nil {
		panic(err)
	}

	icmpConn, err := net.ListenPacket("ip4:icmp", tcpAddr.IP.String())
	if err != nil {
		panic(err)
	}
	defer icmpConn.Close()
	// RawConn is necessary to set the TTL and ID fields
	rawIcmpConn, err := ipv4.NewRawConn(icmpConn)
	if err != nil {
		panic(err)
	}

	tcpConn, err := net.ListenPacket("ip4:tcp", tcpAddr.IP.String())
	if err != nil {
		panic(err)
	}
	defer tcpConn.Close()
	fmt.Printf("Listening for TCP on: %s\n", tcpAddr.IP.String()+":"+tcpAddr.AddrPort().String())
	// RawConn is necessary to set the TTL and ID fields
	rawTcpConn, err := ipv4.NewRawConn(tcpConn)
	if err != nil {
		panic(err)
	}

	start := time.Now()
	for i := 1; i <= 30; i++ {
		flags := byte(0)
		flags |= utils.SYN
		tcpHeader, tcpPacket, err := utils.CreateRawTCPPacket(tcpAddr.IP, tcpAddr.AddrPort().Port(), destIP, uint16(destPort), i, flags)
		if err != nil {
			fmt.Printf("failed to create TCP packet with TTL: %d, error: %s\n", i, err.Error())
		}

		fmt.Printf("Sending on port: %d\n", tcpAddr.AddrPort().Port())

		err = utils.SendPacket(rawTcpConn, tcpHeader, tcpPacket)
		if err != nil {
			fmt.Printf("failed to send TCP SYN: %s\n", err.Error())
		}

		listenAnyPacket(rawIcmpConn, rawTcpConn, 2*time.Second, tcpAddr.IP, tcpAddr.AddrPort().Port(), destIP, uint16(destPort))
		fmt.Printf("Finished loop for TTL %d\n\n", i)
	}
	listenAnyPacket(rawIcmpConn, rawTcpConn, 10*time.Second, tcpAddr.IP, tcpAddr.AddrPort().Port(), destIP, uint16(destPort))
	fmt.Printf("Duration: %s\n", time.Since(start).String())
}

// listenAnyPacket should start up a listener that returns at the first received packet or
// after the timeout
func listenAnyPacket(icmpConn *ipv4.RawConn, tcpConn *ipv4.RawConn, timeout time.Duration, localIP net.IP, localPort uint16, remoteIP net.IP, remotePort uint16) {
	var err1 error
	var err2 error
	var wg sync.WaitGroup
	wg.Add(2)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	go func() {
		defer wg.Done()
		defer cancel()
		err1 = handlePackets(ctx, tcpConn, "tcp", localIP, localPort, remoteIP, remotePort)
	}()
	go func() {
		defer wg.Done()
		defer cancel()
		err2 = handlePackets(ctx, icmpConn, "icmp", localIP, localPort, remoteIP, remotePort)
	}()
	wg.Wait()

	if err1 != nil && err2 != nil {
		_, ok1 := err1.(CanceledError)
		_, ok2 := err2.(CanceledError)
		if ok1 && ok2 {
			fmt.Println("Timed out while awaiting repsonse")
		} else {
			fmt.Printf("TCP Listener Err: %s\n", err1.Error())
			fmt.Printf("ICMP Listener Err: %s\n", err2.Error())
		}
	}

	// if one of them is not an error we should print out some kind of packet
}

// handlePackets in its current implementation should listen for the first matching
// packet on the connection and then return. If no packet is received within the
// timeout, it should return a timeout exceeded error
func handlePackets(ctx context.Context, conn *ipv4.RawConn, listener string, localIP net.IP, localPort uint16, remoteIP net.IP, remotePort uint16) error {
	buf := make([]byte, 1024)
	for {
		select {
		case <-ctx.Done():
			return CanceledError("listener canceled")
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
		if listener == "icmp" {
			err := parseICMP(header, packet)
			if err != nil {
				fmt.Printf("failed to parse ICMP packet: %s\n", err.Error())
			}
		}
		if listener == "tcp" {
			err := parseTCP(header, packet, localIP, localPort, remoteIP, remotePort)
			if err != nil {
				fmt.Printf("failed to parse TCP packet: %s\n", err.Error())
			}
		}
	}
}

func parseICMP(header *ipv4.Header, payload []byte) error {
	packetBytes, err := utils.MarshalPacket(header, payload)
	if err != nil {
		return fmt.Errorf("failed to marshal packet: %w", err)
	}

	packet := utils.ReadRawPacket(packetBytes)

	src, _, icmpType, err := utils.ParseICMPPacket(packet)
	if err != nil {
		return fmt.Errorf("failed to parse ICMP packet: %w", err)
	}

	if icmpType == layers.ICMPv4TypeDestinationUnreachable || icmpType == layers.ICMPv4TypeTimeExceeded {
		fmt.Printf("Received ICMP reply: %s from %s\n", icmpType.String(), src.String())
	} else {
		fmt.Printf("Received other ICMP reply: %s from %s\n", icmpType.String(), src.String())
	}

	return nil
}

func parseTCP(header *ipv4.Header, payload []byte, localIP net.IP, localPort uint16, remoteIP net.IP, remotePort uint16) error {
	packetBytes, err := utils.MarshalPacket(header, payload)
	if err != nil {
		return fmt.Errorf("failed to marshal packet: %w", err)
	}

	packet := utils.ReadRawPacket(packetBytes)
	source, sourcePort, dest, destPort, err := utils.ParseTCPPacket(packet)
	if err != nil {
		return fmt.Errorf("failed to parse TCP packet: %w", err)
	}

	if source.Equal(remoteIP) && sourcePort == remotePort && dest.Equal(localIP) && destPort == localPort {
		fmt.Printf("Received TCP Reply from: %s:%d\n", source.String(), sourcePort)
	}

	return nil
}

func (c CanceledError) Error() string {
	return string(c)
}

package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/ken-schneider/linux-listener/pkg/utils"
)

const (
	URG = 1 << 5
	ACK = 1 << 4
	PSH = 1 << 3
	RST = 1 << 2
	SYN = 1 << 1
	FIN = 1 << 0
)

func main() {
	fmt.Println("Hello, sender!")

	src := net.ParseIP("10.0.4.18")
	dst := net.ParseIP("127.0.0.1")

	flags := byte(0)
	flags |= ACK
	flags |= RST

	// tcpHeader, tcpPayload, err := createRawTCPPacket(src, 80, dst, 12345, 42, flags)
	// if err != nil {
	// 	log.Fatalf("failed to create packet: %s", err.Error())
	// }

	// rawPacket, err := marshalPacket(tcpHeader, tcpPayload)
	// if err != nil {
	// 	log.Fatalf("failed to marshal packet: %s", err.Error())
	// }

	// packet := utils.ReadRawPacket(rawPacket)

	// err = utils.LayerCat(packet)
	// if err != nil {
	// 	log.Fatalf("failed to cat packet: %s", err.Error())
	// }

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
	rawICMPConn, err := ipv4.NewRawConn(icmpConn)
	if err != nil {
		panic(err)
	}

	//sendPacket(rawICMPConn, tcpHeader, tcpPayload)

	icmpHdr, icmpPayload, err := createRawICMPEchoReply(src, dst, 42)
	if err != nil {
		log.Fatalf("failed to create packet: %s", err.Error())
	}

	rawPacket, err := marshalPacket(icmpHdr, icmpPayload)
	if err != nil {
		log.Fatalf("failed to marshal packet: %s", err.Error())
	}

	packet := utils.ReadRawPacket(rawPacket)

	err = utils.LayerCat(packet)
	if err != nil {
		log.Fatalf("failed to cat packet: %s", err.Error())
	}

	sendPacket(rawICMPConn, icmpHdr, icmpPayload)

	fmt.Println("Let's go!")
}

func sendPacket(rawConn *ipv4.RawConn, header *ipv4.Header, payload []byte) error {
	if err := rawConn.WriteTo(header, payload, nil); err != nil {
		return err
	}

	time.Sleep(100 * time.Millisecond)
	return nil
}

func createRawTCPPacket(sourceIP net.IP, sourcePort uint16, destIP net.IP, destPort uint16, ttl int, flags byte) (*ipv4.Header, []byte, error) {
	ipHdr := ipv4.Header{
		Version:  4,
		Len:      20,
		TTL:      ttl,
		Protocol: 6, // TCP
		Dst:      destIP,
		Src:      sourceIP,
	}

	// Create TCP syn packet
	tcpPacket := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpPacket[0:2], sourcePort) // source port
	binary.BigEndian.PutUint16(tcpPacket[2:4], destPort)   // destination port
	tcpPacket[13] = flags

	return &ipHdr, tcpPacket, nil
}

func createRawICMPEchoReply(sourceIP net.IP, destIP net.IP, ttl int) (*ipv4.Header, []byte, error) {
	ipHdr := ipv4.Header{
		Version:  4,
		Len:      20,
		TTL:      ttl,
		Protocol: 1, // ICMP
		Dst:      destIP,
		Src:      sourceIP,
	}

	payload := []byte("testing 1, 2, 3")
	icmpHdr := icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: &icmp.Echo{
			ID:   12345,
			Seq:  1,
			Data: payload,
		},
	}

	packet, err := icmpHdr.Marshal(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal ICMP: %w", err)
	}

	return &ipHdr, packet, nil
}

func marshalPacket(header *ipv4.Header, payload []byte) ([]byte, error) {
	hdrBytes, err := header.Marshal()
	if err != nil {
		return nil, err
	}

	packet := make([]byte, len(hdrBytes)+len(payload))
	copy(packet[:len(hdrBytes)], hdrBytes)
	copy(packet[len(hdrBytes):], payload)

	return packet, nil
}

package utils

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
)

const (
	URG = 1 << 5
	ACK = 1 << 4
	PSH = 1 << 3
	RST = 1 << 2
	SYN = 1 << 1
	FIN = 1 << 0
)

// ReadRawPacket creates a gopacket given a byte array
// containing a packet
func ReadRawPacket(rawPacket []byte) gopacket.Packet {
	return gopacket.NewPacket(rawPacket, layers.LayerTypeIPv4, gopacket.Default)
}

// LayerCat prints the IPv4, TCP, and ICMP layers of
// a packet then lists all layers by type
func LayerCat(pkt gopacket.Packet) error {
	if ipLayer := pkt.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		fmt.Println("This is an IPv4 packet!")
		tcp, ok := ipLayer.(*layers.IPv4)
		if !ok {
			return fmt.Errorf("failed to assert IPv4 layer type")
		}
		fmt.Printf("IPv4 layer: %+v\n", tcp)
	}

	if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		fmt.Println("This is a TCP packet!")
		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			return fmt.Errorf("failed to assert TCP layer type")
		}
		fmt.Printf("TCP layer: %+v\n", tcp)
	}

	if icmpLayer := pkt.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		fmt.Println("This is an ICMPv4 packet!")
		tcp, ok := icmpLayer.(*layers.ICMPv4)
		if !ok {
			return fmt.Errorf("failed to assert ICMPv4 layer type")
		}
		fmt.Printf("ICMPv4 layer: %+v\n", tcp)
	}

	for _, layer := range pkt.Layers() {
		fmt.Println("Packet layer: ", layer.LayerType())
	}

	return nil
}

// CreateRawTCPPacket creates a TCP packet with the specified parameters
func CreateRawTCPPacket(sourceIP net.IP, sourcePort uint16, destIP net.IP, destPort uint16, ttl int, flags byte) (*ipv4.Header, []byte, error) {
	ipHdr := ipv4.Header{
		Version:  4,
		Len:      20,
		TTL:      ttl,
		Protocol: 6, // TCP
		Dst:      destIP,
		Src:      sourceIP,
	}

	// Create TCP packet with the specified flags
	// we'll need to vary sequence number and do
	// some other manipulation for a paris-traceroute
	// like accuracy but for now let's just get a trace
	tcpPacket := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpPacket[0:2], sourcePort) // source port
	binary.BigEndian.PutUint16(tcpPacket[2:4], destPort)   // destination port
	tcpPacket[13] = flags

	// TODO: calculate checksum

	return &ipHdr, tcpPacket, nil
}

// MarshalPacket takes in an ipv4 header and a payload and copies
// them into a newly allocated []byte
func MarshalPacket(header *ipv4.Header, payload []byte) ([]byte, error) {
	hdrBytes, err := header.Marshal()
	if err != nil {
		return nil, err
	}

	packet := make([]byte, len(hdrBytes)+len(payload))
	copy(packet[:len(hdrBytes)], hdrBytes)
	copy(packet[len(hdrBytes):], payload)

	return packet, nil
}

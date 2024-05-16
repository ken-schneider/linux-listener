package utils

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"

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

func LocalAddrForTCP4Host(destIP net.IP, destPort int) (*net.TCPAddr, error) {
	// for macOS support we'd need to change this port to something like 53 as per Dublin Traceroute
	// this is a quick way to get the local address for connecting to the host
	conn, err := net.Dial("tcp4", net.JoinHostPort(destIP.String(), strconv.Itoa(destPort)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	localAddr := conn.LocalAddr()

	localTCPAddr, ok := localAddr.(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("invalid address type for %s: want %T, got %T", localAddr, localTCPAddr, localAddr)
	}

	return localTCPAddr, nil
}

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

func ParseICMPPacket(pkt gopacket.Packet) (net.IP, net.IP, layers.ICMPv4TypeCode, error) {
	var src net.IP
	var dst net.IP
	var typeCode layers.ICMPv4TypeCode

	if ipLayer := pkt.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		//fmt.Println("This is an IPv4 packet!")
		ip, ok := ipLayer.(*layers.IPv4)
		if !ok {
			return net.IP{}, net.IP{}, layers.ICMPv4TypeCode(0), fmt.Errorf("failed to assert IPv4 layer type")
		}
		//fmt.Printf("IPv4 layer: %+v\n", ip)

		src = ip.SrcIP
		dst = ip.DstIP
	}

	if icmpLayer := pkt.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		//fmt.Println("This is an ICMPv4 packet!")
		icmp, ok := icmpLayer.(*layers.ICMPv4)
		if !ok {
			return net.IP{}, net.IP{}, layers.ICMPv4TypeCode(0), fmt.Errorf("failed to assert ICMPv4 layer type")
		}
		//fmt.Printf("ICMPv4 layer: %+v\n", icmp)
		typeCode = icmp.TypeCode
	}

	return src, dst, typeCode, nil
}

func ParseTCPPacket(pkt gopacket.Packet) (net.IP, uint16, net.IP, uint16, error) {
	var src net.IP
	var srcPort uint16
	var dst net.IP
	var dstPort uint16

	if ipLayer := pkt.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		//fmt.Println("This is an IPv4 packet!")
		ip, ok := ipLayer.(*layers.IPv4)
		if !ok {
			return net.IP{}, 0, net.IP{}, 0, fmt.Errorf("failed to assert IPv4 layer type")
		}
		//fmt.Printf("IPv4 layer: %+v\n", ip)

		src = ip.SrcIP
		dst = ip.DstIP
	}

	if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		//fmt.Println("This is a TCP packet!")
		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			return net.IP{}, 0, net.IP{}, 0, fmt.Errorf("failed to assert TCP layer type")
		}
		//fmt.Printf("TCP layer: %+v\n", tcp)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
	}

	return src, srcPort, dst, dstPort, nil
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
	binary.BigEndian.PutUint32(tcpPacket[4:8], 0)          // sequence number
	binary.BigEndian.PutUint32(tcpPacket[8:12], 0)         // ack number
	tcpPacket[12] = 5 << 4                                 // header length
	tcpPacket[13] = flags
	binary.BigEndian.PutUint16(tcpPacket[14:16], 1024) // window size

	cs := tcpChecksum(&ipHdr, tcpPacket)
	binary.BigEndian.PutUint16(tcpPacket[16:18], cs) // checksum

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

func SendPacket(rawConn *ipv4.RawConn, header *ipv4.Header, payload []byte) error {
	if err := rawConn.WriteTo(header, payload, nil); err != nil {
		return err
	}

	return nil
}

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return uint16(^sum)
}

func tcpChecksum(ipHdr *ipv4.Header, tcpHeader []byte) uint16 {
	pseudoHeader := []byte{}
	pseudoHeader = append(pseudoHeader, ipHdr.Src.To4()...)
	pseudoHeader = append(pseudoHeader, ipHdr.Dst.To4()...)
	pseudoHeader = append(pseudoHeader, 0) // reserved
	pseudoHeader = append(pseudoHeader, byte(ipHdr.Protocol))
	pseudoHeader = append(pseudoHeader, 0, byte(len(tcpHeader))) // tcp length

	return checksum(append(pseudoHeader, tcpHeader...))
}

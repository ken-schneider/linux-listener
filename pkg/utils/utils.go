package utils

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func ReadRawPacket(rawPacket []byte) gopacket.Packet {
	return gopacket.NewPacket(rawPacket, layers.LayerTypeIPv4, gopacket.Default)
}

// LayerCat prints the IPv4 and TCP layers of
// a packet then lists all layers by type
func LayerCat(pkt gopacket.Packet) error {
	if ipLayer := pkt.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		fmt.Println("This is a TCP packet!")
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

	for _, layer := range pkt.Layers() {
		fmt.Println("Packet layer: ", layer.LayerType())
	}

	return nil
}

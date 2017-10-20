package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

var (
	replacement string
)

func init() {
	flag.StringVar(&replacement, "replace", "X", "String to replace packet contents with")
}

func blackout(r gopacket.PacketDataSource, lt layers.LinkType, w *pcapgo.Writer) (int, error) {
	totalPackets := 0

	ps := gopacket.NewPacketSource(r, lt)
	for packet := range ps.Packets() {
		fmt.Printf("%v", packet)
		//w.WritePacket(gopacket.CaptureInfo{...}, data1)
		totalPackets++
	}
	return totalPackets, nil

}

func main() {
	flag.Parse()

	if len(flag.Args()) != 2 {
		fmt.Printf("Usage: %s infile outfile [-replace XYZ]\n", os.Args[0])
		os.Exit(1)
	}

	input := flag.Args()[0]
	output := flag.Args()[1]

	inf, _ := os.Open(input)
	defer inf.Close()
	r, err := pcapgo.NewReader(inf)

	outf, _ := os.Create(output)
	defer outf.Close()
	w := pcapgo.NewWriter(outf)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet) // new file, must do this.

	packets, err := blackout(r, r.LinkType(), w)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%d packets rewritten\n", packets)
}

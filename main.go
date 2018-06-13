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

	replacementData := []byte("")

	totalPackets := 0

	ps := gopacket.NewPacketSource(r, lt)
	for packet := range ps.Packets() {
		totalPackets++
		//fmt.Printf("%v", packet)
		//w.WritePacket(gopacket.CaptureInfo{...}, data1)
		if app := packet.ApplicationLayer(); app != nil {
			for len(replacementData) < len(app.LayerContents()) {
				replacementData = append(replacementData, replacement...)
			}
			copy(app.LayerContents()[:], replacementData[0:len(app.LayerContents())])
		}
		w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
	}
	return totalPackets, nil

}

func main() {
	flag.Parse()

	if len(flag.Args()) != 2 {
		fmt.Printf("Usage: %s [-replace XYZ] infile outfile\n", os.Args[0])
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

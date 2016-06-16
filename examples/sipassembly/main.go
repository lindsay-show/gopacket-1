// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// This binary provides sample code for using the gopacket TCP assembler and TCP
// stream reader.  It reads packets off the wire and reconstructs SIP requests
// it sees, logging them.
package main

import (
	"flag"
	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/color"
	"github.com/google/gopacket/examples/sip"
	"github.com/google/gopacket/examples/util"
	//"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	//"github.com/google/gopacket/tcpassembly"
	//"github.com/google/gopacket/tcpassembly/tcpreader"
	"bufio"
	"fmt"
	"log"
	"strings"
)

var iface = flag.String("i", "en0", "Interface to get packets from")
var fname = flag.String("r", "", "Filename to read from, overrides -i")
var snaplen = flag.Int("s", 1600, "SnapLen for pcap packet capture")
var filter = flag.String("f", "udp port 5260", "BPF filter for pcap")
var logAllPackets = flag.Bool("v", false, "Logs every packet in great detail")

func main() {
	defer util.Run()()
	var handle *pcap.Handle
	var err error

	// Set up pcap packet capture
	if *fname != "" {
		log.Printf("Reading from pcap dump %q", *fname)
		handle, err = pcap.OpenOffline(*fname)
	} else {
		log.Printf("Starting capture on interface %q", *iface)
		handle, err = pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
	}
	if err != nil {
		log.Fatal(err)
	}

	if err := handle.SetBPFFilter(*filter); err != nil {
		log.Fatal(err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		printPacketInfo(packet)
	}
}
func printPacketInfo(packet gopacket.Packet) {

	// When iterating through packet.Layers() above,
	// if it lists Payload layer then that is the same as
	// this applicationLayer. applicationLayer contains the payload
	applicationLayer := packet.ApplicationLayer()
	/*if applicationLayer != nil {
		fmt.Println("Application layer/Payload found.")
		fmt.Printf("%s\n", applicationLayer.Payload())
	}*/

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
	//  Set up assembly(UDP)
	var tvi = []string{string(applicationLayer.Payload())}
	for i := 0; i < len(tvi); i++ {
		b := bufio.NewReader(strings.NewReader(tvi[i]))
		msg, _ := sip.ReadMessage(b)
		//fmt.Println("MessageHeader:")
		for headerName, headerContext := range msg.GetHeader() {
			for _, subheaderContext := range headerContext {
				fmt.Printf("%s: %s\n", color.Blue(headerName), subheaderContext)
			}
		}
		//fmt.Println("MessageBody:")
		fmt.Println(msg.GetBody())
	}

}

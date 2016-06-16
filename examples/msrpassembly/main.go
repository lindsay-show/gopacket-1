// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// This binary provides sample code for using the gopacket TCP assembler and TCP
// stream reader.  It reads packets off the wire and reconstructs MSRP requests
// it sees, logging them.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/color"
	"github.com/google/gopacket/examples/msrp"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"io"
	"log"
	"time"
)

var iface = flag.String("i", "en0", "Interface to get packets from")
var fname = flag.String("r", "", "Filename to read from, overrides -i")
var snaplen = flag.Int("s", 1600, "SnapLen for pcap packet capture")
var filter = flag.String("f", "tcp port 51273 ", "BPF filter for pcap")
var logAllPackets = flag.Bool("v", false, "Logs every packet in great detail")

// Build a simple MSRP request parser using tcpassembly.StreamFactory and tcpassembly.Stream interfaces

// msrpStreamFactory implements tcpassembly.StreamFactory
type msrpStreamFactory struct{}

// msrpStream will handle the actual decoding of msrp requests.
type msrpStreamHandler struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (m *msrpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	msrpstream := &msrpStreamHandler{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go msrpstream.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &msrpstream.r
}
func (m *msrpStreamHandler) run() {
	// Do something here that reads all of the ReaderStream, or your assembly
	buf := bufio.NewReader(&m.r)
	for {
		// msrp request and response
		req, err := msrp.ReadRequest(buf)
		if err == io.EOF {
			// We must read until we see an EOF... very important!
			return
		} else if req != nil {
			//log.Println("Received request from stream", m.net, m.transport)
			fmt.Println(color.Green("Request:"))
			fmt.Println(req.Proto, "", req.TranscitonID, "", req.Method)
			for header, value := range req.Header {
				for _, subvalue := range value {
					fmt.Printf("%s:%s\n", header, subvalue)
				}
			}
		}
		resp, resperr := msrp.ReadResponse(buf, req)
		if resperr == io.EOF {
			// We must read until we see an EOF... very important!
			return
		} else if resp != nil {
			//log.Println("Received response from stream", m.net, m.transport)
			fmt.Println(color.Blue("Response:"))
			fmt.Println(resp.Proto, resp.TranscitonID, resp.Status)
			for header, value := range resp.Header {
				for _, subvalue := range value {
					fmt.Printf("%s:%s\n", header, subvalue)
				}
			}

		}
		// msrp request
		/*req, err := msrp.ReadRequest(buf)
		if err == io.EOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading stream", m.net, m.transport, ":", err)
		} else {
			bodyBytes := tcpreader.DiscardBytesToEOF(req.Body)
			req.Body.Close()
			log.Println("Received request from stream", m.net, m.transport, ":", req, "with", bodyBytes, "bytes in request body")
		}*/
	}
}

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

	// Set up assembly
	streamFactory := &msrpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	log.Println("reading in packets")
	// Read in packets, pass to assembler.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(time.Minute)
	for {
		select {
		case packet := <-packets:
			// consume data from channel(packets)
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				return
			}
			if *logAllPackets {
				log.Println(packet)
			}
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				log.Println("Unusable packet")
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}
}

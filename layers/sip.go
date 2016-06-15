// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"net"
)

// SIP is the layer for SIP Request headers.
type SIP struct {
	BaseLayer
	Method     string
	RequestURL string
	Proto      string
	Header     head.Header
	buffer     []byte
}

// LayerType returns gopacket.LayerTypeSIP.
func (s *SIP) LayerType() gopacket.LayerType { return LayerTypeSIP }

// DecodeFromBytes decodes the slice into the SIP struct.
func (s *SIP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	s.buffer = s.buffer[:0]

	// since there are no further layers, the baselayer's content is
	// pointing to this layer
	s.BaseLayer = BaseLayer{Contents: data[:len(data)]}
	//TO DO
	return nil
}

func (s *SIP) CanDecode() gopacket.LayerClass {
	return LayerTypeSIP
}
func (s *SIP) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}
func (s *SIP) Payload() []byte {
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (s SIP) SerializeTo(b SerializeBuffer, opts SerializeOptions) error {
	bytes, err := b.PrependBytes(len(p))
	if err != nil {
		return err
	}
	copy(bytes, s)
	return nil
}

// decodeSIP decodes the byte slice into a SIP type. It also
// setups the application Layer in PacketBuilder.
func decodeSIP(data []byte, p gopacket.PacketBuilder) error {
	s := &SIP{}
	err := s.DecodeFromBytes(data, p)
	if err != nil {
		return nil
	}
	p.AddLayer(s)
	p.SetApplicationLayer(s)
	return nil
}

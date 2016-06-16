// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// MSRP Request reading and parsing.

package msrp

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/textproto"
	"strings"
	"sync"
)

type badStringError struct {
	what string
	str  string
}

func (e *badStringError) Error() string { return fmt.Sprintf("%s %q", e.what, e.str) }

type Request struct {
	Proto         string
	TranscitonID  string
	Method        string
	Header        Header
	Body          io.ReadCloser
	ContentLength int64
	Close         bool
	Response      *Response

	//  Header = map[string][]string{
	//     "To-Path": {msrp://1.1.0.10:51272/95521545,tcp}
	//     "From-Path": {msrp://1.1.0.11:1418/55154884,tcp}
	//     "Message-ID": {55183157}
	//     "Byte-Range": {1-2048/822436}
	//     "Failure-Report": {yes}
	//     "Success-Report": {yes}
	//     "Content-Type": {application/octet-stream}
}

// NewRequest returns a new Request given a method and optional body.
func NewRequest(method string, body io.Reader) (*Request, error) {
	rc, ok := body.(io.ReadCloser)
	if !ok && body != nil {
		rc = ioutil.NopCloser(body)
	}
	req := &Request{
		Method: method,
		Proto:  "MSRP",
		Header: make(Header),
		Body:   rc,
	}
	if body != nil {
		switch v := body.(type) {
		case *bytes.Buffer:
			req.ContentLength = int64(v.Len())
		case *bytes.Reader:
			req.ContentLength = int64(v.Len())
		case *strings.Reader:
			req.ContentLength = int64(v.Len())
		}
	}
	return req, nil
}

// parseRequestLine parses "MSRP 95529209 SEND" into its three parts.
func parseRequestLine(line string) (method, transactionID, proto string, ok bool) {
	s1 := strings.Index(line, " ")
	s2 := strings.Index(line[s1+1:], " ")
	if s1 < 0 || s2 < 0 {
		return
	}
	s2 += s1 + 1
	return line[:s1], line[s1+1 : s2], line[s2+1:], true
}

var textprotoReaderPool sync.Pool

func newTextprotoReader(br *bufio.Reader) *textproto.Reader {
	if v := textprotoReaderPool.Get(); v != nil {
		tr := v.(*textproto.Reader)
		tr.R = br
		return tr
	}
	return textproto.NewReader(br)
}

func putTextprotoReader(r *textproto.Reader) {
	r.R = nil
	textprotoReaderPool.Put(r)
}

// ReadRequest reads and parses an incoming request from b.
func ReadRequest(b *bufio.Reader) (*Request, error) {
	return readRequest(b, deleteHostHeader)
}

// Constants for readRequest's deleteHostHeader parameter.
const (
	deleteHostHeader = true
	keepHostHeader   = false
)

func readRequest(b *bufio.Reader, deleteHostHeader bool) (req *Request, err error) {
	tp := newTextprotoReader(b)
	req = new(Request)

	// RequestLine: MSRP 95529209 SEND
	var s string
	if s, err = tp.ReadLine(); err != nil {
		return nil, err
	}
	defer func() {
		putTextprotoReader(tp)
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
	}()
	var ok bool
	req.Proto, req.TranscitonID, req.Method, ok = parseRequestLine(s)
	if !ok {
		return nil, &badStringError{"malformed MSRP request", s}
	}
	/*if ok = ParseMSRPVersion(req.Proto); !ok {
		return nil, &badStringError{"malformed MSRP version", req.Proto}
	}*/
	// Subsequent lines: Key: value.
	mimeHeader, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}
	req.Header = Header(mimeHeader)

	return req, nil
}
func (r *Request) closeBody() {
	if r.Body != nil {
		r.Body.Close()
	}
}

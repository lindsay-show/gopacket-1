// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// MSRP Response reading and parsing.
package msrp

import (
	"bufio"
	"io"
	"net/textproto"

	"strconv"
	"strings"
)

// Response represents the response from an MSRP request.
type Response struct {
	TranscitonID string
	Status       string // e.g. "200 OK"
	StatusCode   int    // e.g. 200
	Proto        string // e.g. "MSRP
	Header       Header
	Body         io.ReadCloser

	ContentLength int64

	Close bool

	Uncompressed bool

	Trailer Header

	Request *Request
}

// ReadResponse reads and returns an MSRP response from r.
// The req parameter optionally specifies the Request that corresponds
// to this Response.
// Clients must call resp.Body.Close when finished reading resp.Body.
// After that call, clients can inspect resp.Trailer to find key/value
// pairs included in the response trailer.
func ReadResponse(r *bufio.Reader, req *Request) (*Response, error) {
	tp := textproto.NewReader(r)
	resp := &Response{
		Request: req,
	}
	// Parse the first line of the response.
	line, err := tp.ReadLine()
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	f := strings.SplitN(line, " ", 3)
	if len(f) < 2 {
		return nil, &badStringError{"malformed MSRP response", line}
	}
	reasonPhrase := ""
	if len(f) > 2 {
		reasonPhrase = f[2]
	}
	if len(f[1]) != 3 {
		return nil, &badStringError{"malformed MSRP status code", f[1]}
	}
	resp.StatusCode, err = strconv.Atoi(f[1])
	if err != nil || resp.StatusCode < 0 {
		return nil, &badStringError{"malformed MSRP status code", f[1]}
	}
	resp.Status = f[1] + " " + reasonPhrase
	resp.Proto = f[0]

	// Parse the response headers.
	mimeHeader, err := tp.ReadMIMEHeader()
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	resp.Header = Header(mimeHeader)

	return resp, nil
}

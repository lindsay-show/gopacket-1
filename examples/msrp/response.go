// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// MSRP Response reading and parsing.
package msrp

import (
	"bufio"
	"io"
	//"log"
	"net/textproto"
	"strconv"
	"strings"
)

// Response represents the response from an MSRP request.
type Response struct {
	Proto        string // e.g. "MSRP
	TranscitonID string
	Status       string // e.g. "200 OK" "200 Report recevied"
	StatusCode   int    // e.g. 200

	Header Header
	Body   io.ReadCloser

	ContentLength int64

	Close bool

	Request *Request
}

// ReadResponse reads and returns an MSRP response from r.
// The req parameter optionally specifies the Request that corresponds
// to this Response.
func ReadResponse(r *bufio.Reader, req *Request) (resp *Response, err error) {
	tp := textproto.NewReader(r)
	resp = new(Response)

	resp.Request = req

	// Parse the first line of the response.
	line, err := tp.ReadLine()
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	f := strings.SplitN(line, " ", 5)
	if f[0] != "MSRP" {
		return nil, &badStringError{"malformed MSRP version", f[0]}
	}
	if len(f) < 3 {
		return nil, &badStringError{"malformed MSRP response", line}
	}
	reasonPhrase := ""
	if len(f) > 4 {
		reasonPhrase = f[3] + " " + f[4]
	} else if len(f) > 3 {
		reasonPhrase = f[3]
	}
	resp.Status = f[2] + " " + reasonPhrase

	resp.StatusCode, err = strconv.Atoi(f[2])
	if err != nil {
		return nil, &badStringError{"malformed MSRP status code", f[2]}
	}
	resp.Proto = f[0]
	resp.TranscitonID = f[1]
	//log.Println("test:", resp.Proto, resp.TranscitonID, resp.Status)
	// Parse the response headers.
	mimeHeader, _ := tp.ReadMIMEHeader()
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	resp.Header = Header(mimeHeader)

	return resp, nil
}

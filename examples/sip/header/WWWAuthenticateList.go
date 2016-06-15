package header

import "github.com/google/gopacket/examples/sip/core"

/**
* WWWAuthenticate SIPHeader (of which there can be several?)
 */
type WWWAuthenticateList struct {
	SIPHeaderList
}

/**
 * constructor.
 */
func NewWWWAuthenticateList() *WWWAuthenticateList {
	this := &WWWAuthenticateList{}
	this.SIPHeaderList.super(core.SIPHeaderNames_WWW_AUTHENTICATE)
	return this
}

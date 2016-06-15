package header

import "github.com/google/gopacket/examples/sip/core"

/**
* List of Require headers.
* <pre>
* Require  =  "Require" ":" 1#option-tag
* </pre>
 */
type RequireList struct {
	SIPHeaderList
}

/** Default constructor
 */
func NewRequireList() *RequireList {
	this := &RequireList{}
	this.SIPHeaderList.super(core.SIPHeaderNames_REQUIRE)
	return this
}

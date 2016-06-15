package header

import (
	"github.com/google/gopacket/examples/sip/core"
)

/**
* A list of CallInfo headers (there can be multiple in a message).
 */
type CallInfoList struct {
	SIPHeaderList
}

/** Default constructor
 */
func NewCallInfoList() *CallInfoList {
	this := &CallInfoList{}
	this.SIPHeaderList.super(core.SIPHeaderNames_CALL_INFO)
	return this
}

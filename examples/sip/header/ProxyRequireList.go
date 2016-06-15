package header

import "github.com/google/gopacket/examples/sip/core"

/**
* Proxy Require SIPSIPObject (list of option tags)
 */
type ProxyRequireList struct {
	SIPHeaderList
}

/** Default Constructor
 */
func NewProxyRequireList() *ProxyRequireList {
	this := &ProxyRequireList{}
	this.SIPHeaderList.super(core.SIPHeaderNames_PROXY_REQUIRE)
	return this
}

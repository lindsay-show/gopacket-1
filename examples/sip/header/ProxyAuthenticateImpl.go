package header

import (
	"github.com/google/gopacket/examples/sip/core"
)

/**
* Proxy Authenticate SIP (HTTP ) header.
 */
type ProxyAuthenticate struct {
	Authentication
}

/** Default Constructor
 */
func NewProxyAuthenticate() *ProxyAuthenticate {
	this := &ProxyAuthenticate{}
	this.Authentication.super(core.SIPHeaderNames_PROXY_AUTHENTICATE)
	return this
}

package mdns

import "errors"

var (
	errJoiningMulticastGroup = errors.New("mDNS: failed to join multicast group")
	errConnectionClosed      = errors.New("mDNS: connection closed")
	errContextElapsed        = errors.New("mDNS: context has expired")
	errNilConfig             = errors.New("mDNS: config cannot not be nil")
	errRecordExists          = errors.New("mDNS: record already exists")
	errRecordNotFound        = errors.New("mDNS: record not found")
	errInvalidParameter      = errors.New("mDNS: invalid parameter")
)

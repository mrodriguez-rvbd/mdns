# mdns
mDNS is a library written in go that provides service discovery via Multicast DNS.
The library respond to only A and SRV records questions via multicast DNS, in the case of SRV records in will unconditionally responde with the SRV and A record matching the transaction.
This is not intended to be a full mDNS server.

Examples of usage can be found under the example directory.

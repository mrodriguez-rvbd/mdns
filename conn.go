package mdns

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"
	"golang.org/x/net/ipv4"
)

// Conn represents a mDNS Server
type Conn struct {
	ctx    context.Context
	config *Config

	socket  *ipv4.PacketConn
	dstAddr *net.UDPAddr

	queryInterval time.Duration
	queries       []query

	closed chan interface{}
}

type query struct {
	ttype           uint16
	nameWithSuffix  string
	queryResultChan chan QueryResult
}

// QueryResult struct used to return the result of a mdns query
type QueryResult struct {
	answer []dns.RR
	addr   net.Addr
}

type packet struct {
	buf []byte
	src net.Addr
	len int
}

const (
	inboundBufferSize      = 512
	defaultQueryInterval   = 2 * time.Second
	destinationAddress     = "224.0.0.251:5353"
	maxMessageRecords      = 3
	maxQueryMessageRecords = 1
	responseTTL            = 10
)

func (q *QueryResult) GetAnswers() *[]dns.RR {
	return &q.answer
}

func (q *QueryResult) GetAddr() *net.Addr {
	return &q.addr
}

// NewServer creates a new instance of the mDNS server, the server is used
// to read packets from the multicast group for both client and
// server side functionality.
func NewServer(context context.Context) (*Conn, error) {
	addr, err := net.ResolveUDPAddr("udp", destinationAddress)
	if err != nil {
		return nil, err
	}

	l, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, err
	}

	server, err := Server(ipv4.NewPacketConn(l), &Config{})
	if err != nil {
		return nil, err
	}
	server.ctx = context
	return server, nil
}

// RemoveARecord removes an A record from the server
func (c *Conn) RemoveARecord(name string) error {
	return c.config.removeARecord(name)
}

// RemoveSRVRecord remove a srv record from the server
func (c *Conn) RemoveSRVRecord(name string) error {
	return c.config.removeSRVRecord(name)
}

// AddARecord add an A record to the server
func (c *Conn) AddARecord(name string, dst *net.IP, dyn bool) error {
	return c.config.addARecord(name, dst, dyn)
}

// AddSRVRecord add an SRV record to the server
func (c *Conn) AddSRVRecord(name string, priority, weight, port uint16, target string) error {
	return c.config.addSRVRecord(name, priority, weight, port, target)
}

// Server establishes a mDNS connection over an existing conn
func Server(conn *ipv4.PacketConn, config *Config) (*Conn, error) {
	if config == nil {
		return nil, errNilConfig
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	joinErrCount := 0
	for i := range ifaces {
		if err = conn.JoinGroup(&ifaces[i], &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251)}); err != nil {
			joinErrCount++
		}
	}
	if joinErrCount >= len(ifaces) {
		return nil, errJoiningMulticastGroup
	}

	dstAddr, err := net.ResolveUDPAddr("udp", destinationAddress)
	if err != nil {
		return nil, err
	}

	c := &Conn{
		queryInterval: defaultQueryInterval,
		queries:       []query{},
		socket:        conn,
		dstAddr:       dstAddr,
		config:        config,
		closed:        make(chan interface{}),
	}
	if config.QueryInterval != 0 {
		c.queryInterval = config.QueryInterval
	}

	return c, nil
}

// Start the mdns Server
func (c *Conn) Start() { //nolint gocognit
	var wg sync.WaitGroup

	Log().Info("Starting mdns server")
	queue := make(chan packet) // Check this, channel of slice issues

	// Goroutine to read a packet and push it to the channel
	// Exits on socket close
	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		b := make([]byte, inboundBufferSize)
		// Read packet from Socket
		for {
			n, _, src, err := c.socket.ReadFrom(b)
			if err != nil { // Exit if socket error
				return
			}
			if n > 0 {
				queue <- packet{buf: b[:n], len: n, src: src}
			}
		}
	}(&wg)

	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()

		var msg dns.Msg
		for {
			select {
			case <-c.ctx.Done():
				close(c.closed)
				c.socket.Close()
				return
			case p := <-queue:
				// do IsMsg to check for len of header ( double check is a dns message )
				if err := dns.IsMsg(p.buf[:p.len]); err != nil {
					Log().Debug(err.Error())
					continue
				}
				// Parse dns packet
				if err := msg.Unpack(p.buf[:p.len]); err != nil {
					Log().Debug("Failed to parse mDNS packet", zap.Error(err))
					continue
				}

				// "In both multicast query and multicast response messages, the OPCODE MUST
				// be zero on transmission (only standard queries are currently supported
				// over multicast).  Multicast DNS messages received with an OPCODE other
				// than zero MUST be silently ignored."  Note: OpcodeQuery == 0
				if msg.Opcode != dns.OpcodeQuery {
					Log().Debug("Received query with non-zero Opcode", zap.Error(errInvalidPacket))
					continue
				}

				if msg.Rcode != 0 {
					// "In both multicast query and multicast response messages, the Response
					// Code MUST be zero on transmission.  Multicast DNS messages received with
					// non-zero Response Codes MUST be silently ignored."
					Log().Debug("Received query with non-zero Rcode", zap.Error(errInvalidPacket))
					continue
				}

				//    In query messages, if the TC bit is set, it means that additional
				//    Known-Answer records may be following shortly.  A responder SHOULD
				//    record this fact, and wait for those additional Known-Answer records,
				//    before deciding whether to respond.  If the TC bit is clear, it means
				//    that the querying host has no additional Known Answers.
				if msg.Truncated {
					Log().Debug("support for DNS requests with high truncated bit not implemented", zap.Error(errInvalidPacket))
					continue
				}

				c.processQuestions(msg, p.src)
				c.processAnswers(msg, p.src)
			}
		}
	}(&wg)
	// We block here
	wg.Wait()
	Log().Debug("Stop mdns server")
}

func (c *Conn) processQuestions(msg dns.Msg, src net.Addr) {
	// Process questions if any
	for _, q := range msg.Question {
		answers := make([]dns.RR, 0)

		if err := c.config.Lookup(&answers, &q, src); err == nil {
			msg := createAnswerMessage(&msg, &answers)
			c.sendAnswer(msg, src)
		}
	}
}

func (c *Conn) processAnswers(msg dns.Msg, src net.Addr) {
	// Process answers if any
	for _, a := range msg.Answer {
		switch rr := a.(type) {
		case *dns.A:
			// TODO: Query lock
			for i := len(c.queries) - 1; i >= 0; i-- {
				if c.queries[i].nameWithSuffix == rr.Header().Name && c.queries[i].ttype == rr.Header().Rrtype {
					// send respond back to client
					c.queries[i].queryResultChan <- QueryResult{msg.Answer, src}
					// Remove query, we already have a response
					c.queries = append(c.queries[:i], c.queries[i+1:]...)
				}
			}
		case *dns.SRV:
			for i := len(c.queries) - 1; i >= 0; i-- {
				if c.queries[i].nameWithSuffix == rr.Header().Name && c.queries[i].ttype == rr.Header().Rrtype {
					// send respond back to client
					c.queries[i].queryResultChan <- QueryResult{msg.Answer, src}
					// Remove query, we already have a response
					c.queries = append(c.queries[:i], c.queries[i+1:]...)
				}
			}
		}
	}

}

func (c *Conn) sendAnswer(msg *dns.Msg, src net.Addr) {
	rawAnswer, err := msg.Pack()
	if err != nil {
		Log().Debug("Failed to construct mDNS packet", zap.Error(err))
		return
	}

	if _, err := c.socket.WriteTo(rawAnswer, nil, c.dstAddr); err != nil {
		Log().Debug("Failed to send mDNS packet", zap.Error(err))
		return
	}
}

// QuerySync sends mDNS Queries for the following name until
// either the Context is canceled/expires or we get a result
// Query will add the ending dot to the query name
// answer, src, err := server.Query(context.TODO(), "catalog.gibson.local", dnsmessage.TypeA)
func (c *Conn) QuerySync(ctx context.Context, name string, ttype uint16) (*QueryResult, error) {
	// The multicast process close the connection, we cannot query
	select {
	case <-c.closed:
		return nil, errConnectionClosed
	default:
	}

	name = addDot(name)

	queryChan := make(chan QueryResult, 1)

	c.queries = append(c.queries,
		query{ttype: ttype,
			nameWithSuffix:  name,
			queryResultChan: queryChan})

	ticker := time.NewTicker(c.queryInterval)

	c.sendQuestion(name, ttype)
	// Block Here
	for {
		select {
		case <-ticker.C:
			c.sendQuestion(name, ttype)
		case <-c.closed:
			return nil, errConnectionClosed
		case res := <-queryChan:
			return &res, nil
		case <-ctx.Done():
			return nil, errContextElapsed
		}
	}
}

// QueryASync sends mDNS Queries for the following name until
// either the Context is canceled/expires or we get a result
// Query will add the ending dot to the query name
// TODO: Mutex lock the queries structure, for multiple queries at the same time
func (c *Conn) QueryASync(ctx context.Context, name string, ttype uint16) chan *QueryResult {
	results := make(chan *QueryResult)
	go func() {
		// The multicast process close the connection, we cannot query
		select {
		case <-c.closed:
			// Close channel so other end knows that there was an error
			Log().Debug("Connection close", zap.Error(errConnectionClosed))
			close(results)
			return
		default:
		}

		name = addDot(name)
		// Create a query channel with the mdns process
		queryChan := make(chan QueryResult, 1)

		c.queries = append(c.queries,
			query{ttype: ttype,
				nameWithSuffix:  name,
				queryResultChan: queryChan})

		ticker := time.NewTicker(c.queryInterval)

		c.sendQuestion(name, ttype)
		// Block Here
		for {
			select {
			// Time expired , send question to the network again
			case <-ticker.C:
				c.sendQuestion(name, ttype)
			// The connection close, we cannot query
			case <-c.closed:
				Log().Debug("Connection close", zap.Error(errConnectionClosed))
				close(results)
				return
			// mdns process returned a response, return to our client
			case res := <-queryChan:
				results <- &res
				return
			case <-ctx.Done():
				Log().Debug("Context cancel or timeout", zap.Error(errConnectionClosed))
				close(results)
				return
			}
		}
	}()

	return results

}

func (c *Conn) sendQuestion(name string, ttype uint16) {
	msg := new(dns.Msg)
	msg.SetQuestion(name, ttype)
	msg.RecursionDesired = true

	rawQuery, err := msg.Pack()
	if err != nil {
		Log().Debug("Failed to construct mDNS packet", zap.Error(err))
		return
	}

	if _, err := c.socket.WriteTo(rawQuery, nil, c.dstAddr); err != nil {
		Log().Debug("Failed to send mDNS packet", zap.Error(err))
		return
	}
}

func createAnswerMessage(q *dns.Msg, answer *[]dns.RR) *dns.Msg {
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:            q.Id,
			Response:      true,
			Opcode:        dns.OpcodeQuery,
			Authoritative: true,
		},
		Compress: true,

		Answer: *answer,
	}

}

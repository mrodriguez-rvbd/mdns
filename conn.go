package mdns

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"
	"golang.org/x/net/ipv4"
)

// Conn represents a mDNS Server
type Conn struct {
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
	queryResultChan chan queryResult
}

type queryResult struct {
	answer []dns.RR
	addr   net.Addr
}

const (
	inboundBufferSize      = 512
	defaultQueryInterval   = time.Second
	destinationAddress     = "224.0.0.251:5353"
	maxMessageRecords      = 3
	maxQueryMessageRecords = 1
	responseTTL            = 10
)

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

	go c.start()
	return c, nil
}

func (c *Conn) start() { //nolint gocognit
	defer func() {
		close(c.closed)
	}()

	b := make([]byte, inboundBufferSize)
	var msg dns.Msg
	Log().Info("Starting mdns server")
	for {
		// Read packet from Socket
		n, _, src, err := c.socket.ReadFrom(b)
		if err != nil {
			return
		}

		func() {
			// do IsMsg to check for len of header ( double check is a dns message )
			if err := dns.IsMsg(b[:n]); err != nil {
				Log().Warn("Failed to parse mDNS header", zap.Error(err))
				return
			}
			// Parse dns packet
			if err := msg.Unpack(b[:n]); err != nil {
				Log().Warn("Failed to parse mDNS packet", zap.Error(err))
				return
			}

			// "In both multicast query and multicast response messages, the OPCODE MUST
			// be zero on transmission (only standard queries are currently supported
			// over multicast).  Multicast DNS messages received with an OPCODE other
			// than zero MUST be silently ignored."  Note: OpcodeQuery == 0
			if msg.Opcode != dns.OpcodeQuery {
				Log().Debug("Received query with non-zero Opcode", zap.Error(errInvalidPacket))
				return
			}

			if msg.Rcode != 0 {
				// "In both multicast query and multicast response messages, the Response
				// Code MUST be zero on transmission.  Multicast DNS messages received with
				// non-zero Response Codes MUST be silently ignored."
				Log().Debug("Received query with non-zero Rcode", zap.Error(errInvalidPacket))
				return
			}

			//    In query messages, if the TC bit is set, it means that additional
			//    Known-Answer records may be following shortly.  A responder SHOULD
			//    record this fact, and wait for those additional Known-Answer records,
			//    before deciding whether to respond.  If the TC bit is clear, it means
			//    that the querying host has no additional Known Answers.
			if msg.Truncated {
				Log().Debug("support for DNS requests with high truncated bit not implemented", zap.Error(errInvalidPacket))
				return
			}

			// Process questions if any
			for _, q := range msg.Question {
				Log().Debug("Question", zap.String("name", q.Name), zap.Uint16("Type", q.Qtype))
				answers := make([]dns.RR, 0)

				if err := c.config.Lookup(&answers, &q, src); err == nil {
					for _, a := range answers {
						Log().Debug(a.String())
					}
					msg := createAnswerMessage(&msg, &answers)
					c.sendAnswer(msg, src)
				}
			}

			// Process answers if any
			Log().Debug("Answer ", zap.Int("Lenght", len(msg.Answer)))
			for _, a := range msg.Answer {

				switch rr := a.(type) {
				case *dns.A:
					Log().Debug("A", zap.String("Name", rr.Header().Name),
						zap.String("A", rr.A.String()))
					// TODO: Query lock
					for i := len(c.queries) - 1; i >= 0; i-- {
						Log().Debug("Match", zap.String("one", c.queries[i].nameWithSuffix),
							zap.String("two", rr.Header().Name))
						if c.queries[i].nameWithSuffix == rr.Header().Name && c.queries[i].ttype == rr.Header().Rrtype {
							// send respond back to client
							c.queries[i].queryResultChan <- queryResult{msg.Answer, src}
							// Remove query, we already have a response
							c.queries = append(c.queries[:i], c.queries[i+1:]...)
						}
					}
				case *dns.SRV:
					Log().Debug("SRV", zap.String("Name", rr.Header().Name),
						zap.Uint16("Priority", rr.Priority),
						zap.Uint16("Weight", rr.Weight),
						zap.Uint16("Port", rr.Port),
						zap.String("Target", rr.Target))
					for i := len(c.queries) - 1; i >= 0; i-- {
						if c.queries[i].nameWithSuffix == rr.Header().Name && c.queries[i].ttype == rr.Header().Rrtype {
							// send respond back to client
							c.queries[i].queryResultChan <- queryResult{msg.Answer, src}
							// Remove query, we already have a response
							c.queries = append(c.queries[:i], c.queries[i+1:]...)
						}
					}
				}

				//Log().Debug("Answer", zap.String("name", q.Name), zap.Uint16("Type", q.Qtype))
			}

		}()
	}
}

func (c *Conn) sendAnswer(msg *dns.Msg, src net.Addr) {
	rawAnswer, err := msg.Pack()
	if err != nil {
		Log().Warn("Failed to construct mDNS packet", zap.Error(err))
		return
	}

	if _, err := c.socket.WriteTo(rawAnswer, nil, c.dstAddr); err != nil {
		Log().Warn("Failed to send mDNS packet", zap.Error(err))
		return
	}
}

// Query sends mDNS Queries for the following name until
// either the Context is canceled/expires or we get a result
// Query will add the ending dot to the query name
// answer, src, err := server.Query(context.TODO(), "catalog.gibson.local", dnsmessage.TypeA)
func (c *Conn) Query(ctx context.Context, name string, ttype uint16) (*[]dns.RR, net.Addr, error) {
	select {
	case <-c.closed:
		return nil, nil, errConnectionClosed
	default:
	}

	name = addDot(name)

	queryChan := make(chan queryResult, 1)

	c.queries = append(c.queries,
		query{ttype: ttype,
			nameWithSuffix:  name,
			queryResultChan: queryChan})

	ticker := time.NewTicker(c.queryInterval)

	c.sendQuestion(name, ttype)
	for {
		select {
		case <-ticker.C:
			c.sendQuestion(name, ttype)
		case <-c.closed:
			return nil, nil, errConnectionClosed
		case res := <-queryChan:
			return &res.answer, res.addr, nil
		case <-ctx.Done():
			return nil, nil, errContextElapsed
		}
	}
}

func (c *Conn) sendQuestion(name string, ttype uint16) {
	msg := new(dns.Msg)
	msg.SetQuestion(name, ttype)
	msg.RecursionDesired = true

	rawQuery, err := msg.Pack()
	if err != nil {
		Log().Warn("Failed to construct mDNS packet", zap.Error(err))
		return
	}

	if _, err := c.socket.WriteTo(rawQuery, nil, c.dstAddr); err != nil {
		Log().Warn("Failed to send mDNS packet", zap.Error(err))
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

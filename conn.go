package mdns

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
)

// Conn represents a mDNS Server
type Conn struct {
	mu     sync.RWMutex
	config *Config

	socket  *ipv4.PacketConn
	dstAddr *net.UDPAddr

	queryInterval time.Duration
	queries       []query

	closed chan interface{}
}

type query struct {
	ttype           dnsmessage.Type
	nameWithSuffix  string
	queryResultChan chan queryResult
}

type queryResult struct {
	answer dnsmessage.ResourceHeader
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
		c.mu.Lock()
		defer c.mu.Unlock()
		close(c.closed)
	}()

	b := make([]byte, inboundBufferSize)
	p := dnsmessage.Parser{}
	Log().Info("Starting mdns server")
	for {
		// Read packet from Socket
		n, _, src, err := c.socket.ReadFrom(b)
		if err != nil {
			return
		}

		func() {
			c.mu.RLock()
			defer c.mu.RUnlock()
			// Parse dns packet
			if _, err := p.Start(b[:n]); err != nil {
				Log().Warn("Failed to parse mDNS packet", zap.Error(err))
				return
			}
			// process only 1 message
			for i := 0; i <= maxQueryMessageRecords; i++ {
				q, err := p.Question()
				if errors.Is(err, dnsmessage.ErrSectionDone) {
					break
				} else if err != nil {
					Log().Debug("Failed to parse mDNS packet", zap.Error(err))
					return
				}
				Log().Debug("Question", zap.String("name", q.Name.String()), zap.String("Type", q.Type.GoString()))
				// Create empty array for answers
				answers := make([]dnsmessage.Resource, 0)
				// Lookup Records to see if we can answer the question
				if err := c.config.Lookup(answers, q.Name.String(), q.Type, q.Class, src); err == nil {
					msg := createMessage(answers)
					c.sendAnswer(msg)
				}
			}

			for i := 0; i <= maxMessageRecords; i++ {
				a, err := p.AnswerHeader()
				if errors.Is(err, dnsmessage.ErrSectionDone) {
					return
				}
				if err != nil {
					// Dont log parsing errors
					Log().Debug("Failed to parse mDNS packet", zap.Error(err))
					return
				}

				if a.Type != dnsmessage.TypeA && a.Type != dnsmessage.TypeAAAA {
					continue
				}

				for i := len(c.queries) - 1; i >= 0; i-- {
					if c.queries[i].nameWithSuffix == a.Name.String() && c.queries[i].ttype == a.Type {
						// send respond back to client
						c.queries[i].queryResultChan <- queryResult{a, src}
						// Remove query, we already have a response
						c.queries = append(c.queries[:i], c.queries[i+1:]...)
					}
				}
			}
			test, err := p.AllAnswers()
			if err != nil {
				Log().Debug(err.Error())
			}
			Log().Debug("All answers", zap.Int("Length", len(test)))
			Log().Debug("\n")
			for _, v := range test {
				Log().Debug("Answers", zap.String("Value", v.GoString()))
			}
			Log().Debug("\n")
		}()
	}
}

func (c *Conn) sendAnswer(msg *dnsmessage.Message) {
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
func (c *Conn) Query(ctx context.Context, name string, ttype dnsmessage.Type) (dnsmessage.ResourceHeader, net.Addr, error) {
	select {
	case <-c.closed:
		return dnsmessage.ResourceHeader{}, nil, errConnectionClosed
	default:
	}

	nameWithSuffix := name + "."

	queryChan := make(chan queryResult, 1)

	c.mu.Lock()
	c.queries = append(c.queries,
		query{ttype: ttype,
			nameWithSuffix:  nameWithSuffix,
			queryResultChan: queryChan})

	ticker := time.NewTicker(c.queryInterval)
	c.mu.Unlock()

	c.sendQuestion(nameWithSuffix, ttype)
	for {
		select {
		case <-ticker.C:
			c.sendQuestion(nameWithSuffix, ttype)
		case <-c.closed:
			return dnsmessage.ResourceHeader{}, nil, errConnectionClosed
		case res := <-queryChan:
			return res.answer, res.addr, nil
		case <-ctx.Done():
			return dnsmessage.ResourceHeader{}, nil, errContextElapsed
		}
	}
}

func (c *Conn) sendQuestion(name string, ttype dnsmessage.Type) {
	var msg dnsmessage.Message

	packedName, err := dnsmessage.NewName(name)
	if err != nil {
		Log().Warn("Failed to construct mDNS packet", zap.Error(err))
		return
	}
	msg = dnsmessage.Message{
		Header: dnsmessage.Header{},
		Questions: []dnsmessage.Question{
			{
				Class: dnsmessage.ClassINET,
				Name:  packedName,
			},
		},
	}

	switch ttype {
	case dnsmessage.TypeA:
		msg.Questions[0].Type = dnsmessage.TypeA
	case dnsmessage.TypeSRV:
		msg.Questions[0].Type = dnsmessage.TypeSRV
	}

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

func createMessage(answer []dnsmessage.Resource) *dnsmessage.Message {
	return &dnsmessage.Message{
		Header: dnsmessage.Header{
			Response:      true,
			Authoritative: true,
		},
		Answers: answer,
	}
}

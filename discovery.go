package mdns

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Discovery service
type Discovery struct {
	ctx             context.Context
	parentWaitGroup *sync.WaitGroup
	conn            *Conn
}

type DiscoverySrvResult struct {
	Port uint16
	Addr *net.IP
}

type DiscoverySrvQuery struct {
	ctx      context.Context
	name     string
	ttype    uint16
	qChannel chan *DiscoverySrvQuery
	timeout  time.Duration
}

// NewDiscovery creates a new process
func NewDiscovery(opts ...func(*Discovery)) *Discovery {
	d := &Discovery{}

	for _, opt := range opts {
		opt(d)
	}

	return d
}

// WithContext configure a probe with the specified AF
func WithContext(ctx context.Context) func(*Discovery) {
	return func(t *Discovery) {
		t.ctx = ctx
	}
}

// WithWaitGroup configure a probe with the specified AF
func WithWaitGroup(wg *sync.WaitGroup) func(*Discovery) {
	return func(s *Discovery) {
		s.parentWaitGroup = wg
	}
}

// Start the discovery process
func (d *Discovery) Start() {
	conn, err := NewServer(d.ctx)
	if err != nil {
		Log().Debug(err.Error())
		return
	}
	d.conn = conn

	d.parentWaitGroup.Add(1)
	go func() {
		// Start connection handling of multicast DNS packets
		// Exits on context cancel
		d.conn.Start()
		d.parentWaitGroup.Done()
	}()
}

// Timeout function
// Set the timeout of the query
func Timeout(timeout time.Duration) func(*DiscoverySrvQuery) {
	return func(dq *DiscoverySrvQuery) {
		dq.timeout = timeout
	}
}

// Name function
// Set the name of the query
func Name(name string) func(*DiscoverySrvQuery) {
	return func(dq *DiscoverySrvQuery) {
		dq.name = name
	}
}

// Type function
// Set the type of the query
func Type(ttype uint16) func(*DiscoverySrvQuery) {
	return func(dq *DiscoverySrvQuery) {
		dq.ttype = ttype
	}
}

// Context function
// Set the context of the query
func Context(ctx context.Context) func(*DiscoverySrvQuery) {
	return func(dq *DiscoverySrvQuery) {
		dq.ctx = ctx
	}
}

// FindCatalog finds the catalog service, returns a channel to transmit the result or close channel if timeout
func (d *Discovery) FindCatalog(opts ...func(*DiscoverySrvQuery)) chan *DiscoverySrvResult {
	query := &DiscoverySrvQuery{
		ctx:   context.TODO(),
		name:  "_catalog._tcp.local",
		ttype: dns.TypeSRV,
	}
	// apply the list of options to Server
	for _, opt := range opts {
		opt(query)
	}
	discoverResults := make(chan *DiscoverySrvResult)

	go func() {
		// Create timeout
		tick := time.Tick(query.timeout)

		results := d.conn.QueryASync(query.ctx, query.name, query.ttype)
		select {
		case res, ok := <-results:
			if !ok {
				// If there is an error receiving results the context close, so we need to exit
				Log().Debug("Error receiving answer from mdns")
				close(discoverResults)
				return
			}
			answers := res.GetAnswers()
			dr := &DiscoverySrvResult{}
			for _, a := range *answers {
				if rr, ok := a.(*dns.A); ok {
					dr.Addr = &rr.A
				}
				if rr, ok := a.(*dns.SRV); ok {
					dr.Port = rr.Port
				}
			}
			if dr.Addr != nil && dr.Port != 0 {
				//fmt.Printf("Found catalog at %s:%s\n", ip, port)
				discoverResults <- dr
			}
		case <-query.ctx.Done():
			close(discoverResults)
			break
		case <-tick:
			Log().Debug("Timeout looking for catalog")
			close(discoverResults)
			break
		}
	}()

	return discoverResults
}

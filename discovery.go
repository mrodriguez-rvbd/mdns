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
	ctx             *context.Context
	parentWaitGroup *sync.WaitGroup
	conn            *Conn
}

type DiscoverySrvResult struct {
	Port uint16
	Addr *net.IP
}

type DiscoverySrvQuery struct {
	Ctx      context.Context
	Name     string
	Ttype    uint16
	QChannel chan *DiscoverySrvQuery
	Timeout  time.Duration
}

// New creates a new discovery service
func NewDiscovery(c *context.Context, wait *sync.WaitGroup) *Discovery {

	conn, err := NewServer(c)
	if err != nil {
		Log().Debug(err.Error())
		return nil
	}

	return &Discovery{
		ctx:             c,
		parentWaitGroup: wait,
		conn:            conn,
	}
}

// Start the discovery process
func (d *Discovery) Start() {

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
		dq.Timeout = timeout
	}
}

// Name function
// Set the name of the query
func Name(name string) func(*DiscoverySrvQuery) {
	return func(dq *DiscoverySrvQuery) {
		dq.Name = name
	}
}

// Type function
// Set the type of the query
func Type(ttype uint16) func(*DiscoverySrvQuery) {
	return func(dq *DiscoverySrvQuery) {
		dq.Ttype = ttype
	}
}

// Context function
// Set the context of the query
func Context(ctx context.Context) func(*DiscoverySrvQuery) {
	return func(dq *DiscoverySrvQuery) {
		dq.Ctx = ctx
	}
}

// FindCatalog finds the catalog service, returns a channel to transmit the result or close channel if timeout
func (d *Discovery) FindCatalog(opts ...func(*DiscoverySrvQuery)) chan *DiscoverySrvResult {
	query := &DiscoverySrvQuery{
		Ctx:   context.TODO(),
		Name:  "_catalog._tcp.local",
		Ttype: dns.TypeSRV,
	}
	// apply the list of options to Server
	for _, opt := range opts {
		opt(query)
	}
	discoverResults := make(chan *DiscoverySrvResult)

	go func() {
		// Create timeout
		tick := time.Tick(query.Timeout)

		results := d.conn.QueryASync(query.Ctx, query.Name, query.Ttype)
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
		case <-query.Ctx.Done():
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

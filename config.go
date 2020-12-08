package mdns

import (
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const (
	// DefaultAddress is the default used by mDNS
	DefaultAddress = "224.0.0.0:5353"
)

// Config is used to configure a mDNS client or server.
type Config struct {
	sync.RWMutex
	// QueryInterval controls how often we sends Queries until we
	// get a response
	QueryInterval time.Duration

	// LocalNames are the names that we will generate answers for
	// when we get questions
	ARecords   []DynamicARR
	SRVRecords []dns.SRV
}

// DynamicARR allow creating A Records that will change ip address
// based on the source of the packet
type DynamicARR struct {
	dns.A
	Dynamic bool
}

// RemoveARecord remove a record for the configuration based on name
func (c *Config) removeARecord(name string) error {
	c.Lock()
	defer c.Unlock()

	for i := len(c.ARecords) - 1; i >= 0; i-- {

		if c.ARecords[i].Header().Name == name {
			c.ARecords = append(c.ARecords[:i], c.ARecords[i+1])
			Log().Debug("Removed A record", zap.String("name", name))
			return nil
		}
	}
	return errRecordNotFound
}

// RemoveSRVRecord remove a srv record from configuration
func (c *Config) removeSRVRecord(name string) error {
	c.Lock()
	defer c.Unlock()

	for i := len(c.SRVRecords) - 1; i >= 0; i-- {
		if c.SRVRecords[i].Header().Name == name {
			c.SRVRecords = append(c.SRVRecords[:i], c.SRVRecords[i+1])
			Log().Debug("Added SRV record", zap.String("name", name))
			return nil
		}
	}
	return errRecordNotFound
}

// AddARecord adds a A record
// if dyn is true, then the record is dynamic and dst can be nil
// if dst is specified , then dyn should be set to false to create
// a static A Record
func (c *Config) addARecord(name string, dst *net.IP, dyn bool) error {
	if name == "" {
		return errInvalidParameter
	}

	name = addDot(name)

	rec, err := c.createSimpleARecord(name)
	if err != nil {
		return err
	}
	if !dyn && dst != nil {
		rec.Header().Name = name
		rec.A.A = *dst
		rec.Dynamic = false
	} else {
		if dyn == false {
			Log().Debug("AddARecord no dst specified, created dynamic record instead",
				zap.String("name", name))
		}
		// Create dynamic record and warn user
		rec.Dynamic = true
	}

	// add record if not exists
	if err := c.addARecordToConfig(rec); err != nil {
		return err
	}
	Log().Debug("Added A record", zap.String("name", rec.String()))
	return nil
}

// AddSRVRecord adds a SRV record to the configuration
func (c *Config) addSRVRecord(name string, priority, weight, port uint16, target string) error {
	if name == "" || target == "" {
		return errInvalidParameter
	}
	name = addDot(name)
	target = addDot(target)
	rec, err := c.createSRVRecord(name, priority, weight, port, target)
	if err != nil {
		return err
	}

	// add record if not exists
	if err := c.addSRVRecordToConfig(rec); err != nil {
		return err
	}
	Log().Debug("Added SVR record", zap.String("name", name), zap.String("target", target))
	return nil
}

func (c *Config) addARecordToConfig(rec *DynamicARR) error {
	c.Lock()
	defer c.Unlock()
	for i := len(c.ARecords) - 1; i >= 0; i-- {
		if c.ARecords[i].Header().Name == rec.Header().Name { // Record already there
			return errRecordExists
		}
	}
	c.ARecords = append(c.ARecords, *rec)
	return nil
}

func (c *Config) addSRVRecordToConfig(rec *dns.SRV) error {
	c.Lock()
	defer c.Unlock()
	for i := len(c.SRVRecords) - 1; i >= 0; i-- {
		if c.SRVRecords[i].Header().Name == rec.Header().Name { // Record already there
			return errRecordExists
		}
	}
	c.SRVRecords = append(c.SRVRecords, *rec)
	return nil
}

func (c *Config) createSimpleARecord(name string) (*DynamicARR, error) {
	rec := &DynamicARR{
		A: dns.A{
			Hdr: dns.RR_Header{
				Name:   name,
				Class:  dns.ClassINET,
				Ttl:    responseTTL,
				Rrtype: dns.TypeA,
			},
		},
	}

	return rec, nil
}

func (c *Config) createSRVRecord(name string, priority, weight, port uint16, target string) (*dns.SRV, error) {
	rec := &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET,
		},
		Port:     port,
		Priority: priority,
		Weight:   weight,
		Target:   target,
	}
	return rec, nil
}

// Lookup look up A and SRV records, allow for recursion in SVR record
func (c *Config) Lookup(answers *[]dns.RR, q *dns.Question, src net.Addr) error {
	c.RLock()
	defer c.RUnlock()

	switch q.Qtype {
	case dns.TypeA:
		if rec := c.lookupA(q.Name); rec != nil {
			// create default message and fill out values
			if rec.Dynamic {
				if err := rec.AddDynamicIP(src); err != nil {
					Log().Debug("Error", zap.Error(err))
					return err
				}
			}
			*answers = append(*answers, rec)
			return nil
		}

	case dns.TypeSRV:
		if rec := c.lookupSRV(q.Name); rec != nil {
			// Find A Records if available and add to answers ( A Records )

			newQ := dns.Question{
				Name:   rec.Target, // Recursive based on the target of the SVR Record
				Qtype:  dns.TypeA,
				Qclass: rec.Header().Class,
			}
			*answers = append(*answers, rec)

			if err := c.Lookup(answers, &newQ, src); err != nil {
				return err
			}

			return nil

		}
	}

	return nil // Is not an error if not found
}

// LookupA Records based on name
func (c *Config) lookupA(qName string) *DynamicARR {
	for _, aRec := range c.ARecords {
		if aRec.Header().Name == qName {
			aRec1 := aRec // shallow copy
			return &aRec1
		}
	}
	return nil
}

// LookupSRV Records based on name
func (c *Config) lookupSRV(qName string) *dns.SRV {
	c.RLock()
	defer c.RUnlock()
	for _, srvRec := range c.SRVRecords {
		if srvRec.Header().Name == qName {
			return &srvRec
		}
	}
	return nil
}

// AddDynamicIP modify the DynamicARR to include the dynamic ip address,
// return error on error or nil
func (d *DynamicARR) AddDynamicIP(src net.Addr) error {
	dst, err := interfaceForRemote(src.String())
	if err != nil {
		Log().Debug("Failed to get local interface to talk peer",
			zap.String("Source", src.String()), zap.Error(err))
		return errInvalidParameter
	}
	d.A.A = dst
	return nil
}

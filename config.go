package mdns

import (
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/net/dns/dnsmessage"
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
	ARecords   []DynamicARecord
	SRVRecords []dnsmessage.Resource
}

// DynamicARecord allow creating ARecords that will change ip address
// based on the source of the packet
type DynamicARecord struct {
	dnsmessage.Resource
	Dynamic bool
}

// RemoveARecord remove a record for the configuration based on name
func (c *Config) RemoveARecord(name string) error {
	c.Lock()
	defer c.Unlock()

	for i := len(c.ARecords) - 1; i >= 0; i-- {
		if c.ARecords[i].Header.Name.String() == name {
			c.ARecords = append(c.ARecords[:i], c.ARecords[i+1])
			Log().Debug("Removed A record", zap.String("name", name))
			return nil
		}
	}
	return errRecordNotFound
}

// RemoveSRVRecord remove a srv record from configuration
func (c *Config) RemoveSRVRecord(name string) error {
	c.Lock()
	defer c.Unlock()

	for i := len(c.SRVRecords) - 1; i >= 0; i-- {
		if c.SRVRecords[i].Header.Name.String() == name {
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
func (c *Config) AddARecord(name string, dst *net.IP, dyn bool) error {
	if name == "" {
		return errInvalidParameter
	}
	rec, err := c.createSimpleARecord(name)
	if err != nil {
		return err
	}
	if !dyn && dst != nil {
		rec.Resource.Body = &dnsmessage.AResource{
			A: ipToBytes(*dst),
		}
		rec.Dynamic = false
	} else {
		if dyn == false {
			Log().Warn("AddARecord no dst specified, created dynamic record instead",
				zap.String("name", name))
		}
		// Create dynamic record and warn user
		rec.Dynamic = true
	}

	// add record if not exists
	if err := c.addARecordToConfig(rec); err != nil {
		return err
	}
	Log().Debug("Added A record", zap.String("name", name))
	return nil
}

// AddSRVRecord adds a SRV record to the configuration
func (c *Config) AddSRVRecord(name string, priority, weight, port uint16, target string) error {
	if name == "" || target == "" {
		return errInvalidParameter
	}
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

func (c *Config) addARecordToConfig(rec *DynamicARecord) error {
	c.Lock()
	defer c.Unlock()
	for i := len(c.ARecords) - 1; i >= 0; i-- {
		if c.ARecords[i].Header.Name.String() == rec.Header.Name.String() { // Record already there
			return errRecordExists
		}
	}
	c.ARecords = append(c.ARecords, *rec)
	return nil
}

func (c *Config) addSRVRecordToConfig(rec *dnsmessage.Resource) error {
	c.Lock()
	defer c.Unlock()
	for i := len(c.SRVRecords) - 1; i >= 0; i-- {
		if c.SRVRecords[i].Header.Name.String() == rec.Header.Name.String() { // Record already there
			return errRecordExists
		}
	}
	c.SRVRecords = append(c.SRVRecords, *rec)
	return nil
}

func (c *Config) createSimpleARecord(name string) (*DynamicARecord, error) {
	packedName, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}
	rec := &DynamicARecord{
		Resource: dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
				Name:  packedName,
				TTL:   responseTTL,
			},
			Body: nil,
		},
	}
	return rec, nil
}

func (c *Config) createSRVRecord(name string, priority, weight, port uint16, target string) (*dnsmessage.Resource, error) {
	packedName, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}

	packedTarget, err := dnsmessage.NewName(target)
	if err != nil {
		return nil, err
	}

	rec := &dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
			Name:  packedName,
			TTL:   responseTTL,
		},
		Body: &dnsmessage.SRVResource{
			Port:     port,
			Priority: priority,
			Target:   packedTarget,
			Weight:   weight,
		},
	}
	return rec, nil
}

// Lookup look up A and SRV records, allow for recursion in SVR record
func (c *Config) Lookup(answers []dnsmessage.Resource, name string, ttype dnsmessage.Type, class dnsmessage.Class, src net.Addr) error {
	c.RLock()
	defer c.RUnlock()

	switch ttype {
	case dnsmessage.TypeA:

		if rec := c.lookupA(name); rec != nil {
			// create default message and fill out values
			if rec.Dynamic {
				if err := rec.AddDynamicIP(src); err != nil {
					Log().Warn("Error", zap.Error(err))
					return err
				}
			}

			answers = append(answers, rec.Resource)
			return nil
		}

	case dnsmessage.TypeSRV:
		if rec := c.lookupSRV(name); rec != nil {
			// Recursive add other answers ( A Records )
			if err := c.Lookup(answers, rec.Header.Name.String(), rec.Header.Type, rec.Header.Class, src); err != nil {
				answers = append(answers, *rec)
			}
			return nil
		}
	}

	return errRecordNotFound
}

// LookupA Records based on name
func (c *Config) lookupA(qName string) *DynamicARecord {
	for _, aRec := range c.ARecords {
		if aRec.Header.Name.String() == qName {
			aRec1 := aRec // shallow copy
			return &aRec1
		}
	}
	return nil
}

// LookupSRV Records based on name
func (c *Config) lookupSRV(qName string) *dnsmessage.Resource {
	c.RLock()
	defer c.RUnlock()
	for _, srvRec := range c.SRVRecords {
		if srvRec.Header.Name.String() == qName {
			return &srvRec
		}
	}
	return nil
}

// AddDynamicIP modify the dynamicARecord to include the dynamic ip address,
// return error on error or nil
func (d *DynamicARecord) AddDynamicIP(src net.Addr) error {
	dst, err := interfaceForRemote(src.String())
	if err != nil {
		Log().Warn("Failed to get local interface to talk peer",
			zap.String("Source", src.String()), zap.Error(err))
		return errInvalidParameter
	}
	d.Resource.Body = &dnsmessage.AResource{
		A: ipToBytes(dst),
	}
	return nil
}

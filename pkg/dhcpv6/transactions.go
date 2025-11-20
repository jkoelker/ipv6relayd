package dhcpv6

import (
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"

	"github.com/jkoelker/ipv6relayd/pkg/cache"
)

type transactionCache struct {
	store *cache.TTL[uint32, transactionRecord]
}

func newTransactionCache(ttl time.Duration) *transactionCache {
	store := cache.NewTTL[uint32, transactionRecord](ttl)
	if store == nil {
		return nil
	}

	return &transactionCache{
		store: store,
	}
}

func (c *transactionCache) remember(id uint32, record transactionRecord) {
	if c == nil || c.store == nil || id == 0 || record.iface == "" {
		return
	}

	c.store.Add(id, record)
}

func (c *transactionCache) record(ident uint32) (transactionRecord, bool) {
	var zero transactionRecord
	if c == nil || c.store == nil {
		return zero, false
	}

	record, ok, _ := c.store.Get(ident)
	if !ok {
		return zero, false
	}

	return record, true
}

func (c *transactionCache) exists(ident uint32) bool {
	if c == nil || c.store == nil {
		return false
	}

	_, ok, _ := c.store.Get(ident)

	return ok
}

func (c *transactionCache) remove(id uint32) {
	if c == nil || c.store == nil {
		return
	}

	c.store.Remove(id)
}

type transactionRecord struct {
	iface   string
	expires time.Time
}

// StoreTransaction remembers the interface tied to a transaction ID.
func (s *Service) StoreTransaction(id uint32, iface string) {
	if iface == "" || s.transactions == nil {
		return
	}

	s.transactions.remember(id, transactionRecord{
		iface:   iface,
		expires: time.Now().Add(s.transactionTTL),
	})
}

// TransactionRecord returns the stored interface and expiry for the given transaction ID.
func (s *Service) TransactionRecord(id uint32) (string, time.Time, bool) {
	if s.transactions == nil {
		return "", time.Time{}, false
	}

	record, ok := s.transactions.record(id)
	if !ok {
		return "", time.Time{}, false
	}

	return record.iface, record.expires, true
}

// TransactionExists reports whether a transaction is currently tracked.
func (s *Service) TransactionExists(id uint32) bool {
	if s.transactions == nil {
		return false
	}

	return s.transactions.exists(id)
}

func transactionIDToUint(xid dhcpv6.TransactionID) uint32 {
	return uint32(xid[0])<<16 | uint32(xid[1])<<8 | uint32(xid[2])
}

func (s *Service) lookupInterfaceByTransaction(txnID uint32) (string, bool) {
	if s.transactions == nil {
		return "", false
	}

	record, ok := s.transactions.record(txnID)
	if !ok {
		return "", false
	}

	return record.iface, true
}

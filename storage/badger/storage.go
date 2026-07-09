// Package badger implements nanoca.Storage over BadgerDB. Records are
// stored as JSON envelopes carrying an explicit revision counter, so
// conditional writes are a read-compare-write inside one transaction;
// the reservation and status-transition logic lives in nanoca.
package badger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/brandonweeks/nanoca"
	"github.com/dgraph-io/badger/v4"
)

// Storage provides a Badger-based implementation of the nanoca.Storage interface
type Storage struct {
	db *badger.DB
}

// Options for configuring the Badger storage
type Options struct {
	// Path to the database directory
	Path string
	// InMemory runs the database entirely in memory
	InMemory bool
	// Additional Badger options can be added here
}

// New creates a new Badger storage instance
func New(opts Options) (*Storage, error) {
	if opts.Path == "" && !opts.InMemory {
		return nil, errors.New("path is required for persistent storage")
	}

	db, err := badger.Open(badger.DefaultOptions(opts.Path).WithInMemory(opts.InMemory))
	if err != nil {
		return nil, fmt.Errorf("failed to open badger database: %w", err)
	}

	return &Storage{db: db}, nil
}

const (
	noncePrefix       = "nonce:"
	accountPrefix     = "account:"
	accountKeyPrefix  = "account_key:"
	orderPrefix       = "order:"
	authzPrefix       = "authz:"
	challengePrefix   = "challenge:"
	certificatePrefix = "cert:"
)

func nonceKey(value string) []byte {
	return []byte(noncePrefix + value)
}

func accountKey(id string) []byte {
	return []byte(accountPrefix + id)
}

func accountKeyLookupKey(keyHash string) []byte {
	return []byte(accountKeyPrefix + keyHash)
}

func orderKey(id string) []byte {
	return []byte(orderPrefix + id)
}

func authzKey(id string) []byte {
	return []byte(authzPrefix + id)
}

func challengeKey(id string) []byte {
	return []byte(challengePrefix + id)
}

func certificateKey(id string) []byte {
	return []byte(certificatePrefix + id)
}

// envelope wraps every revisioned record; Rev is an explicit counter
// rather than badger's internal version so it survives backup/restore.
type envelope struct {
	Rev    uint64          `json:"rev"`
	Record json.RawMessage `json:"record"`
}

// update retries fn when badger's optimistic concurrency detects a
// conflicting commit. This is engine-internal convergence, not
// classification: fn re-reads the stored state, so a competing write
// surfaces as nanoca.ErrConflict from the revision comparison or
// nanoca.ErrExists from the duplicate check, never as a spurious backend
// error.
func (s *Storage) update(fn func(txn *badger.Txn) error) error {
	for {
		err := s.db.Update(fn)
		if !errors.Is(err, badger.ErrConflict) {
			return err
		}
	}
}

// getValue loads a key's value, mapping a missing key to nanoca.ErrNotFound.
func getValue(txn *badger.Txn, key []byte, resource string) ([]byte, error) {
	item, err := txn.Get(key)
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil, nanoca.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get %s: %w", resource, err)
	}
	return item.ValueCopy(nil)
}

func getJSON(txn *badger.Txn, key []byte, resource string, dst any) error {
	data, err := getValue(txn, key, resource)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return fmt.Errorf("failed to unmarshal %s: %w", resource, err)
	}
	return nil
}

func setJSON(txn *badger.Txn, key []byte, resource string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("failed to marshal %s: %w", resource, err)
	}
	return txn.Set(key, data)
}

// getEnvelope loads a revisioned record into dst and returns its revision.
func getEnvelope(txn *badger.Txn, key []byte, resource string, dst any) (uint64, error) {
	var env envelope
	if err := getJSON(txn, key, resource, &env); err != nil {
		return 0, err
	}
	if err := json.Unmarshal(env.Record, dst); err != nil {
		return 0, fmt.Errorf("failed to unmarshal %s: %w", resource, err)
	}
	return env.Rev, nil
}

// setEnvelope writes a revisioned record.
func setEnvelope(txn *badger.Txn, key []byte, resource string, rev uint64, v any) error {
	record, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("failed to marshal %s: %w", resource, err)
	}
	return setJSON(txn, key, resource, envelope{Rev: rev, Record: record})
}

// createEnvelope writes a new revisioned record, refusing to overwrite.
func createEnvelope(txn *badger.Txn, key []byte, resource string, v any) error {
	switch _, err := txn.Get(key); {
	case err == nil:
		return fmt.Errorf("%s already stored: %w", resource, nanoca.ErrExists)
	case !errors.Is(err, badger.ErrKeyNotFound):
		return fmt.Errorf("failed to get %s: %w", resource, err)
	}
	return setEnvelope(txn, key, resource, 1, v)
}

func revision(rev uint64) nanoca.Revision {
	return nanoca.Revision(strconv.FormatUint(rev, 10))
}

// getRecord loads a revisioned record in its own read transaction.
func getRecord[T any](s *Storage, key []byte, resource string) (*T, nanoca.Revision, error) {
	var record T
	var rev uint64
	err := s.db.View(func(txn *badger.Txn) error {
		var err error
		rev, err = getEnvelope(txn, key, resource, &record)
		return err
	})
	if err != nil {
		return nil, "", err
	}
	return &record, revision(rev), nil
}

// putRecord replaces a revisioned record, conditioned on the caller's
// revision still matching the stored one.
func putRecord(s *Storage, key []byte, resource string, record any, rev nanoca.Revision) error {
	expected, err := strconv.ParseUint(string(rev), 10, 64)
	if err != nil {
		return fmt.Errorf("malformed %s revision %q: %w", resource, rev, nanoca.ErrConflict)
	}
	return s.update(func(txn *badger.Txn) error {
		var stored envelope
		if err := getJSON(txn, key, resource, &stored); err != nil {
			return err
		}
		if stored.Rev != expected {
			return fmt.Errorf("%s revision moved: %w", resource, nanoca.ErrConflict)
		}
		return setEnvelope(txn, key, resource, expected+1, record)
	})
}

func (s *Storage) CreateNonce(_ context.Context, nonce *nanoca.Nonce, ttl time.Duration) error {
	return s.update(func(txn *badger.Txn) error {
		// Badger hides expired items from reads, so an evicted key cannot
		// trip the duplicate check.
		switch _, err := txn.Get(nonceKey(nonce.Value)); {
		case err == nil:
			return fmt.Errorf("nonce already stored: %w", nanoca.ErrExists)
		case !errors.Is(err, badger.ErrKeyNotFound):
			return fmt.Errorf("failed to get nonce: %w", err)
		}
		data, err := json.Marshal(nonce)
		if err != nil {
			return fmt.Errorf("failed to marshal nonce: %w", err)
		}
		return txn.SetEntry(badger.NewEntry(nonceKey(nonce.Value), data).WithTTL(ttl))
	})
}

func (s *Storage) TakeNonce(_ context.Context, value string) (*nanoca.Nonce, error) {
	var nonce nanoca.Nonce
	err := s.update(func(txn *badger.Txn) error {
		if err := getJSON(txn, nonceKey(value), "nonce", &nonce); err != nil {
			return err
		}
		return txn.Delete(nonceKey(value))
	})
	if err != nil {
		return nil, err
	}
	return &nonce, nil
}

// putAccount writes the account envelope and maintains the thumbprint
// index in the same transaction.
func putAccount(txn *badger.Txn, account *nanoca.Account, rev uint64) error {
	if err := setEnvelope(txn, accountKey(account.ID), "account", rev, account); err != nil {
		return err
	}
	if account.KeyThumbprint != "" {
		return txn.Set(accountKeyLookupKey(account.KeyThumbprint), []byte(account.ID))
	}
	return nil
}

func (s *Storage) CreateAccount(_ context.Context, account *nanoca.Account) error {
	// A concurrent registration of the same key surfaces as a badger
	// conflict; the retry re-reads the thumbprint index and returns
	// ErrExists.
	return s.update(func(txn *badger.Txn) error {
		switch _, err := txn.Get(accountKey(account.ID)); {
		case err == nil:
			return fmt.Errorf("account already stored: %w", nanoca.ErrExists)
		case !errors.Is(err, badger.ErrKeyNotFound):
			return fmt.Errorf("failed to get account: %w", err)
		}
		if account.KeyThumbprint != "" {
			switch _, err := txn.Get(accountKeyLookupKey(account.KeyThumbprint)); {
			case err == nil:
				return fmt.Errorf("account key already registered: %w", nanoca.ErrExists)
			case !errors.Is(err, badger.ErrKeyNotFound):
				return fmt.Errorf("failed to get account key index: %w", err)
			}
		}
		return putAccount(txn, account, 1)
	})
}

func (s *Storage) GetAccount(_ context.Context, id string) (*nanoca.Account, nanoca.Revision, error) {
	return getRecord[nanoca.Account](s, accountKey(id), "account")
}

func (s *Storage) GetAccountByKey(_ context.Context, keyThumbprint string) (*nanoca.Account, nanoca.Revision, error) {
	var account nanoca.Account
	var rev uint64
	err := s.db.View(func(txn *badger.Txn) error {
		id, err := getValue(txn, accountKeyLookupKey(keyThumbprint), "account key index")
		if err != nil {
			return err
		}
		rev, err = getEnvelope(txn, accountKey(string(id)), "account", &account)
		return err
	})
	if err != nil {
		return nil, "", err
	}
	return &account, revision(rev), nil
}

func (s *Storage) PutAccount(_ context.Context, account *nanoca.Account, rev nanoca.Revision) error {
	expected, err := strconv.ParseUint(string(rev), 10, 64)
	if err != nil {
		return fmt.Errorf("malformed account revision %q: %w", rev, nanoca.ErrConflict)
	}
	return s.update(func(txn *badger.Txn) error {
		var stored envelope
		if err := getJSON(txn, accountKey(account.ID), "account", &stored); err != nil {
			return err
		}
		if stored.Rev != expected {
			return fmt.Errorf("account revision moved: %w", nanoca.ErrConflict)
		}
		return putAccount(txn, account, expected+1)
	})
}

func (s *Storage) CreateOrder(_ context.Context, order *nanoca.Order, authzs []*nanoca.Authorization, challenges []*nanoca.Challenge) error {
	return s.update(func(txn *badger.Txn) error {
		for _, challenge := range challenges {
			if err := createEnvelope(txn, challengeKey(challenge.ID), "challenge", challenge); err != nil {
				return err
			}
		}
		for _, authz := range authzs {
			if err := createEnvelope(txn, authzKey(authz.ID), "authorization", authz); err != nil {
				return err
			}
		}
		return createEnvelope(txn, orderKey(order.ID), "order", order)
	})
}

func (s *Storage) GetOrder(_ context.Context, id string) (*nanoca.Order, nanoca.Revision, error) {
	return getRecord[nanoca.Order](s, orderKey(id), "order")
}

func (s *Storage) PutOrder(_ context.Context, order *nanoca.Order, rev nanoca.Revision) error {
	return putRecord(s, orderKey(order.ID), "order", order, rev)
}

func (s *Storage) GetOrdersByAccount(_ context.Context, accountID string) ([]*nanoca.Order, error) {
	var orders []*nanoca.Order

	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = true
		it := txn.NewIterator(opts)
		defer it.Close()

		prefix := []byte(orderPrefix)
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var env envelope
				if err := json.Unmarshal(val, &env); err != nil {
					return err
				}
				var order nanoca.Order
				if err := json.Unmarshal(env.Record, &order); err != nil {
					return err
				}
				if order.AccountID == accountID {
					orders = append(orders, &order)
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get orders by account: %w", err)
	}

	return orders, nil
}

func (s *Storage) GetAuthorization(_ context.Context, id string) (*nanoca.Authorization, nanoca.Revision, error) {
	return getRecord[nanoca.Authorization](s, authzKey(id), "authorization")
}

func (s *Storage) PutAuthorization(_ context.Context, authz *nanoca.Authorization, rev nanoca.Revision) error {
	return putRecord(s, authzKey(authz.ID), "authorization", authz, rev)
}

func (s *Storage) GetChallenge(_ context.Context, id string) (*nanoca.Challenge, nanoca.Revision, error) {
	return getRecord[nanoca.Challenge](s, challengeKey(id), "challenge")
}

func (s *Storage) PutChallenge(_ context.Context, challenge *nanoca.Challenge, rev nanoca.Revision) error {
	return putRecord(s, challengeKey(challenge.ID), "challenge", challenge, rev)
}

func (s *Storage) CreateCertificate(_ context.Context, cert *nanoca.Certificate) error {
	return s.update(func(txn *badger.Txn) error {
		switch _, err := txn.Get(certificateKey(cert.ID)); {
		case err == nil:
			return fmt.Errorf("certificate already stored: %w", nanoca.ErrExists)
		case !errors.Is(err, badger.ErrKeyNotFound):
			return fmt.Errorf("failed to get certificate: %w", err)
		}
		return setJSON(txn, certificateKey(cert.ID), "certificate", cert)
	})
}

func (s *Storage) GetCertificate(_ context.Context, id string) (*nanoca.Certificate, error) {
	var cert nanoca.Certificate

	err := s.db.View(func(txn *badger.Txn) error {
		return getJSON(txn, certificateKey(id), "certificate", &cert)
	})
	if err != nil {
		return nil, err
	}

	return &cert, nil
}

// Close releases any resources held by the storage
func (s *Storage) Close() error {
	return s.db.Close()
}

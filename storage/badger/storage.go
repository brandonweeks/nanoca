package badger

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
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

func (s *Storage) CreateNonce(_ context.Context, nonce *nanoca.Nonce) error {
	data, err := json.Marshal(nonce)
	if err != nil {
		return fmt.Errorf("failed to marshal nonce: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(nonceKey(nonce.Value), data)
	})
}

// update retries fn when badger's optimistic concurrency detects a
// conflicting commit; our write transactions are small read-then-write ops
// for which a retry is always safe.
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

// reservedRecord points at the status and reservation fields the
// reservation state machine manipulates, so orders and challenges share
// one implementation of its transitions.
type reservedRecord struct {
	status      *string
	reservation **nanoca.Reservation
	resource    string
	processing  string
}

func orderRecord(o *nanoca.Order) reservedRecord {
	return reservedRecord{&o.Status, &o.Reservation, "order", nanoca.OrderStatusProcessing}
}

func challengeRecord(c *nanoca.Challenge) reservedRecord {
	return reservedRecord{&c.Status, &c.Reservation, "challenge", nanoca.ChallengeStatusProcessing}
}

// reserve transitions the record from `from` to processing — or reclaims a
// processing record whose reservation has lapsed — recording token and the
// reservation time.
func (r reservedRecord) reserve(from, token string, lease time.Duration) error {
	switch {
	case *r.status == from:
	case *r.status == r.processing && !(*r.reservation).Live(lease):
	case *r.status == r.processing:
		return fmt.Errorf("%s is already reserved: %w", r.resource, nanoca.ErrReserved)
	default:
		return fmt.Errorf("%s status is %s, not %s: %w", r.resource, *r.status, from, nanoca.ErrStatusMismatch)
	}

	*r.status = r.processing
	*r.reservation = &nanoca.Reservation{Token: token, ReservedAt: time.Now()}
	return nil
}

// consume admits a write only from the reservation's holder and clears the
// reservation; the caller sets the resulting status.
func (r reservedRecord) consume(token string) error {
	if *r.status != r.processing {
		return fmt.Errorf("%s status is %s, not %s: %w", r.resource, *r.status, r.processing, nanoca.ErrStatusMismatch)
	}
	if *r.reservation == nil || (*r.reservation).Token != token {
		return fmt.Errorf("%s reservation is held by another token: %w", r.resource, nanoca.ErrReserved)
	}
	*r.reservation = nil
	return nil
}

// ConsumeNonce atomically validates and consumes a nonce, preventing race conditions
func (s *Storage) ConsumeNonce(_ context.Context, value string, expiry time.Duration) (*nanoca.Nonce, error) {
	var nonce nanoca.Nonce

	// The nonce is deleted even when expired; reporting expiry from inside
	// the transaction would roll back the delete and keep the nonce forever.
	err := s.update(func(txn *badger.Txn) error {
		if err := getJSON(txn, nonceKey(value), "nonce", &nonce); err != nil {
			return err
		}
		return txn.Delete(nonceKey(value))
	})
	if err != nil {
		return nil, err
	}

	if time.Since(nonce.CreatedAt) > expiry {
		return nil, nanoca.ErrNonceExpired
	}

	return &nonce, nil
}

func putAccount(txn *badger.Txn, account *nanoca.Account) error {
	data, err := json.Marshal(account)
	if err != nil {
		return fmt.Errorf("failed to marshal account: %w", err)
	}

	if err := txn.Set(accountKey(account.ID), data); err != nil {
		return err
	}

	if account.KeyThumbprint != "" {
		return txn.Set(accountKeyLookupKey(account.KeyThumbprint), []byte(account.ID))
	}

	return nil
}

func (s *Storage) CreateAccount(_ context.Context, account *nanoca.Account) error {
	// A concurrent registration of the same key surfaces as a conflict; the
	// retry re-reads the thumbprint index and returns ErrAccountExists.
	return s.update(func(txn *badger.Txn) error {
		if account.KeyThumbprint != "" {
			switch _, err := txn.Get(accountKeyLookupKey(account.KeyThumbprint)); {
			case err == nil:
				return nanoca.ErrAccountExists
			case !errors.Is(err, badger.ErrKeyNotFound):
				return fmt.Errorf("failed to get account key index: %w", err)
			}
		}

		return putAccount(txn, account)
	})
}

func (s *Storage) GetAccount(_ context.Context, id string) (*nanoca.Account, error) {
	var account nanoca.Account

	err := s.db.View(func(txn *badger.Txn) error {
		return getJSON(txn, accountKey(id), "account", &account)
	})
	if err != nil {
		return nil, err
	}

	return &account, nil
}

func (s *Storage) GetAccountByKey(ctx context.Context, keyThumbprint string) (*nanoca.Account, error) {
	var accountID string

	err := s.db.View(func(txn *badger.Txn) error {
		val, err := getValue(txn, accountKeyLookupKey(keyThumbprint), "account key index")
		if err != nil {
			return err
		}
		accountID = string(val)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return s.GetAccount(ctx, accountID)
}

// requireKey ensures a record exists before it is overwritten, without
// reading its value.
func requireKey(txn *badger.Txn, key []byte, resource string) error {
	if _, err := txn.Get(key); err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nanoca.ErrNotFound
		}
		return fmt.Errorf("failed to get %s: %w", resource, err)
	}
	return nil
}

func (s *Storage) UpdateAccount(_ context.Context, account *nanoca.Account) error {
	return s.update(func(txn *badger.Txn) error {
		if err := requireKey(txn, accountKey(account.ID), "account"); err != nil {
			return err
		}
		return putAccount(txn, account)
	})
}

func (s *Storage) CreateOrder(_ context.Context, order *nanoca.Order) error {
	data, err := json.Marshal(order)
	if err != nil {
		return fmt.Errorf("failed to marshal order: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(orderKey(order.ID), data)
	})
}

func (s *Storage) GetOrder(_ context.Context, id string) (*nanoca.Order, error) {
	var order nanoca.Order

	err := s.db.View(func(txn *badger.Txn) error {
		return getJSON(txn, orderKey(id), "order", &order)
	})
	if err != nil {
		return nil, err
	}

	return &order, nil
}

func (s *Storage) SetOrderStatus(_ context.Context, id, from, to string) error {
	return s.update(func(txn *badger.Txn) error {
		var order nanoca.Order
		if err := getJSON(txn, orderKey(id), "order", &order); err != nil {
			return err
		}

		if order.Status != from {
			return fmt.Errorf("order status is %s, not %s: %w", order.Status, from, nanoca.ErrStatusMismatch)
		}
		order.Status = to

		return setJSON(txn, orderKey(id), "order", &order)
	})
}

func (s *Storage) ReserveOrderFinalize(_ context.Context, id, token string, lease time.Duration) error {
	return s.update(func(txn *badger.Txn) error {
		var order nanoca.Order
		if err := getJSON(txn, orderKey(id), "order", &order); err != nil {
			return err
		}
		if err := orderRecord(&order).reserve(nanoca.OrderStatusReady, token, lease); err != nil {
			return err
		}
		return setJSON(txn, orderKey(id), "order", &order)
	})
}

func (s *Storage) ReleaseOrderFinalize(_ context.Context, id, token, to string) error {
	return s.update(func(txn *badger.Txn) error {
		var order nanoca.Order
		if err := getJSON(txn, orderKey(id), "order", &order); err != nil {
			return err
		}
		if err := orderRecord(&order).consume(token); err != nil {
			return err
		}
		order.Status = to

		return setJSON(txn, orderKey(id), "order", &order)
	})
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
				var order nanoca.Order
				if err := json.Unmarshal(val, &order); err != nil {
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

func (s *Storage) CreateAuthorization(_ context.Context, authz *nanoca.Authorization) error {
	data, err := json.Marshal(authz)
	if err != nil {
		return fmt.Errorf("failed to marshal authorization: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(authzKey(authz.ID), data)
	})
}

func (s *Storage) GetAuthorization(_ context.Context, id string) (*nanoca.Authorization, error) {
	var authz nanoca.Authorization

	err := s.db.View(func(txn *badger.Txn) error {
		return getJSON(txn, authzKey(id), "authorization", &authz)
	})
	if err != nil {
		return nil, err
	}

	return &authz, nil
}

func (s *Storage) SettleAuthorization(_ context.Context, authz *nanoca.Authorization) error {
	return s.update(func(txn *badger.Txn) error {
		var stored nanoca.Authorization
		if err := getJSON(txn, authzKey(authz.ID), "authorization", &stored); err != nil {
			return err
		}
		if stored.Status != nanoca.AuthzStatusPending {
			return fmt.Errorf("authorization status is %s, not %s: %w", stored.Status, nanoca.AuthzStatusPending, nanoca.ErrStatusMismatch)
		}
		return setJSON(txn, authzKey(authz.ID), "authorization", authz)
	})
}

func (s *Storage) CreateChallenge(_ context.Context, challenge *nanoca.Challenge) error {
	data, err := json.Marshal(challenge)
	if err != nil {
		return fmt.Errorf("failed to marshal challenge: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(challengeKey(challenge.ID), data)
	})
}

func (s *Storage) GetChallenge(_ context.Context, id string) (*nanoca.Challenge, error) {
	var challenge nanoca.Challenge

	err := s.db.View(func(txn *badger.Txn) error {
		return getJSON(txn, challengeKey(id), "challenge", &challenge)
	})
	if err != nil {
		return nil, err
	}

	return &challenge, nil
}

func (s *Storage) ReserveChallengeValidation(_ context.Context, id, reservationToken string, lease time.Duration) error {
	return s.update(func(txn *badger.Txn) error {
		var challenge nanoca.Challenge
		if err := getJSON(txn, challengeKey(id), "challenge", &challenge); err != nil {
			return err
		}
		if err := challengeRecord(&challenge).reserve(nanoca.ChallengeStatusPending, reservationToken, lease); err != nil {
			return err
		}
		return setJSON(txn, challengeKey(id), "challenge", &challenge)
	})
}

func (s *Storage) settleChallenge(id, reservationToken string, updateFn func(*nanoca.Challenge)) error {
	return s.update(func(txn *badger.Txn) error {
		var challenge nanoca.Challenge
		if err := getJSON(txn, challengeKey(id), "challenge", &challenge); err != nil {
			return err
		}
		if err := challengeRecord(&challenge).consume(reservationToken); err != nil {
			return err
		}
		updateFn(&challenge)

		return setJSON(txn, challengeKey(id), "challenge", &challenge)
	})
}

func (s *Storage) SetChallengeValid(_ context.Context, id, reservationToken string, validated time.Time, attestation []byte) error {
	return s.settleChallenge(id, reservationToken, func(c *nanoca.Challenge) {
		c.Status = nanoca.ChallengeStatusValid
		c.Validated = &validated
		c.Attestation = attestation
		c.Error = nil
	})
}

func (s *Storage) SetChallengeInvalid(_ context.Context, id, reservationToken string, validated time.Time, problem *nanoca.Problem) error {
	return s.settleChallenge(id, reservationToken, func(c *nanoca.Challenge) {
		c.Status = nanoca.ChallengeStatusInvalid
		c.Validated = &validated
		c.Error = problem
	})
}

func (s *Storage) ReleaseChallengeValidation(_ context.Context, id, reservationToken string) error {
	return s.settleChallenge(id, reservationToken, func(c *nanoca.Challenge) {
		c.Status = nanoca.ChallengeStatusPending
	})
}

func (s *Storage) CompleteOrder(_ context.Context, order *nanoca.Order, cert *nanoca.Certificate, token string) error {
	// CompleteOrder owns the processing-to-valid transition; forcing the
	// status here keeps a stored certificate from ever sharing a record
	// with a non-valid order, whatever the caller passed.
	completed := *order
	completed.Status = nanoca.OrderStatusValid
	completed.Reservation = nil

	return s.update(func(txn *badger.Txn) error {
		var stored nanoca.Order
		if err := getJSON(txn, orderKey(order.ID), "order", &stored); err != nil {
			return err
		}
		if err := orderRecord(&stored).consume(token); err != nil {
			return err
		}

		if err := setJSON(txn, orderKey(order.ID), "order", &completed); err != nil {
			return err
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

	if len(cert.Raw) > 0 {
		x509Cert, err := x509.ParseCertificate(cert.Raw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate from raw bytes: %w", err)
		}
		cert.Certificate = x509Cert
	}

	return &cert, nil
}

// Close releases any resources held by the storage
func (s *Storage) Close() error {
	return s.db.Close()
}

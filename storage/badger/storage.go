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
		entry := badger.NewEntry(nonceKey(nonce.Value), data)
		return txn.SetEntry(entry)
	})
}

// ConsumeNonce atomically validates and consumes a nonce, preventing race conditions
func (s *Storage) ConsumeNonce(_ context.Context, value string, expiry time.Duration) (*nanoca.Nonce, error) {
	var nonce nanoca.Nonce

	err := s.db.Update(func(txn *badger.Txn) error {
		item, err := txn.Get(nonceKey(value))
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				return nanoca.ErrNonceNotFound
			}
			return fmt.Errorf("failed to get nonce: %w", err)
		}

		err = item.Value(func(val []byte) error {
			return json.Unmarshal(val, &nonce)
		})
		if err != nil {
			return fmt.Errorf("failed to unmarshal nonce: %w", err)
		}

		if time.Since(nonce.CreatedAt) > expiry {
			if err := txn.Delete(nonceKey(value)); err != nil {
				return fmt.Errorf("failed to delete expired nonce: %w", err)
			}
			return nanoca.ErrNonceExpired
		}

		return txn.Delete(nonceKey(value))
	})
	if err != nil {
		return nil, err
	}

	return &nonce, nil
}

func (s *Storage) CreateAccount(_ context.Context, account *nanoca.Account) error {
	data, err := json.Marshal(account)
	if err != nil {
		return fmt.Errorf("failed to marshal account: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		if err := txn.Set(accountKey(account.ID), data); err != nil {
			return err
		}

		if len(account.KeyBytes) > 0 {
			keyHash := string(account.KeyBytes)
			return txn.Set(accountKeyLookupKey(keyHash), []byte(account.ID))
		}

		return nil
	})
}

func (s *Storage) GetAccount(_ context.Context, id string) (*nanoca.Account, error) {
	var account nanoca.Account

	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(accountKey(id))
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &account)
		})
	})
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil, errors.New("account not found")
		}
		return nil, fmt.Errorf("failed to get account: %w", err)
	}

	return &account, nil
}

func (s *Storage) GetAccountByKey(ctx context.Context, keyThumbprint string) (*nanoca.Account, error) {
	var accountID string

	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(accountKeyLookupKey(keyThumbprint))
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			accountID = string(val)
			return nil
		})
	})
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil, errors.New("account not found")
		}
		return nil, fmt.Errorf("failed to lookup account by key: %w", err)
	}

	return s.GetAccount(ctx, accountID)
}

func (s *Storage) UpdateAccount(ctx context.Context, account *nanoca.Account) error {
	_, err := s.GetAccount(ctx, account.ID)
	if err != nil {
		return errors.New("account not found")
	}

	data, err := json.Marshal(account)
	if err != nil {
		return fmt.Errorf("failed to marshal account: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		if err := txn.Set(accountKey(account.ID), data); err != nil {
			return err
		}

		if len(account.KeyBytes) > 0 {
			keyHash := string(account.KeyBytes)
			return txn.Set(accountKeyLookupKey(keyHash), []byte(account.ID))
		}

		return nil
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
		item, err := txn.Get(orderKey(id))
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &order)
		})
	})
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil, errors.New("order not found")
		}
		return nil, fmt.Errorf("failed to get order: %w", err)
	}

	return &order, nil
}

func (s *Storage) UpdateOrder(ctx context.Context, order *nanoca.Order) error {
	_, err := s.GetOrder(ctx, order.ID)
	if err != nil {
		return errors.New("order not found")
	}

	data, err := json.Marshal(order)
	if err != nil {
		return fmt.Errorf("failed to marshal order: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(orderKey(order.ID), data)
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
		item, err := txn.Get(authzKey(id))
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &authz)
		})
	})
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil, errors.New("authorization not found")
		}
		return nil, fmt.Errorf("failed to get authorization: %w", err)
	}

	return &authz, nil
}

func (s *Storage) UpdateAuthorization(ctx context.Context, authz *nanoca.Authorization) error {
	_, err := s.GetAuthorization(ctx, authz.ID)
	if err != nil {
		return errors.New("authorization not found")
	}

	data, err := json.Marshal(authz)
	if err != nil {
		return fmt.Errorf("failed to marshal authorization: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(authzKey(authz.ID), data)
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
		item, err := txn.Get(challengeKey(id))
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &challenge)
		})
	})
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil, errors.New("challenge not found")
		}
		return nil, fmt.Errorf("failed to get challenge: %w", err)
	}

	return &challenge, nil
}

func (s *Storage) updateChallengeStatus(id, expectedStatus string, updateFn func(*nanoca.Challenge)) error {
	return s.db.Update(func(txn *badger.Txn) error {
		item, err := txn.Get(challengeKey(id))
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				return errors.New("challenge not found")
			}
			return fmt.Errorf("failed to get challenge: %w", err)
		}

		var challenge nanoca.Challenge
		err = item.Value(func(val []byte) error {
			return json.Unmarshal(val, &challenge)
		})
		if err != nil {
			return fmt.Errorf("failed to unmarshal challenge: %w", err)
		}

		if challenge.Status != expectedStatus {
			return fmt.Errorf("challenge status mismatch: expected %s, got %s", expectedStatus, challenge.Status)
		}

		updateFn(&challenge)

		data, err := json.Marshal(challenge)
		if err != nil {
			return fmt.Errorf("failed to marshal challenge: %w", err)
		}

		return txn.Set(challengeKey(id), data)
	})
}

func (s *Storage) SetChallengeProcessing(_ context.Context, id string) error {
	return s.updateChallengeStatus(id, nanoca.ChallengeStatusPending, func(c *nanoca.Challenge) {
		c.Status = nanoca.ChallengeStatusProcessing
	})
}

func (s *Storage) SetChallengeValid(_ context.Context, id string, validated time.Time, attestation map[string]any) error {
	return s.updateChallengeStatus(id, nanoca.ChallengeStatusProcessing, func(c *nanoca.Challenge) {
		c.Status = nanoca.ChallengeStatusValid
		c.Validated = &validated
		c.Attestation = attestation
		c.Error = nil
	})
}

func (s *Storage) SetChallengeInvalid(_ context.Context, id string, validated time.Time, problem *nanoca.Problem) error {
	return s.updateChallengeStatus(id, nanoca.ChallengeStatusProcessing, func(c *nanoca.Challenge) {
		c.Status = nanoca.ChallengeStatusInvalid
		c.Validated = &validated
		c.Error = problem
	})
}

func (s *Storage) CreateCertificate(_ context.Context, cert *nanoca.Certificate) error {
	data, err := json.Marshal(cert)
	if err != nil {
		return fmt.Errorf("failed to marshal certificate: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(certificateKey(cert.SerialNumber), data)
	})
}

func (s *Storage) GetCertificate(_ context.Context, id string) (*nanoca.Certificate, error) {
	var cert nanoca.Certificate

	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(certificateKey(id))
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			if err := json.Unmarshal(val, &cert); err != nil {
				return err
			}

			if len(cert.Raw) > 0 {
				x509Cert, err := x509.ParseCertificate(cert.Raw)
				if err != nil {
					return fmt.Errorf("failed to parse certificate from raw bytes: %w", err)
				}
				cert.Certificate = x509Cert
			}

			return nil
		})
	})
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil, errors.New("certificate not found")
		}
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	return &cert, nil
}

// Close releases any resources held by the storage
func (s *Storage) Close() error {
	return s.db.Close()
}

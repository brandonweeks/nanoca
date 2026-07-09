package nanoca

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// MemoryStorage is a map-backed Storage for tests and quick starts. It is
// the reference implementation for the storage/storagetest conformance
// suite.
type MemoryStorage struct {
	mu          sync.Mutex
	nonces      map[string]storedNonce
	accounts    map[string]record
	accountKeys map[string]string
	orders      map[string]record
	authzs      map[string]record
	challenges  map[string]record
	certs       map[string][]byte
}

// record is a stored document with its revision counter.
type record struct {
	data []byte
	rev  uint64
}

// storedNonce carries the ttl deadline so minted-but-never-presented
// nonces can be evicted.
type storedNonce struct {
	data      []byte
	expiresAt time.Time
}

func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		nonces:      make(map[string]storedNonce),
		accounts:    make(map[string]record),
		accountKeys: make(map[string]string),
		orders:      make(map[string]record),
		authzs:      make(map[string]record),
		challenges:  make(map[string]record),
		certs:       make(map[string][]byte),
	}
}

// encode and decode round-trip records through JSON so stored state never
// aliases caller memory.
func encode(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("nanoca: marshal record: %v", err))
	}
	return data
}

func decode[T any](data []byte) (*T, error) {
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("failed to unmarshal record: %w", err)
	}
	return &v, nil
}

func getRecord[T any](m *MemoryStorage, records map[string]record, id string) (*T, Revision, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	stored, ok := records[id]
	if !ok {
		return nil, "", ErrNotFound
	}
	v, err := decode[T](stored.data)
	if err != nil {
		return nil, "", err
	}
	return v, Revision(strconv.FormatUint(stored.rev, 10)), nil
}

// putRecord replaces a stored record if the caller's revision still
// matches. The caller must hold m.mu.
func putRecord(records map[string]record, id string, v any, rev Revision) error {
	stored, ok := records[id]
	if !ok {
		return ErrNotFound
	}
	expected, err := strconv.ParseUint(string(rev), 10, 64)
	if err != nil || stored.rev != expected {
		return fmt.Errorf("revision moved: %w", ErrConflict)
	}
	records[id] = record{data: encode(v), rev: expected + 1}
	return nil
}

func createRecord(records map[string]record, id string, v any) error {
	if _, ok := records[id]; ok {
		return fmt.Errorf("record %q: %w", id, ErrExists)
	}
	records[id] = record{data: encode(v), rev: 1}
	return nil
}

// CreateNonce sweeps nonces past their ttl before storing, so nonces
// that are minted but never presented do not accumulate. The sweep is
// linear in the live nonce count, which the ttl bounds.
func (m *MemoryStorage) CreateNonce(_ context.Context, nonce *Nonce, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for value, stored := range m.nonces {
		if now.After(stored.expiresAt) {
			delete(m.nonces, value)
		}
	}
	if _, ok := m.nonces[nonce.Value]; ok {
		return fmt.Errorf("nonce %q: %w", nonce.Value, ErrExists)
	}
	m.nonces[nonce.Value] = storedNonce{data: encode(nonce), expiresAt: now.Add(ttl)}
	return nil
}

func (m *MemoryStorage) TakeNonce(_ context.Context, value string) (*Nonce, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	stored, ok := m.nonces[value]
	if !ok {
		return nil, ErrNotFound
	}
	delete(m.nonces, value)
	return decode[Nonce](stored.data)
}

func (m *MemoryStorage) CreateAccount(_ context.Context, account *Account) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if account.KeyThumbprint != "" {
		if _, ok := m.accountKeys[account.KeyThumbprint]; ok {
			return fmt.Errorf("account key already registered: %w", ErrExists)
		}
	}
	if err := createRecord(m.accounts, account.ID, account); err != nil {
		return err
	}
	if account.KeyThumbprint != "" {
		m.accountKeys[account.KeyThumbprint] = account.ID
	}
	return nil
}

func (m *MemoryStorage) GetAccount(_ context.Context, id string) (*Account, Revision, error) {
	return getRecord[Account](m, m.accounts, id)
}

func (m *MemoryStorage) GetAccountByKey(_ context.Context, keyThumbprint string) (*Account, Revision, error) {
	m.mu.Lock()
	id, ok := m.accountKeys[keyThumbprint]
	m.mu.Unlock()
	if !ok {
		return nil, "", ErrNotFound
	}
	return getRecord[Account](m, m.accounts, id)
}

func (m *MemoryStorage) PutAccount(_ context.Context, account *Account, rev Revision) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := putRecord(m.accounts, account.ID, account, rev); err != nil {
		return err
	}
	if account.KeyThumbprint != "" {
		m.accountKeys[account.KeyThumbprint] = account.ID
	}
	return nil
}

func (m *MemoryStorage) CreateOrder(_ context.Context, order *Order, authzs []*Authorization, challenges []*Challenge) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, challenge := range challenges {
		if err := createRecord(m.challenges, challenge.ID, challenge); err != nil {
			return err
		}
	}
	for _, authz := range authzs {
		if err := createRecord(m.authzs, authz.ID, authz); err != nil {
			return err
		}
	}
	return createRecord(m.orders, order.ID, order)
}

func (m *MemoryStorage) GetOrder(_ context.Context, id string) (*Order, Revision, error) {
	return getRecord[Order](m, m.orders, id)
}

func (m *MemoryStorage) PutOrder(_ context.Context, order *Order, rev Revision) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return putRecord(m.orders, order.ID, order, rev)
}

func (m *MemoryStorage) GetOrdersByAccount(_ context.Context, accountID string) ([]*Order, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	orders := []*Order{}
	for _, stored := range m.orders {
		order, err := decode[Order](stored.data)
		if err != nil {
			return nil, err
		}
		if order.AccountID == accountID {
			orders = append(orders, order)
		}
	}
	return orders, nil
}

func (m *MemoryStorage) GetAuthorization(_ context.Context, id string) (*Authorization, Revision, error) {
	return getRecord[Authorization](m, m.authzs, id)
}

func (m *MemoryStorage) PutAuthorization(_ context.Context, authz *Authorization, rev Revision) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return putRecord(m.authzs, authz.ID, authz, rev)
}

func (m *MemoryStorage) GetChallenge(_ context.Context, id string) (*Challenge, Revision, error) {
	return getRecord[Challenge](m, m.challenges, id)
}

func (m *MemoryStorage) PutChallenge(_ context.Context, challenge *Challenge, rev Revision) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return putRecord(m.challenges, challenge.ID, challenge, rev)
}

func (m *MemoryStorage) CreateCertificate(_ context.Context, cert *Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.certs[cert.ID]; ok {
		return fmt.Errorf("certificate %q: %w", cert.ID, ErrExists)
	}
	m.certs[cert.ID] = encode(cert)
	return nil
}

func (m *MemoryStorage) GetCertificate(_ context.Context, id string) (*Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.certs[id]
	if !ok {
		return nil, ErrNotFound
	}
	return decode[Certificate](data)
}

func (m *MemoryStorage) Close() error {
	return nil
}

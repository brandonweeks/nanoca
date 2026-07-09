package nanoca

import (
	"context"
	"errors"
	"time"
)

// Storage is the mechanical record store beneath the CA: typed reads and
// writes with optimistic revisions, and no knowledge of ACME state. All
// reservation, lease, and status-transition logic lives in the CA, so a
// backend never decides why a write should be refused; it only reports
// what happened to it. Implement this interface and run the
// storage/storagetest suite against it.
//
// Sentinel errors a backend must return (possibly wrapped):
//
//   - Get*, Put*, and TakeNonce return ErrNotFound when the record does
//     not exist. GetOrdersByAccount is the exception: an account with no
//     orders yields an empty slice and no error.
//   - Put* returns ErrConflict when the presented revision no longer
//     matches the stored one, meaning the record was written since the
//     read that produced it. A backend that cannot tell a missing record
//     from a mismatched revision (a conditional UPDATE affecting zero
//     rows) may return ErrConflict for both; the CA re-reads and reports
//     the truth.
//   - Create* returns ErrExists, detected by the write itself (a unique
//     constraint violation, not a read followed by a write), when a
//     record with the same ID is already stored. CreateAccount must also
//     treat Account.KeyThumbprint as a unique key, so two concurrent
//     registrations of one key yield exactly one account and one
//     ErrExists.
//
// These are the only errors a backend classifies. The CA turns them into
// ACME outcomes; ErrReserved, ErrStatusMismatch, ErrNonceExpired, and
// ErrAccountExists are produced by the CA core, never by a backend.
//
// Revisions are opaque tokens minted by the backend. Every Get* with a
// matching Put* returns the revision of the record it read; Put* succeeds
// only if the stored revision still matches, and installs a new one. Any
// scheme works, a counter column, a row version, a fresh random token per
// write, as long as two writes of the same record never share a revision.
// The CA never inspects, orders, or fabricates revisions. A revision the
// backend cannot parse or never minted is a mismatch like any other: Put*
// returns ErrConflict, not an internal error.
//
// Writes replace the whole record. A backend never merges fields, judges
// leases, retries, or reads Status, Reservation, or timestamps for any
// purpose beyond storing them. A rejected conditional write must leave
// the record unchanged: the CA re-reads and retries on ErrConflict, so a
// failed Put that wrote anything corrupts that reasoning.
//
// Records must round-trip by encoding: a Get* after a write returns a
// record that marshals to the same document as the one written
// (encoding/json on these types is the reference encoding). Any storage
// shape works, one document per row or one column per field, as long as
// the lookups beyond ID stay answerable: GetAccountByKey by
// Account.KeyThumbprint and GetOrdersByAccount by Order.AccountID.
// Equivalence is by value, not memory shape:
//
//   - Times are instants: a stored time may come back in any location as
//     long as it names the same moment, preserved to at least microsecond
//     precision. The CA never depends on finer.
//   - A nil slice and an empty one are the same value. A nil pointer must
//     come back nil: a missing Reservation is a record with no
//     reservation, not one holding a zero reservation.
//   - Byte fields such as Challenge.Attestation and Certificate.ChainRaw
//     must survive exactly; finalize re-verifies the attestation byte for
//     byte.
//   - Fields tagged json:"-" are not part of the record.
//     Certificate.Certificate is derived from Certificate.Raw; the CA
//     repopulates it on read.
//
// A backend must not impose field-presence constraints of its own: any
// record whose ID is set is storable, even with every other field zero.
// Authorization.Challenges, Order.Authorizations, Order.Finalize,
// Order.Certificate, and Challenge.URL are composed by the CA and never
// reach a backend populated.
//
// A backend needs no clock for correctness: nonce expiry and reservation
// leases are judged by the CA processes sharing the store, so the lease
// caveat is clock skew between CA hosts, as documented on
// WithReservationLease. The CreateNonce ttl only licenses storage-level
// cleanup. Nothing else expires at the storage layer: orders,
// authorizations, and challenges that never complete are kept, and
// reclaiming that space is an operator concern outside this contract.
type Storage interface {
	// CreateNonce stores a fresh nonce. ttl is a cleanup hint: a backend
	// MAY drop the nonce any time after ttl has elapsed (a dropped nonce
	// reads as ErrNotFound, which the CA reports as badNonce), keeping
	// nonces that are minted but never presented from accumulating.
	// Correctness never depends on it; the CA judges expiry against
	// Nonce.CreatedAt on consume.
	CreateNonce(ctx context.Context, nonce *Nonce, ttl time.Duration) error
	// TakeNonce atomically removes and returns the nonce in one step (in
	// SQL, DELETE ... RETURNING), returning ErrNotFound for an unknown or
	// already taken value. An expired nonce is still taken and returned;
	// expiry is judged by the caller.
	TakeNonce(ctx context.Context, value string) (*Nonce, error)

	CreateAccount(ctx context.Context, account *Account) error
	GetAccount(ctx context.Context, id string) (*Account, Revision, error)
	// GetAccountByKey looks up an account by Account.KeyThumbprint: the
	// unpadded base64url encoding of the SHA-256 JWK thumbprint (RFC 7638)
	// of the account key.
	GetAccountByKey(ctx context.Context, keyThumbprint string) (*Account, Revision, error)
	PutAccount(ctx context.Context, account *Account, rev Revision) error

	// CreateOrder stores a new order together with its authorizations and
	// challenges, preferably atomically; a backend without multi-record
	// atomicity must write challenges, then authorizations, then the order,
	// so a readable record never references a missing one.
	CreateOrder(ctx context.Context, order *Order, authzs []*Authorization, challenges []*Challenge) error
	GetOrder(ctx context.Context, id string) (*Order, Revision, error)
	PutOrder(ctx context.Context, order *Order, rev Revision) error
	GetOrdersByAccount(ctx context.Context, accountID string) ([]*Order, error)

	GetAuthorization(ctx context.Context, id string) (*Authorization, Revision, error)
	PutAuthorization(ctx context.Context, authz *Authorization, rev Revision) error

	GetChallenge(ctx context.Context, id string) (*Challenge, Revision, error)
	PutChallenge(ctx context.Context, challenge *Challenge, rev Revision) error

	// CreateCertificate stores an issued certificate; certificates are
	// written once and never rewritten.
	CreateCertificate(ctx context.Context, cert *Certificate) error
	GetCertificate(ctx context.Context, id string) (*Certificate, error)

	Close() error
}

// Revision is an opaque per-record write token minted by the backend.
type Revision string

// Sentinels a Storage backend returns; see the Storage contract.
var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("revision conflict")
	ErrExists   = errors.New("record already exists")
)

// Sentinels produced by the CA core, never by a Storage backend. They are
// exported so callers embedding the CA can distinguish the conditions in
// logs and tests.
var (
	ErrNonceExpired   = errors.New("nonce expired")
	ErrAccountExists  = errors.New("account already exists")
	ErrStatusMismatch = errors.New("status mismatch")
	ErrReserved       = errors.New("reservation held")
)

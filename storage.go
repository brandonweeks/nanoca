package nanoca

import (
	"context"
	"errors"
	"time"
)

// Sentinel errors that Storage implementations must return (possibly wrapped)
// so handlers can distinguish expected conditions — a missing or expired
// object, a duplicate account key, a reservation held elsewhere — from a
// backend failure. Operations that fail for any other reason are treated as
// internal server errors.
//
//   - Get*, Update*, Settle*, Reserve*, and SetChallenge* must return
//     ErrNotFound when the object does not exist.
//   - ConsumeNonce must return ErrNotFound for an unknown or already
//     consumed nonce, and ErrNonceExpired after consuming an expired one.
//   - CreateAccount must return ErrAccountExists, atomically with the
//     write, if an account already exists with the same key thumbprint.
//   - SetOrderStatus, SettleAuthorization, and the reserve/fenced methods
//     below must return ErrStatusMismatch, atomically with the write, when
//     the record is not in the expected preceding status.
//   - Reserve* must return ErrReserved, atomically with the write, while
//     an unexpired reservation is held; the fenced writes (CompleteOrder,
//     ReleaseOrderFinalize, ReleaseChallengeValidation, SetChallengeValid,
//     SetChallengeInvalid) must return ErrReserved when the presented token
//     does not match the stored reservation. Successful fenced writes clear
//     the reservation.
//
// Reservation leases are judged by comparing the stored ReservedAt against
// the caller-supplied duration with the backend's clock, so a shared
// backend assumes loosely synchronized CA hosts: clock skew shifts the
// effective lease by the skew.
var (
	ErrNotFound       = errors.New("not found")
	ErrNonceExpired   = errors.New("nonce expired")
	ErrAccountExists  = errors.New("account already exists")
	ErrStatusMismatch = errors.New("status mismatch")
	ErrReserved       = errors.New("reservation held")
)

type Storage interface {
	CreateNonce(ctx context.Context, nonce *Nonce) error
	ConsumeNonce(ctx context.Context, value string, expiry time.Duration) (*Nonce, error)

	CreateAccount(ctx context.Context, account *Account) error
	GetAccount(ctx context.Context, id string) (*Account, error)
	// GetAccountByKey looks up an account by Account.KeyThumbprint: the
	// unpadded base64url encoding of the SHA-256 JWK thumbprint (RFC 7638)
	// of the account key.
	GetAccountByKey(ctx context.Context, keyThumbprint string) (*Account, error)
	UpdateAccount(ctx context.Context, account *Account) error

	CreateOrder(ctx context.Context, order *Order) error
	GetOrder(ctx context.Context, id string) (*Order, error)
	// SetOrderStatus transitions an order from one status to the next only
	// if it is still in the expected preceding status, so a stale caller
	// cannot overwrite a transition that has already happened.
	SetOrderStatus(ctx context.Context, id, from, to string) error
	// ReserveOrderFinalize takes the exclusive right to finalize an order:
	// atomically, it transitions a ready order to processing — or reclaims
	// a processing order whose reservation is older than lease — recording
	// token and the reservation time. It returns ErrReserved while an
	// unexpired reservation is held and ErrStatusMismatch for any other
	// status. The reservation is consumed by CompleteOrder or surrendered
	// by ReleaseOrderFinalize; it holds across CA processes sharing this
	// storage.
	ReserveOrderFinalize(ctx context.Context, id, token string, lease time.Duration) error
	// ReleaseOrderFinalize surrenders a finalize reservation, transitioning
	// the order from processing to `to` — ready, so a retry can finalize
	// again, or invalid, for a terminal failure — and clearing the
	// reservation. The write is fenced by token.
	ReleaseOrderFinalize(ctx context.Context, id, token, to string) error
	GetOrdersByAccount(ctx context.Context, accountID string) ([]*Order, error)

	CreateAuthorization(ctx context.Context, authz *Authorization) error
	GetAuthorization(ctx context.Context, id string) (*Authorization, error)
	// SettleAuthorization transitions a pending authorization to
	// authz.Status — valid or invalid — writing the full record so the
	// refreshed embedded challenge copies land with the transition. It
	// returns ErrStatusMismatch, atomically with the write, when the stored
	// authorization is no longer pending, so a recompute from stale reads
	// cannot overwrite a settlement another request has since written.
	SettleAuthorization(ctx context.Context, authz *Authorization) error

	CreateChallenge(ctx context.Context, challenge *Challenge) error
	GetChallenge(ctx context.Context, id string) (*Challenge, error)
	// ReserveChallengeValidation takes the exclusive right to validate a
	// challenge, with the same contract as ReserveOrderFinalize: pending to
	// processing, or reclaim of an expired reservation.
	ReserveChallengeValidation(ctx context.Context, id, reservationToken string, lease time.Duration) error
	// ReleaseChallengeValidation surrenders a validation reservation,
	// returning the challenge from processing to pending so a retry can
	// validate again after a transient failure. The write is fenced by
	// reservationToken.
	ReleaseChallengeValidation(ctx context.Context, id, reservationToken string) error
	// SetChallengeValid stores the raw CBOR attestation object beside the
	// status; it is opaque to storage and re-verified byte-for-byte at
	// finalize. The write is fenced by reservationToken and clears the
	// reservation.
	SetChallengeValid(ctx context.Context, id, reservationToken string, validated time.Time, attestation []byte) error
	SetChallengeInvalid(ctx context.Context, id, reservationToken string, validated time.Time, problem *Problem) error

	// CompleteOrder atomically stores the certificate under Certificate.ID
	// — the identifier GetCertificate looks up — and transitions the order
	// from processing to valid, clearing its reservation; the write is
	// fenced by token, so a finalize whose reservation was reclaimed cannot
	// persist a certificate for a stale CSR. On error neither write is
	// persisted, so a stored certificate always belongs to a valid order.
	CompleteOrder(ctx context.Context, order *Order, cert *Certificate, token string) error
	GetCertificate(ctx context.Context, id string) (*Certificate, error)

	Close() error
}

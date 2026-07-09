package nanoca

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// storageMachine wraps a Storage backend with the concurrency machine the
// handlers rely on: reservations, leases, guarded status transitions, and
// the classification of lost races into ErrReserved and ErrStatusMismatch.
// Backends stay mechanical; every decision about why a write is refused is
// made here, against the same read the winning write is conditioned on.
type storageMachine struct {
	b Storage
}

func newStorageMachine(b Storage) *storageMachine {
	return &storageMachine{b: b}
}

// cas runs one guarded write as read, classify-and-modify, conditional
// put, retrying from a fresh read when the put loses to a concurrent
// writer. modify must be a pure in-memory transform of the record it is
// handed: no I/O, no side effects, safe to run any number of times. An
// error from modify is the operation's verdict and ends the loop, so the
// verdict is always judged from the exact record the winning write
// replaced. Retries are unbounded; the context bounds the loop.
func cas[T any](
	ctx context.Context,
	get func(context.Context, string) (*T, Revision, error),
	put func(context.Context, *T, Revision) error,
	id string,
	modify func(*T) error,
) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		record, rev, err := get(ctx, id)
		if err != nil {
			return err
		}
		if err := modify(record); err != nil {
			return err
		}
		switch err := put(ctx, record, rev); {
		case err == nil:
			return nil
		case errors.Is(err, ErrConflict):
			// Another writer landed between the read and the put; re-read
			// and judge what it left behind.
		default:
			return err
		}
	}
}

// reservedRecord points at the status and reservation fields the
// reservation state machine manipulates, so orders and challenges share
// one implementation of its transitions.
type reservedRecord struct {
	status      *string
	reservation **Reservation
	resource    string
	processing  string
}

func orderRecord(o *Order) reservedRecord {
	return reservedRecord{&o.Status, &o.Reservation, "order", OrderStatusProcessing}
}

func challengeRecord(c *Challenge) reservedRecord {
	return reservedRecord{&c.Status, &c.Reservation, "challenge", ChallengeStatusProcessing}
}

// reserve transitions the record from `from` to processing, or reclaims a
// processing record whose reservation has lapsed, recording token and the
// reservation time. The lease is judged here only, with this host's
// clock: a write with the matching token succeeds even after the lease
// has lapsed, so a slow holder that was not superseded can still commit.
// Clock skew between CA hosts sharing a store shifts the effective lease
// by the skew.
func (r reservedRecord) reserve(from, token string, lease time.Duration) error {
	switch {
	case *r.status == from:
	case *r.status == r.processing && !(*r.reservation).Live(lease):
	case *r.status == r.processing:
		return fmt.Errorf("%s is already reserved: %w", r.resource, ErrReserved)
	default:
		return fmt.Errorf("%s status is %s, not %s: %w", r.resource, *r.status, from, ErrStatusMismatch)
	}

	*r.status = r.processing
	*r.reservation = &Reservation{Token: token, ReservedAt: time.Now()}
	return nil
}

// consume admits a write only from the reservation's holder and clears the
// reservation; the caller sets the resulting status.
func (r reservedRecord) consume(token string) error {
	if *r.status != r.processing {
		return fmt.Errorf("%s status is %s, not %s: %w", r.resource, *r.status, r.processing, ErrStatusMismatch)
	}
	if *r.reservation == nil || (*r.reservation).Token != token {
		return fmt.Errorf("%s reservation is held by another token: %w", r.resource, ErrReserved)
	}
	*r.reservation = nil
	return nil
}

func (m *storageMachine) CreateNonce(ctx context.Context, nonce *Nonce, ttl time.Duration) error {
	return m.b.CreateNonce(ctx, nonce, ttl)
}

// ConsumeNonce takes the nonce and judges its expiry afterwards, so an
// expired nonce is still consumed rather than lingering forever.
func (m *storageMachine) ConsumeNonce(ctx context.Context, value string, expiry time.Duration) (*Nonce, error) {
	nonce, err := m.b.TakeNonce(ctx, value)
	if err != nil {
		return nil, err
	}
	if time.Since(nonce.CreatedAt) > expiry {
		return nil, ErrNonceExpired
	}
	return nonce, nil
}

func (m *storageMachine) CreateAccount(ctx context.Context, account *Account) error {
	if err := m.b.CreateAccount(ctx, account); err != nil {
		if errors.Is(err, ErrExists) {
			return fmt.Errorf("%w: %w", ErrAccountExists, err)
		}
		return err
	}
	return nil
}

func (m *storageMachine) GetAccount(ctx context.Context, id string) (*Account, error) {
	account, _, err := m.b.GetAccount(ctx, id)
	return account, err
}

func (m *storageMachine) GetAccountByKey(ctx context.Context, keyThumbprint string) (*Account, error) {
	account, _, err := m.b.GetAccountByKey(ctx, keyThumbprint)
	return account, err
}

// UpdateAccount overwrites the stored account: the last writer wins, as
// long as the account still exists.
func (m *storageMachine) UpdateAccount(ctx context.Context, account *Account) error {
	return cas(ctx, m.b.GetAccount, m.b.PutAccount, account.ID, func(stored *Account) error {
		*stored = *account
		return nil
	})
}

func (m *storageMachine) CreateOrder(ctx context.Context, order *Order, authzs []*Authorization, challenges []*Challenge) error {
	// The composed wire fields are never persisted; a stored record names
	// its children by ID.
	o := *order
	o.Authorizations = nil
	o.Finalize = ""
	o.Certificate = ""
	strippedAuthzs := make([]*Authorization, len(authzs))
	for i, authz := range authzs {
		a := *authz
		a.Challenges = nil
		strippedAuthzs[i] = &a
	}
	strippedChallenges := make([]*Challenge, len(challenges))
	for i, challenge := range challenges {
		c := *challenge
		c.URL = ""
		strippedChallenges[i] = &c
	}
	return m.b.CreateOrder(ctx, &o, strippedAuthzs, strippedChallenges)
}

func (m *storageMachine) GetOrder(ctx context.Context, id string) (*Order, error) {
	order, _, err := m.b.GetOrder(ctx, id)
	return order, err
}

// SetOrderStatus transitions an order from one status to the next only if
// it is still in the expected preceding status, so a stale caller cannot
// overwrite a transition that has already happened.
func (m *storageMachine) SetOrderStatus(ctx context.Context, id, from, to string) error {
	return cas(ctx, m.b.GetOrder, m.b.PutOrder, id, func(order *Order) error {
		if order.Status != from {
			return fmt.Errorf("order status is %s, not %s: %w", order.Status, from, ErrStatusMismatch)
		}
		order.Status = to
		return nil
	})
}

// ReserveOrderFinalize takes the exclusive right to finalize an order:
// it transitions a ready order to processing, or reclaims a processing
// order whose reservation is older than lease, recording token and the
// reservation time. It returns ErrReserved while an unexpired reservation
// is held and ErrStatusMismatch for any other status. The reservation is
// consumed by CompleteOrder or surrendered by ReleaseOrderFinalize; it
// holds across CA processes sharing the store.
func (m *storageMachine) ReserveOrderFinalize(ctx context.Context, id, token string, lease time.Duration) error {
	return cas(ctx, m.b.GetOrder, m.b.PutOrder, id, func(order *Order) error {
		return orderRecord(order).reserve(OrderStatusReady, token, lease)
	})
}

// ReleaseOrderFinalize surrenders a finalize reservation, transitioning
// the order from processing to `to`: ready, so a retry can finalize
// again, or invalid, for a terminal failure. The write requires the
// matching token.
func (m *storageMachine) ReleaseOrderFinalize(ctx context.Context, id, token, to string) error {
	return cas(ctx, m.b.GetOrder, m.b.PutOrder, id, func(order *Order) error {
		if err := orderRecord(order).consume(token); err != nil {
			return err
		}
		order.Status = to
		return nil
	})
}

// GetAuthorization loads an authorization and composes the wire-format
// Challenges from the challenge records named by ChallengeIDs.
func (m *storageMachine) GetAuthorization(ctx context.Context, id string) (*Authorization, error) {
	authz, _, err := m.b.GetAuthorization(ctx, id)
	if err != nil {
		return nil, err
	}
	authz.Challenges = make([]Challenge, 0, len(authz.ChallengeIDs))
	for _, challengeID := range authz.ChallengeIDs {
		challenge, _, err := m.b.GetChallenge(ctx, challengeID)
		if err != nil {
			return nil, fmt.Errorf("failed to compose challenge %s: %w", challengeID, err)
		}
		authz.Challenges = append(authz.Challenges, *challenge)
	}
	return authz, nil
}

// SettleAuthorization transitions a pending authorization to authz.Status,
// valid or invalid; only the status is written. It returns
// ErrStatusMismatch when the stored authorization is no longer pending, so
// a recompute from stale reads cannot overwrite a settlement another
// request has since written.
func (m *storageMachine) SettleAuthorization(ctx context.Context, authz *Authorization) error {
	return cas(ctx, m.b.GetAuthorization, m.b.PutAuthorization, authz.ID, func(stored *Authorization) error {
		if stored.Status != AuthzStatusPending {
			return fmt.Errorf("authorization status is %s, not %s: %w", stored.Status, AuthzStatusPending, ErrStatusMismatch)
		}
		stored.Status = authz.Status
		return nil
	})
}

func (m *storageMachine) GetChallenge(ctx context.Context, id string) (*Challenge, error) {
	challenge, _, err := m.b.GetChallenge(ctx, id)
	return challenge, err
}

// ReserveChallengeValidation takes the exclusive right to validate a
// challenge, with the same contract as ReserveOrderFinalize: pending to
// processing, or reclaim of an expired reservation.
func (m *storageMachine) ReserveChallengeValidation(ctx context.Context, id, reservationToken string, lease time.Duration) error {
	return cas(ctx, m.b.GetChallenge, m.b.PutChallenge, id, func(challenge *Challenge) error {
		return challengeRecord(challenge).reserve(ChallengeStatusPending, reservationToken, lease)
	})
}

// SettleChallenge settles a reserved challenge, transitioning it from
// processing to challenge.Status and clearing the reservation; the write
// requires the matching reservationToken. The full record is written, so
// the settlement's fields (Validated, Error, and the raw attestation
// object, which is re-verified byte for byte at finalize) land with the
// transition. Settling back to pending surrenders the reservation so a
// retry can validate again after a transient failure.
func (m *storageMachine) SettleChallenge(ctx context.Context, challenge *Challenge, reservationToken string) error {
	settled := *challenge
	settled.Reservation = nil
	settled.URL = ""
	return cas(ctx, m.b.GetChallenge, m.b.PutChallenge, challenge.ID, func(stored *Challenge) error {
		if err := challengeRecord(stored).consume(reservationToken); err != nil {
			return err
		}
		*stored = settled
		return nil
	})
}

// CompleteOrder stores the certificate and transitions the order from
// processing to valid, clearing its reservation. The certificate is
// written first, unconditionally; the token-gated order write is the
// commit point that makes it reachable, so a finalize whose reservation
// was reclaimed cannot make its certificate servable for a stale CSR. A
// completion that loses the order write leaves the certificate stored but
// referenced by no order.
func (m *storageMachine) CompleteOrder(ctx context.Context, order *Order, cert *Certificate, token string) error {
	if err := m.b.CreateCertificate(ctx, cert); err != nil {
		return fmt.Errorf("failed to store certificate: %w", err)
	}

	// CompleteOrder owns the processing-to-valid transition; forcing the
	// status here keeps an order from referencing a certificate without
	// turning valid, whatever the caller passed.
	completed := *order
	completed.Status = OrderStatusValid
	completed.Reservation = nil

	return cas(ctx, m.b.GetOrder, m.b.PutOrder, order.ID, func(stored *Order) error {
		if err := orderRecord(stored).consume(token); err != nil {
			return err
		}
		*stored = completed
		return nil
	})
}

func (m *storageMachine) GetCertificate(ctx context.Context, id string) (*Certificate, error) {
	cert, err := m.b.GetCertificate(ctx, id)
	if err != nil {
		return nil, err
	}
	if len(cert.Raw) > 0 && cert.Certificate == nil {
		parsed, err := x509.ParseCertificate(cert.Raw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate from raw bytes: %w", err)
		}
		cert.Certificate = parsed
	}
	return cert, nil
}

func (m *storageMachine) Close() error {
	return m.b.Close()
}

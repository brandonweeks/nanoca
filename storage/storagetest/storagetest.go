package storagetest

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/brandonweeks/nanoca"
)

// RunConformanceTests exercises the nanoca.Storage contract against a
// backend. newStorage is called once per subtest and must return an empty
// store; register cleanup with t.Cleanup.
func RunConformanceTests(t *testing.T, newStorage func(t *testing.T) nanoca.Storage) {
	t.Run("GetMissing", func(t *testing.T) { testGetMissing(t, newStorage(t)) })
	t.Run("PutMissing", func(t *testing.T) { testPutMissing(t, newStorage(t)) })
	t.Run("RoundTrip", func(t *testing.T) { testRoundTrip(t, newStorage(t)) })
	t.Run("CreateDuplicate", func(t *testing.T) { testCreateDuplicate(t, newStorage(t)) })
	t.Run("ConcurrentCreateAccount", func(t *testing.T) { testConcurrentCreateAccount(t, newStorage(t)) })
	t.Run("StaleRevision", func(t *testing.T) { testStaleRevision(t, newStorage(t)) })
	t.Run("GarbageRevision", func(t *testing.T) { testGarbageRevision(t, newStorage(t)) })
	t.Run("RejectedPutWritesNothing", func(t *testing.T) { testRejectedPutWritesNothing(t, newStorage(t)) })
	t.Run("PairwiseCASRace", func(t *testing.T) { testPairwiseCASRace(t, newStorage(t)) })
	t.Run("LostUpdateStress", func(t *testing.T) { testLostUpdateStress(t, newStorage(t)) })
	t.Run("TakeNonce", func(t *testing.T) { testTakeNonce(t, newStorage(t)) })
	t.Run("ConcurrentTakeNonce", func(t *testing.T) { testConcurrentTakeNonce(t, newStorage(t)) })
	t.Run("AccountByKey", func(t *testing.T) { testAccountByKey(t, newStorage(t)) })
	t.Run("CreateOrderTree", func(t *testing.T) { testCreateOrderTree(t, newStorage(t)) })
}

// createOrder stores a bare order so a record exists to write against.
func createOrder(t *testing.T, s nanoca.Storage, order *nanoca.Order) {
	t.Helper()
	if err := s.CreateOrder(t.Context(), order, nil, nil); err != nil {
		t.Fatalf("CreateOrder() error = %v", err)
	}
}

var timeType = reflect.TypeFor[time.Time]()

// normalize rewrites v in place so that records differing only in time
// location or nil-versus-empty slices marshal identically: every
// reachable time.Time is converted to UTC and every zero-length slice is
// set to nil.
func normalize(v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			normalize(v.Elem())
		}
	case reflect.Struct:
		if v.Type() == timeType {
			if v.CanSet() {
				v.Set(reflect.ValueOf(v.Interface().(time.Time).UTC()))
			}
			return
		}
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				normalize(v.Field(i))
			}
		}
	case reflect.Slice:
		if v.Len() == 0 {
			if v.CanSet() {
				v.Set(reflect.Zero(v.Type()))
			}
			return
		}
		for i := range v.Len() {
			normalize(v.Index(i))
		}
	case reflect.Array:
		for i := range v.Len() {
			normalize(v.Index(i))
		}
	}
}

// clearComposed zeroes the wire fields the CA composes on read; they are
// never persisted and take no part in round-trip equivalence.
func clearComposed(v any) {
	switch r := v.(type) {
	case *nanoca.Order:
		r.Authorizations, r.Finalize, r.Certificate = nil, "", ""
	case *nanoca.Authorization:
		r.Challenges = nil
	case *nanoca.Challenge:
		r.URL = ""
	}
}

// referenceJSON renders a record in the reference encoding, normalized so
// that equal documents mean equivalent records: same instants, same bytes,
// same shape. It mutates v.
func referenceJSON(t *testing.T, v any) string {
	t.Helper()
	clearComposed(v)
	normalize(reflect.ValueOf(v))
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %T: %v", v, err)
	}
	return string(data)
}

func checkRoundTrip(t *testing.T, kind string, got, want any) {
	t.Helper()
	if g, w := referenceJSON(t, got), referenceJSON(t, want); g != w {
		t.Errorf("%s round-trip:\n got  %s\nwant %s", kind, g, w)
	}
}

func testGetMissing(t *testing.T, s nanoca.Storage) {
	ctx := t.Context()
	for name, get := range map[string]func() error{
		"GetAccount":      func() error { _, _, err := s.GetAccount(ctx, "ghost"); return err },
		"GetAccountByKey": func() error { _, _, err := s.GetAccountByKey(ctx, "ghost"); return err },
		"GetOrder":        func() error { _, _, err := s.GetOrder(ctx, "ghost"); return err },
		"GetAuthorization": func() error {
			_, _, err := s.GetAuthorization(ctx, "ghost")
			return err
		},
		"GetChallenge":   func() error { _, _, err := s.GetChallenge(ctx, "ghost"); return err },
		"GetCertificate": func() error { _, err := s.GetCertificate(ctx, "ghost"); return err },
		"TakeNonce":      func() error { _, err := s.TakeNonce(ctx, "ghost"); return err },
	} {
		if err := get(); !errors.Is(err, nanoca.ErrNotFound) {
			t.Errorf("%s(missing) error = %v, want ErrNotFound", name, err)
		}
	}
}

// A Put on a missing record reports ErrNotFound, or ErrConflict for a
// backend whose conditional write cannot tell the two apart.
func testPutMissing(t *testing.T, s nanoca.Storage) {
	ctx := t.Context()
	for name, put := range map[string]func() error{
		"PutAccount": func() error { return s.PutAccount(ctx, &nanoca.Account{ID: "ghost"}, "1") },
		"PutOrder":   func() error { return s.PutOrder(ctx, &nanoca.Order{ID: "ghost"}, "1") },
		"PutAuthorization": func() error {
			return s.PutAuthorization(ctx, &nanoca.Authorization{ID: "ghost"}, "1")
		},
		"PutChallenge": func() error { return s.PutChallenge(ctx, &nanoca.Challenge{ID: "ghost"}, "1") },
	} {
		if err := put(); !errors.Is(err, nanoca.ErrNotFound) && !errors.Is(err, nanoca.ErrConflict) {
			t.Errorf("%s(missing) error = %v, want ErrNotFound or ErrConflict", name, err)
		}
	}
}

// testJWK is the P-256 public key from RFC 7515 Appendix A.3.
const testJWK = `{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}`

func testRoundTrip(t *testing.T, s nanoca.Storage) {
	ctx := t.Context()
	// A fixed instant in a non-UTC zone at microsecond precision: a
	// backend may return times in any location as long as the moment
	// survives, to at least the microsecond.
	written := time.Date(2025, 6, 15, 8, 30, 15, 123456000, time.FixedZone("", 7*3600))
	ptr := func(ts time.Time) *time.Time { return &ts }

	key := &jose.JSONWebKey{}
	if err := json.Unmarshal([]byte(testJWK), key); err != nil {
		t.Fatalf("unmarshal test JWK: %v", err)
	}

	account := &nanoca.Account{
		ID:            "a1",
		Key:           key,
		KeyThumbprint: "thumb-1",
		Status:        "valid",
		Contact:       []string{"mailto:admin@example.com"},
		OrderIDs:      []string{"o1"},
		CreatedAt:     written,
	}
	if err := s.CreateAccount(ctx, account); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}
	gotAccount, _, err := s.GetAccount(ctx, "a1")
	if err != nil {
		t.Fatalf("GetAccount() error = %v", err)
	}
	checkRoundTrip(t, "account", gotAccount, account)

	order := &nanoca.Order{
		ID:               "o1",
		AccountID:        "a1",
		Status:           nanoca.OrderStatusProcessing,
		Identifiers:      []nanoca.Identifier{{Type: "permanent-identifier", Value: "serial-1"}},
		Expires:          ptr(written),
		AuthorizationIDs: []string{"z1"},
		CertificateID:    "cert1",
		Reservation:      &nanoca.Reservation{Token: "t1", ReservedAt: written},
		CreatedAt:        written,
	}
	authz := &nanoca.Authorization{
		ID:           "z1",
		Status:       nanoca.AuthzStatusPending,
		Identifier:   nanoca.Identifier{Type: "permanent-identifier", Value: "serial-1"},
		ChallengeIDs: []string{"c1"},
		AccountID:    "a1",
		OrderID:      "o1",
		Expires:      ptr(written),
		CreatedAt:    written,
	}
	challenge := &nanoca.Challenge{
		ID:          "c1",
		AuthzID:     "z1",
		Type:        "device-attest-01",
		Status:      nanoca.ChallengeStatusProcessing,
		Token:       "tok",
		Validated:   ptr(written),
		Error:       nanoca.Unauthorized("device not authorized"),
		Attestation: []byte{0xa3, 0x00, 0xff, 0x10},
		Reservation: &nanoca.Reservation{Token: "t2", ReservedAt: written},
		CreatedAt:   written,
	}
	if err := s.CreateOrder(ctx, order, []*nanoca.Authorization{authz}, []*nanoca.Challenge{challenge}); err != nil {
		t.Fatalf("CreateOrder() error = %v", err)
	}
	gotOrder, _, err := s.GetOrder(ctx, "o1")
	if err != nil {
		t.Fatalf("GetOrder() error = %v", err)
	}
	checkRoundTrip(t, "order", gotOrder, order)
	gotAuthz, _, err := s.GetAuthorization(ctx, "z1")
	if err != nil {
		t.Fatalf("GetAuthorization() error = %v", err)
	}
	checkRoundTrip(t, "authorization", gotAuthz, authz)
	gotChallenge, _, err := s.GetChallenge(ctx, "c1")
	if err != nil {
		t.Fatalf("GetChallenge() error = %v", err)
	}
	checkRoundTrip(t, "challenge", gotChallenge, challenge)

	cert := &nanoca.Certificate{
		ID:           "cert1",
		OrderID:      "o1",
		Raw:          []byte{0x30, 0x82, 0x01, 0x00},
		SerialNumber: "1234",
		ChainRaw:     [][]byte{{0x30, 0x81}, {0x30, 0x82}},
	}
	if err := s.CreateCertificate(ctx, cert); err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	gotCert, err := s.GetCertificate(ctx, "cert1")
	if err != nil {
		t.Fatalf("GetCertificate() error = %v", err)
	}
	checkRoundTrip(t, "certificate", gotCert, cert)
}

// Duplicate creates are detected by the write itself. The records here
// are deliberately bare: any record whose ID is set must be storable, so
// a schema that demands more fields fails here first.
func testCreateDuplicate(t *testing.T, s nanoca.Storage) {
	ctx := t.Context()

	if err := s.CreateAccount(ctx, &nanoca.Account{ID: "a1", KeyThumbprint: "thumb-1"}); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}
	if err := s.CreateAccount(ctx, &nanoca.Account{ID: "a1", KeyThumbprint: "thumb-other"}); !errors.Is(err, nanoca.ErrExists) {
		t.Errorf("CreateAccount(duplicate ID) error = %v, want ErrExists", err)
	}
	if err := s.CreateAccount(ctx, &nanoca.Account{ID: "a2", KeyThumbprint: "thumb-1"}); !errors.Is(err, nanoca.ErrExists) {
		t.Errorf("CreateAccount(duplicate thumbprint) error = %v, want ErrExists", err)
	}

	createOrder(t, s, &nanoca.Order{ID: "o1"})
	if err := s.CreateOrder(ctx, &nanoca.Order{ID: "o1"}, nil, nil); !errors.Is(err, nanoca.ErrExists) {
		t.Errorf("CreateOrder(duplicate) error = %v, want ErrExists", err)
	}

	if err := s.CreateNonce(ctx, &nanoca.Nonce{Value: "n1", CreatedAt: time.Now()}, time.Hour); err != nil {
		t.Fatalf("CreateNonce() error = %v", err)
	}
	if err := s.CreateNonce(ctx, &nanoca.Nonce{Value: "n1", CreatedAt: time.Now()}, time.Hour); !errors.Is(err, nanoca.ErrExists) {
		t.Errorf("CreateNonce(duplicate) error = %v, want ErrExists", err)
	}

	if err := s.CreateCertificate(ctx, &nanoca.Certificate{ID: "cert1"}); err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	if err := s.CreateCertificate(ctx, &nanoca.Certificate{ID: "cert1"}); !errors.Is(err, nanoca.ErrExists) {
		t.Errorf("CreateCertificate(duplicate) error = %v, want ErrExists", err)
	}
}

// Two concurrent registrations of one key must yield exactly one account
// and one ErrExists, detected by the write itself.
func testConcurrentCreateAccount(t *testing.T, s nanoca.Storage) {
	ctx := t.Context()
	const writers = 8

	errs := make([]error, writers)
	var wg sync.WaitGroup
	for i := range writers {
		wg.Go(func() {
			errs[i] = s.CreateAccount(ctx, &nanoca.Account{
				ID:            fmt.Sprintf("a%d", i),
				KeyThumbprint: "shared-thumb",
			})
		})
	}
	wg.Wait()

	var winners int
	for _, err := range errs {
		switch {
		case err == nil:
			winners++
		case !errors.Is(err, nanoca.ErrExists):
			t.Errorf("CreateAccount() error = %v, want nil or ErrExists", err)
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent CreateAccount winners = %d, want 1", winners)
	}

	if _, _, err := s.GetAccountByKey(ctx, "shared-thumb"); err != nil {
		t.Errorf("GetAccountByKey() after race error = %v", err)
	}
}

func testStaleRevision(t *testing.T, s nanoca.Storage) {
	ctx := t.Context()
	createOrder(t, s, &nanoca.Order{ID: "o1", Status: nanoca.OrderStatusPending})

	order, rev, err := s.GetOrder(ctx, "o1")
	if err != nil {
		t.Fatalf("GetOrder() error = %v", err)
	}

	order.Status = nanoca.OrderStatusReady
	if err := s.PutOrder(ctx, order, rev); err != nil {
		t.Fatalf("PutOrder() error = %v", err)
	}

	// The consumed revision never works again.
	if err := s.PutOrder(ctx, order, rev); !errors.Is(err, nanoca.ErrConflict) {
		t.Errorf("PutOrder(stale) error = %v, want ErrConflict", err)
	}

	// Nor after further writes (no ABA).
	for range 3 {
		fresh, freshRev, err := s.GetOrder(ctx, "o1")
		if err != nil {
			t.Fatalf("GetOrder() error = %v", err)
		}
		if err := s.PutOrder(ctx, fresh, freshRev); err != nil {
			t.Fatalf("PutOrder() error = %v", err)
		}
	}
	if err := s.PutOrder(ctx, order, rev); !errors.Is(err, nanoca.ErrConflict) {
		t.Errorf("PutOrder(stale after writes) error = %v, want ErrConflict", err)
	}
}

// A revision the backend cannot parse or never minted is a mismatch like
// any other: a Put against an existing record reports ErrConflict, not an
// internal error.
func testGarbageRevision(t *testing.T, s nanoca.Storage) {
	ctx := t.Context()
	if err := s.CreateAccount(ctx, &nanoca.Account{ID: "a1", KeyThumbprint: "thumb-1"}); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}
	order := &nanoca.Order{ID: "o1"}
	authz := &nanoca.Authorization{ID: "z1", OrderID: "o1"}
	challenge := &nanoca.Challenge{ID: "c1", AuthzID: "z1"}
	if err := s.CreateOrder(ctx, order, []*nanoca.Authorization{authz}, []*nanoca.Challenge{challenge}); err != nil {
		t.Fatalf("CreateOrder() error = %v", err)
	}

	for _, rev := range []nanoca.Revision{"", "not-a-number", "-1", "18446744073709551616", "999999999"} {
		for name, put := range map[string]func() error{
			"PutAccount": func() error { return s.PutAccount(ctx, &nanoca.Account{ID: "a1"}, rev) },
			"PutOrder":   func() error { return s.PutOrder(ctx, &nanoca.Order{ID: "o1"}, rev) },
			"PutAuthorization": func() error {
				return s.PutAuthorization(ctx, &nanoca.Authorization{ID: "z1"}, rev)
			},
			"PutChallenge": func() error { return s.PutChallenge(ctx, &nanoca.Challenge{ID: "c1"}, rev) },
		} {
			if err := put(); !errors.Is(err, nanoca.ErrConflict) {
				t.Errorf("%s(rev %q) error = %v, want ErrConflict", name, rev, err)
			}
		}
	}
}

// A rejected conditional write must leave the record unchanged.
func testRejectedPutWritesNothing(t *testing.T, s nanoca.Storage) {
	ctx := t.Context()
	createOrder(t, s, &nanoca.Order{ID: "o1", Status: nanoca.OrderStatusPending})

	order, rev, err := s.GetOrder(ctx, "o1")
	if err != nil {
		t.Fatalf("GetOrder() error = %v", err)
	}
	order.Status = nanoca.OrderStatusReady
	if err := s.PutOrder(ctx, order, rev); err != nil {
		t.Fatalf("PutOrder() error = %v", err)
	}

	before, beforeRev, err := s.GetOrder(ctx, "o1")
	if err != nil {
		t.Fatalf("GetOrder() error = %v", err)
	}

	rejected := *before
	rejected.Status = nanoca.OrderStatusInvalid
	if err := s.PutOrder(ctx, &rejected, rev); !errors.Is(err, nanoca.ErrConflict) {
		t.Fatalf("PutOrder(stale) error = %v, want ErrConflict", err)
	}

	after, afterRev, err := s.GetOrder(ctx, "o1")
	if err != nil {
		t.Fatalf("GetOrder() error = %v", err)
	}
	if g, w := referenceJSON(t, after), referenceJSON(t, before); g != w || afterRev != beforeRev {
		t.Errorf("rejected put changed the record:\n got  %s (rev %s)\nwant %s (rev %s)", g, afterRev, w, beforeRev)
	}
}

// Two writers holding the same revision race a Put: exactly one wins.
func testPairwiseCASRace(t *testing.T, s nanoca.Storage) {
	ctx := t.Context()
	createOrder(t, s, &nanoca.Order{ID: "o1", Status: nanoca.OrderStatusPending})

	order, rev, err := s.GetOrder(ctx, "o1")
	if err != nil {
		t.Fatalf("GetOrder() error = %v", err)
	}

	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Go(func() {
			o := *order
			o.Error = &nanoca.Problem{Detail: fmt.Sprintf("writer-%d", i)}
			errs[i] = s.PutOrder(ctx, &o, rev)
		})
	}
	wg.Wait()

	var wins, conflicts int
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, nanoca.ErrConflict):
			conflicts++
		default:
			t.Errorf("PutOrder() error = %v, want nil or ErrConflict", err)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Errorf("pairwise race: wins = %d, conflicts = %d, want 1 and 1", wins, conflicts)
	}
}

// N writers each apply M read-modify-put increments with retry; the final
// count is exact. A conditional write that is not actually conditional
// loses updates here.
func testLostUpdateStress(t *testing.T, s nanoca.Storage) {
	ctx := t.Context()
	const writers, increments = 8, 50

	if err := s.CreateAccount(ctx, &nanoca.Account{ID: "a1", Contact: []string{"0"}}); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}

	var wg sync.WaitGroup
	for range writers {
		wg.Go(func() {
			for range increments {
				for {
					account, rev, err := s.GetAccount(ctx, "a1")
					if err != nil {
						t.Errorf("GetAccount() error = %v", err)
						return
					}
					n, err := strconv.Atoi(account.Contact[0])
					if err != nil {
						t.Errorf("counter = %q: %v", account.Contact[0], err)
						return
					}
					account.Contact[0] = strconv.Itoa(n + 1)
					err = s.PutAccount(ctx, account, rev)
					if err == nil {
						break
					}
					if !errors.Is(err, nanoca.ErrConflict) {
						t.Errorf("PutAccount() error = %v, want ErrConflict", err)
						return
					}
				}
			}
		})
	}
	wg.Wait()

	account, _, err := s.GetAccount(ctx, "a1")
	if err != nil {
		t.Fatalf("GetAccount() error = %v", err)
	}
	if want := strconv.Itoa(writers * increments); account.Contact[0] != want {
		t.Errorf("final count = %s, want %s (updates were lost)", account.Contact[0], want)
	}
}

func testTakeNonce(t *testing.T, s nanoca.Storage) {
	ctx := t.Context()
	created := time.Date(2025, 6, 15, 8, 30, 15, 123456000, time.FixedZone("", 7*3600))
	if err := s.CreateNonce(ctx, &nanoca.Nonce{Value: "n1", CreatedAt: created}, time.Hour); err != nil {
		t.Fatalf("CreateNonce() error = %v", err)
	}

	nonce, err := s.TakeNonce(ctx, "n1")
	if err != nil {
		t.Fatalf("TakeNonce() error = %v", err)
	}
	if nonce.Value != "n1" || !nonce.CreatedAt.Equal(created) {
		t.Errorf("TakeNonce() = %+v, want value n1 created %v", nonce, created)
	}

	if _, err := s.TakeNonce(ctx, "n1"); !errors.Is(err, nanoca.ErrNotFound) {
		t.Errorf("TakeNonce(taken) error = %v, want ErrNotFound", err)
	}
}

// N concurrent takes of one nonce: exactly one wins.
func testConcurrentTakeNonce(t *testing.T, s nanoca.Storage) {
	ctx := t.Context()
	const takers = 8

	if err := s.CreateNonce(ctx, &nanoca.Nonce{Value: "n1", CreatedAt: time.Now()}, time.Hour); err != nil {
		t.Fatalf("CreateNonce() error = %v", err)
	}

	errs := make([]error, takers)
	var wg sync.WaitGroup
	for i := range takers {
		wg.Go(func() {
			_, errs[i] = s.TakeNonce(ctx, "n1")
		})
	}
	wg.Wait()

	var winners int
	for _, err := range errs {
		switch {
		case err == nil:
			winners++
		case !errors.Is(err, nanoca.ErrNotFound):
			t.Errorf("TakeNonce() error = %v, want nil or ErrNotFound", err)
		}
	}
	if winners != 1 {
		t.Errorf("concurrent TakeNonce winners = %d, want 1", winners)
	}
}

func testAccountByKey(t *testing.T, s nanoca.Storage) {
	ctx := t.Context()

	if err := s.CreateAccount(ctx, &nanoca.Account{ID: "a1", KeyThumbprint: "thumb-1", Status: "valid"}); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}
	account, rev, err := s.GetAccountByKey(ctx, "thumb-1")
	if err != nil {
		t.Fatalf("GetAccountByKey() error = %v", err)
	}
	if account.ID != "a1" {
		t.Errorf("GetAccountByKey() ID = %s, want a1", account.ID)
	}

	// The index holds across a Put.
	account.Status = "deactivated"
	if err := s.PutAccount(ctx, account, rev); err != nil {
		t.Fatalf("PutAccount() error = %v", err)
	}
	account, _, err = s.GetAccountByKey(ctx, "thumb-1")
	if err != nil {
		t.Fatalf("GetAccountByKey() after put error = %v", err)
	}
	if account.Status != "deactivated" {
		t.Errorf("GetAccountByKey() status = %s, want deactivated", account.Status)
	}
}

func testCreateOrderTree(t *testing.T, s nanoca.Storage) {
	ctx := t.Context()

	order := &nanoca.Order{ID: "o1", AccountID: "a1", Status: nanoca.OrderStatusPending}
	authz := &nanoca.Authorization{ID: "z1", OrderID: "o1", Status: nanoca.AuthzStatusPending, ChallengeIDs: []string{"c1"}}
	challenge := &nanoca.Challenge{ID: "c1", AuthzID: "z1", Status: nanoca.ChallengeStatusPending}

	if err := s.CreateOrder(ctx, order, []*nanoca.Authorization{authz}, []*nanoca.Challenge{challenge}); err != nil {
		t.Fatalf("CreateOrder() error = %v", err)
	}

	if _, _, err := s.GetOrder(ctx, "o1"); err != nil {
		t.Errorf("GetOrder() error = %v", err)
	}
	if _, _, err := s.GetAuthorization(ctx, "z1"); err != nil {
		t.Errorf("GetAuthorization() error = %v", err)
	}
	if _, _, err := s.GetChallenge(ctx, "c1"); err != nil {
		t.Errorf("GetChallenge() error = %v", err)
	}
}

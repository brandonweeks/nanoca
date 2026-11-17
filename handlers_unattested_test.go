package nanoca_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"log/slog"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brandonweeks/nanoca"
	"github.com/brandonweeks/nanoca/certutil"
	"golang.org/x/crypto/acme"
)

// unattestedGate admits the identifier values in allow and records every
// request.
type unattestedGate struct {
	mu    sync.Mutex
	allow map[string]bool
	err   error
	calls []nanoca.UnattestedRequest
}

func (g *unattestedGate) AuthorizeUnattested(_ context.Context, req nanoca.UnattestedRequest) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls = append(g.calls, req)
	if g.err != nil {
		return false, g.err
	}
	return g.allow[req.Identifier.Value], nil
}

func (g *unattestedGate) set(allow map[string]bool, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.allow, g.err = allow, err
}

func (g *unattestedGate) recorded() []nanoca.UnattestedRequest {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]nanoca.UnattestedRequest(nil), g.calls...)
}

func newUnattestedServer(t *testing.T, gate nanoca.UnattestedAuthorizer, cfg testServerConfig) *acme.Client {
	t.Helper()
	cfg.opts = append(cfg.opts, nanoca.WithUnattestedAuthorizer(gate))
	ts, _ := newTestServer(t, cfg)
	return newACMEClient(t, ts)
}

// unattestedChallenge creates an order for one permanent-identifier and
// returns its device-attest-01 challenge.
func unattestedChallenge(t *testing.T, client *acme.Client, value string) (*acme.Order, *acme.Challenge) {
	t.Helper()
	order, err := client.AuthorizeOrder(t.Context(), []acme.AuthzID{{Type: "permanent-identifier", Value: value}})
	if err != nil {
		t.Fatalf("failed to create order: %v", err)
	}
	authz, err := client.GetAuthorization(t.Context(), order.AuthzURLs[0])
	if err != nil {
		t.Fatalf("failed to get authorization: %v", err)
	}
	return order, authz.Challenges[0]
}

// submitEmpty answers the challenge as Apple's ACME client does with Attest
// false: an empty JSON object.
func submitEmpty(t *testing.T, client *acme.Client, chal *acme.Challenge) error {
	t.Helper()
	chal.Payload = []byte("{}")
	_, err := client.Accept(t.Context(), chal)
	return err
}

func challengeStatus(t *testing.T, client *acme.Client, chal *acme.Challenge) string {
	t.Helper()
	got, err := client.GetChallenge(t.Context(), chal.URI)
	if err != nil {
		t.Fatalf("GetChallenge() error = %v", err)
	}
	return got.Status
}

func TestUnattestedGateYesValidates(t *testing.T) {
	t.Parallel()
	gate := &unattestedGate{allow: map[string]bool{"vm-token-1": true}}
	client := newUnattestedServer(t, gate, testServerConfig{})

	order, chal := unattestedChallenge(t, client, "vm-token-1")
	if err := submitEmpty(t, client, chal); err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	if got := challengeStatus(t, client, chal); got != acme.StatusValid {
		t.Errorf("challenge status = %q, want %q", got, acme.StatusValid)
	}
	authz, err := client.GetAuthorization(t.Context(), order.AuthzURLs[0])
	if err != nil {
		t.Fatalf("GetAuthorization() error = %v", err)
	}
	if authz.Status != acme.StatusValid {
		t.Errorf("authorization status = %q, want %q", authz.Status, acme.StatusValid)
	}

	calls := gate.recorded()
	if len(calls) != 1 {
		t.Fatalf("gate called %d times, want 1", len(calls))
	}
	want := nanoca.UnattestedRequest{
		Identifier:  nanoca.Identifier{Type: "permanent-identifier", Value: "vm-token-1"},
		AccountID:   calls[0].AccountID,
		OrderID:     path.Base(order.URI),
		ChallengeID: path.Base(chal.URI),
	}
	if calls[0] != want || calls[0].AccountID == "" {
		t.Errorf("gate request = %+v, want %+v with an account", calls[0], want)
	}
}

func TestUnattestedGateNoInvalidates(t *testing.T) {
	t.Parallel()
	client := newUnattestedServer(t, &unattestedGate{}, testServerConfig{})

	_, chal := unattestedChallenge(t, client, "vm-token-1")
	if err := submitEmpty(t, client, chal); err == nil {
		t.Fatal("Accept() succeeded for a refused device")
	}
	if got := challengeStatus(t, client, chal); got != acme.StatusInvalid {
		t.Errorf("challenge status = %q, want %q", got, acme.StatusInvalid)
	}
}

func TestUnattestedGateErrorLeavesPending(t *testing.T) {
	t.Parallel()
	gate := &unattestedGate{err: errors.New("backend down")}
	client := newUnattestedServer(t, gate, testServerConfig{})

	_, chal := unattestedChallenge(t, client, "vm-token-1")
	if err := submitEmpty(t, client, chal); err == nil {
		t.Fatal("Accept() succeeded while the gate failed")
	}
	if got := challengeStatus(t, client, chal); got != acme.StatusPending {
		t.Fatalf("challenge status = %q, want %q", got, acme.StatusPending)
	}

	gate.set(map[string]bool{"vm-token-1": true}, nil)
	if err := submitEmpty(t, client, chal); err != nil {
		t.Fatalf("retry Accept() error = %v", err)
	}
	if got := challengeStatus(t, client, chal); got != acme.StatusValid {
		t.Errorf("challenge status after retry = %q, want %q", got, acme.StatusValid)
	}
}

// A gate error is a backend condition even when it is a *Problem.
func TestUnattestedGateProblemErrorLeavesPending(t *testing.T) {
	t.Parallel()
	gate := &unattestedGate{err: nanoca.Unauthorized("backend refused the lookup")}
	client := newUnattestedServer(t, gate, testServerConfig{})

	_, chal := unattestedChallenge(t, client, "vm-token-1")
	if err := submitEmpty(t, client, chal); err == nil {
		t.Fatal("Accept() succeeded while the gate failed")
	}
	if got := challengeStatus(t, client, chal); got != acme.StatusPending {
		t.Fatalf("challenge status = %q, want %q", got, acme.StatusPending)
	}
}

func TestUnattestedWithoutGateKeepsUpstreamError(t *testing.T) {
	t.Parallel()
	ts, _ := newTestServer(t, testServerConfig{})
	client := newACMEClient(t, ts)

	_, chal := unattestedChallenge(t, client, "vm-token-1")
	err := submitEmpty(t, client, chal)
	var acmeErr *acme.Error
	if !errors.As(err, &acmeErr) || !strings.HasSuffix(acmeErr.ProblemType, ":malformed") {
		t.Fatalf("Accept() error = %v, want a malformed problem", err)
	}
}

func TestAttestedAnswerIgnoresGate(t *testing.T) {
	t.Parallel()
	gate := &unattestedGate{}
	client := newUnattestedServer(t, gate, testServerConfig{})

	_, chal := pendingChallenge(t, client)
	if err := submitAttObj(t, client, chal, nullAttObj(t)); err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	if calls := gate.recorded(); len(calls) != 0 {
		t.Errorf("gate called %d times for an attested answer", len(calls))
	}
}

func TestUnattestedRepostReturnsValid(t *testing.T) {
	t.Parallel()
	gate := &unattestedGate{allow: map[string]bool{"vm-token-1": true}}
	client := newUnattestedServer(t, gate, testServerConfig{})

	_, chal := unattestedChallenge(t, client, "vm-token-1")
	if err := submitEmpty(t, client, chal); err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	if err := submitEmpty(t, client, chal); err != nil {
		t.Fatalf("second Accept() error = %v", err)
	}
	if got := challengeStatus(t, client, chal); got != acme.StatusValid {
		t.Errorf("challenge status = %q, want %q", got, acme.StatusValid)
	}
	if calls := gate.recorded(); len(calls) != 1 {
		t.Errorf("gate called %d times, want 1", len(calls))
	}
}

// parkingGate parks its first call until released, so its reservation lapses
// and a retry reclaims the challenge.
type parkingGate struct {
	unattestedGate
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (g *parkingGate) AuthorizeUnattested(ctx context.Context, req nanoca.UnattestedRequest) (bool, error) {
	first := false
	g.once.Do(func() { first = true })
	if first {
		close(g.entered)
		<-g.release
	}
	return g.unattestedGate.AuthorizeUnattested(ctx, req)
}

func TestUnattestedReclaimedAfterLapsedLease(t *testing.T) {
	t.Parallel()
	gate := &parkingGate{
		unattestedGate: unattestedGate{allow: map[string]bool{"vm-token-1": true}},
		entered:        make(chan struct{}),
		release:        make(chan struct{}),
	}
	client := newUnattestedServer(t, gate, testServerConfig{opts: []nanoca.Option{nanoca.WithReservationLease(testReservationLease)}})

	_, chal := unattestedChallenge(t, client, "vm-token-1")
	zombie := *chal
	zombieDone := make(chan struct{})
	go func() {
		defer close(zombieDone)
		_ = submitEmpty(t, client, &zombie)
	}()
	<-gate.entered

	time.Sleep(2 * testReservationLease)
	if err := submitEmpty(t, client, chal); err != nil {
		t.Fatalf("reclaiming Accept() error = %v", err)
	}
	close(gate.release)
	<-zombieDone

	if got := challengeStatus(t, client, chal); got != acme.StatusValid {
		t.Errorf("challenge status = %q, want %q", got, acme.StatusValid)
	}
	calls := gate.recorded()
	if len(calls) != 2 || calls[0].ChallengeID != calls[1].ChallengeID {
		t.Errorf("gate calls = %+v, want two for the same challenge", calls)
	}
}

func TestUnattestedMarkerNotOnWire(t *testing.T) {
	t.Parallel()
	gate := &unattestedGate{allow: map[string]bool{"vm-token-1": true}}
	ts, _ := newTestServer(t, testServerConfig{opts: []nanoca.Option{nanoca.WithUnattestedAuthorizer(gate)}})
	client := newACMEClient(t, ts)

	order, chal := unattestedChallenge(t, client, "vm-token-1")
	if err := submitEmpty(t, client, chal); err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	for _, u := range []string{chal.URI, order.AuthzURLs[0]} {
		status, body := signedPostAsGet(t, ts, client.Key.(*ecdsa.PrivateKey), string(client.KID), u)
		if status != 200 {
			t.Fatalf("fetch %s status = %d", u, status)
		}
		if bytes.Contains(body, []byte("unattested")) {
			t.Errorf("%s on the wire carries the stored marker: %s", u, body)
		}
	}
}

// liarVerifier accepts any statement and claims the device is unattested,
// which only nanoca may say.
type liarVerifier struct{}

func (liarVerifier) Format() string { return "liar" }

func (liarVerifier) Verify(context.Context, nanoca.AttestationStatement, []byte) (*nanoca.DeviceInfo, error) {
	return &nanoca.DeviceInfo{PublicKey: testDeviceKey.Public(), Unattested: true}, nil
}

func TestVerifierCannotClaimUnattested(t *testing.T) {
	t.Parallel()
	client := newUnattestedServer(t, &unattestedGate{}, testServerConfig{verifiers: []nanoca.AttestationVerifier{liarVerifier{}}})

	_, chal := pendingChallenge(t, client)
	if err := submitAttObj(t, client, chal, attObjFor(t, "liar")); err == nil {
		t.Fatal("Accept() succeeded for a verifier claiming an unattested device")
	}
	if got := challengeStatus(t, client, chal); got != acme.StatusInvalid {
		t.Errorf("challenge status = %q, want %q", got, acme.StatusInvalid)
	}
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestUnattestedLogsNoIdentifier(t *testing.T) {
	t.Parallel()
	logs := &lockedBuffer{}
	logger := slog.New(nanoca.NewContextHandler(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	gate := &unattestedGate{allow: map[string]bool{"secret-yes": true}}
	client := newUnattestedServer(t, gate, testServerConfig{logger: logger})

	_, yes := unattestedChallenge(t, client, "secret-yes")
	if err := submitEmpty(t, client, yes); err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	_, no := unattestedChallenge(t, client, "secret-no")
	_ = submitEmpty(t, client, no)
	gate.set(nil, errors.New("backend down"))
	_, failed := unattestedChallenge(t, client, "secret-err")
	_ = submitEmpty(t, client, failed)

	for _, v := range []string{"secret-yes", "secret-no", "secret-err"} {
		if strings.Contains(logs.String(), v) {
			t.Errorf("logs contain identifier %q", v)
		}
	}
}

// recordingAuthorizer admits every attested device and records whether it was
// asked.
type recordingAuthorizer struct {
	mu     sync.Mutex
	called bool
}

func (a *recordingAuthorizer) Authorize(context.Context, *nanoca.DeviceInfo) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.called = true
	return true, nil
}

func finalize(t *testing.T, client *acme.Client, order *acme.Order, key crypto.Signer) (*x509.Certificate, error) {
	t.Helper()
	ders, _, err := client.CreateOrderCert(t.Context(), order.FinalizeURL, csrFor(t, key), true)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(ders[0])
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	return leaf, nil
}

func isProblem(err error, suffix string) bool {
	var acmeErr *acme.Error
	return errors.As(err, &acmeErr) && strings.HasSuffix(acmeErr.ProblemType, suffix)
}

func TestUnattestedOrderIssues(t *testing.T) {
	t.Parallel()
	attested := &recordingAuthorizer{}
	gate := &unattestedGate{allow: map[string]bool{"vm-token-1": true}}
	client := newUnattestedServer(t, gate, testServerConfig{authorizer: attested})

	order, chal := unattestedChallenge(t, client, "vm-token-1")
	if err := submitEmpty(t, client, chal); err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := finalize(t, client, order, key)
	if err != nil {
		t.Fatalf("finalize error = %v", err)
	}
	if !key.PublicKey.Equal(leaf.PublicKey) {
		t.Error("certificate does not certify the CSR key")
	}
	if certutil.FindExtension(leaf, certutil.OIDSubjectAltName) != nil {
		t.Error("certificate names a device nothing attested")
	}
	if attested.called {
		t.Error("Authorizer consulted for an unattested device")
	}
}

func TestUnattestedKeyFloor(t *testing.T) {
	t.Parallel()
	ecKey := func(c elliptic.Curve) crypto.Signer {
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	rsaKey := func(bits int) crypto.Signer {
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	tests := []struct {
		name string
		key  crypto.Signer
		ok   bool
	}{
		{"P-256", ecKey(elliptic.P256()), true},
		{"P-384", ecKey(elliptic.P384()), true},
		{"P-521", ecKey(elliptic.P521()), true},
		{"RSA-2048", rsaKey(2048), true},
		{"P-224", ecKey(elliptic.P224()), false},
		{"RSA-1024", rsaKey(1024), false},
	}
	allow := map[string]bool{}
	for _, tt := range tests {
		allow[tt.name] = true
	}
	client := newUnattestedServer(t, &unattestedGate{allow: allow}, testServerConfig{})

	for _, tt := range tests {
		order, chal := unattestedChallenge(t, client, tt.name)
		if err := submitEmpty(t, client, chal); err != nil {
			t.Fatalf("%s: Accept() error = %v", tt.name, err)
		}
		_, err := finalize(t, client, order, tt.key)
		if tt.ok {
			if err != nil {
				t.Errorf("%s: finalize error = %v, want issued", tt.name, err)
			}
			continue
		}
		if !isProblem(err, ":badCSR") {
			t.Errorf("%s: finalize error = %v, want badCSR", tt.name, err)
		}
		got, err := client.GetOrder(t.Context(), order.URI)
		if err != nil || got.Status != acme.StatusReady {
			t.Errorf("%s: order after refused CSR = %+v, %v; want ready", tt.name, got, err)
		}
	}
}

func TestUnattestedTwoIdentifiersIssueOnce(t *testing.T) {
	t.Parallel()
	client := newUnattestedServer(t, &unattestedGate{allow: map[string]bool{"vm-a": true, "vm-b": true}}, testServerConfig{})

	order, err := client.AuthorizeOrder(t.Context(), []acme.AuthzID{{Type: "permanent-identifier", Value: "vm-a"}, {Type: "permanent-identifier", Value: "vm-b"}})
	if err != nil {
		t.Fatalf("AuthorizeOrder() error = %v", err)
	}
	for _, u := range order.AuthzURLs {
		authz, err := client.GetAuthorization(t.Context(), u)
		if err != nil {
			t.Fatalf("GetAuthorization() error = %v", err)
		}
		if err := submitEmpty(t, client, authz.Challenges[0]); err != nil {
			t.Fatalf("Accept() error = %v", err)
		}
	}
	if _, err := finalize(t, client, order, testDeviceKey); err != nil {
		t.Fatalf("finalize error = %v", err)
	}
}

func TestMixedOrderRejected(t *testing.T) {
	t.Parallel()
	client := newUnattestedServer(t, &unattestedGate{allow: map[string]bool{"vm-token-1": true}}, testServerConfig{})

	order, err := client.AuthorizeOrder(t.Context(), []acme.AuthzID{{Type: "permanent-identifier", Value: testDeviceSerial}, {Type: "permanent-identifier", Value: "vm-token-1"}})
	if err != nil {
		t.Fatalf("AuthorizeOrder() error = %v", err)
	}
	for i, u := range order.AuthzURLs {
		authz, err := client.GetAuthorization(t.Context(), u)
		if err != nil {
			t.Fatalf("GetAuthorization() error = %v", err)
		}
		if i == 0 {
			err = submitAttObj(t, client, authz.Challenges[0], nullAttObj(t))
		} else {
			err = submitEmpty(t, client, authz.Challenges[0])
		}
		if err != nil {
			t.Fatalf("Accept(%s) error = %v", authz.Identifier.Value, err)
		}
	}

	if _, err := finalize(t, client, order, testDeviceKey); !isProblem(err, ":unauthorized") {
		t.Fatalf("finalize of a mixed order: error = %v, want unauthorized", err)
	}
	got, err := client.GetOrder(t.Context(), order.URI)
	if err != nil || got.Status != acme.StatusInvalid {
		t.Errorf("mixed order after finalize = %+v, %v; want invalid", got, err)
	}
}

func TestUnattestedHardwareModuleStaysMalformed(t *testing.T) {
	t.Parallel()
	const hm = "ABCD/1.2.3.4"
	gate := &unattestedGate{allow: map[string]bool{hm: true}}
	client := newUnattestedServer(t, gate, testServerConfig{})

	order, err := client.AuthorizeOrder(t.Context(), []acme.AuthzID{{Type: "hardware-module", Value: hm}})
	if err != nil {
		t.Fatalf("AuthorizeOrder() error = %v", err)
	}
	authz, err := client.GetAuthorization(t.Context(), order.AuthzURLs[0])
	if err != nil {
		t.Fatalf("GetAuthorization() error = %v", err)
	}
	if err := submitEmpty(t, client, authz.Challenges[0]); !isProblem(err, ":malformed") {
		t.Fatalf("Accept() error = %v, want malformed", err)
	}
	if calls := gate.recorded(); len(calls) != 0 {
		t.Errorf("gate called %d times for a hardware-module identifier", len(calls))
	}
}

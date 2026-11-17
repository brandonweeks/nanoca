package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/brandonweeks/nanoca"
)

func request(value, challengeID string) nanoca.UnattestedRequest {
	return nanoca.UnattestedRequest{Identifier: nanoca.Identifier{Type: "permanent-identifier", Value: value}, ChallengeID: challengeID}
}

func authorize(t *testing.T, g *TokenGate, req nanoca.UnattestedRequest) bool {
	t.Helper()
	ok, err := g.AuthorizeUnattested(t.Context(), req)
	if err != nil {
		t.Fatalf("AuthorizeUnattested() error = %v", err)
	}
	return ok
}

func newGate(t *testing.T) (*TokenGate, string) {
	t.Helper()
	g := NewTokenGate(t.TempDir(), 7*24*time.Hour)
	tok, err := g.Mint()
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	return g, tok
}

func TestTokenGateOncePerChallenge(t *testing.T) {
	t.Parallel()
	g, tok := newGate(t)
	if !authorize(t, g, request(tok, "c1")) {
		t.Fatal("fresh token refused")
	}
	if !authorize(t, g, request(tok, "c1")) {
		t.Error("retry for the challenge that used the token refused")
	}
	if authorize(t, g, request(tok, "c2")) {
		t.Error("used token admitted another challenge")
	}
}

func TestTokenGateRefusesUnknownAndMalformed(t *testing.T) {
	t.Parallel()
	g, _ := newGate(t)
	before, _ := os.ReadDir(g.dir)
	for _, v := range []string{strings.Repeat("a", 32), "../x", "ABC", "", strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("A", 32)} {
		if authorize(t, g, request(v, "c1")) {
			t.Errorf("admitted %q", v)
		}
	}
	after, _ := os.ReadDir(g.dir)
	if len(after) != len(before) {
		t.Errorf("directory changed from %d to %d entries", len(before), len(after))
	}
}

func TestTokenGateRefusesOtherIdentifierTypes(t *testing.T) {
	t.Parallel()
	g, tok := newGate(t)
	req := request(tok, "c1")
	req.Identifier.Type = "hardware-module"
	if authorize(t, g, req) {
		t.Fatal("hardware-module identifier admitted")
	}
	if !authorize(t, g, request(tok, "c1")) {
		t.Error("token was used up by a refused request")
	}
}

func TestTokenGateRefusesExpired(t *testing.T) {
	t.Parallel()
	g, tok := newGate(t)
	old := time.Now().Add(-8 * 24 * time.Hour)
	if err := os.Chtimes(filepath.Join(g.dir, tok), old, old); err != nil {
		t.Fatal(err)
	}
	if authorize(t, g, request(tok, "c1")) {
		t.Error("expired token admitted")
	}
}

func TestTokenGateRaceAdmitsOne(t *testing.T) {
	t.Parallel()
	g, tok := newGate(t)
	var wg sync.WaitGroup
	var admitted atomic.Int32
	for i := range 16 {
		wg.Go(func() {
			if ok, err := g.AuthorizeUnattested(t.Context(), request(tok, strconv.Itoa(i))); err == nil && ok {
				admitted.Add(1)
			}
		})
	}
	wg.Wait()
	if n := admitted.Load(); n != 1 {
		t.Errorf("%d challenges admitted, want 1", n)
	}
}

func TestTokenGateErrorsOmitToken(t *testing.T) {
	t.Parallel()
	g, tok := newGate(t)
	// A file where used/ belongs makes reading used/<token> fail with an
	// error that names the path.
	if err := os.WriteFile(filepath.Join(g.dir, "used"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := g.AuthorizeUnattested(t.Context(), request(tok, "c1"))
	if err == nil {
		t.Fatal("AuthorizeUnattested() succeeded with a broken store")
	}
	if strings.Contains(err.Error(), tok) {
		t.Errorf("error %q contains the token, and nanoca logs gate errors", err)
	}
}

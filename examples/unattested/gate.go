package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/brandonweeks/nanoca"
)

// tokenRE is the only accepted shape, checked before the value reaches the
// filesystem as a file name.
var tokenRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// TokenGate is a one-time-token nanoca.UnattestedAuthorizer over a directory.
// Each token is a file in dir, goes in one ACME payload's ClientIdentifier,
// and admits one challenge. Once used it is recorded in dir/used with the
// challenge that used it, so a retry for that challenge is still admitted.
type TokenGate struct {
	dir    string
	maxAge time.Duration
}

// NewTokenGate returns a gate over dir whose tokens expire maxAge after they
// are minted.
func NewTokenGate(dir string, maxAge time.Duration) *TokenGate {
	return &TokenGate{dir: dir, maxAge: maxAge}
}

// Mint creates a new token and returns it.
func (g *TokenGate) Mint() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b)
	if err := os.MkdirAll(g.dir, 0o700); err != nil {
		return "", err
	}
	f, err := os.OpenFile(filepath.Join(g.dir, tok), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	return tok, f.Close()
}

// AuthorizeUnattested admits a fresh token once, by linking a record of the
// challenge into dir/used, which fails if another challenge got there first.
func (g *TokenGate) AuthorizeUnattested(_ context.Context, req nanoca.UnattestedRequest) (bool, error) {
	ok, err := g.authorize(req)
	return ok, withoutPath(err)
}

func (g *TokenGate) authorize(req nanoca.UnattestedRequest) (bool, error) {
	tok := req.Identifier.Value
	if req.Identifier.Type != nanoca.IdentifierTypePermanentIdentifier || !tokenRE.MatchString(tok) {
		return false, nil
	}
	usedDir := filepath.Join(g.dir, "used")
	used := filepath.Join(usedDir, tok)
	if ok, err := usedBy(used, req.ChallengeID); !errors.Is(err, fs.ErrNotExist) {
		return ok, err
	}

	st, err := os.Stat(filepath.Join(g.dir, tok))
	if errors.Is(err, fs.ErrNotExist) {
		// A concurrent call may have claimed it for this same challenge since
		// the check above.
		ok, err := usedBy(used, req.ChallengeID)
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return ok, err
	}
	if err != nil {
		return false, err
	}
	if time.Since(st.ModTime()) > g.maxAge {
		return false, nil
	}

	if err := os.MkdirAll(usedDir, 0o700); err != nil {
		return false, err
	}
	claim, err := os.CreateTemp(usedDir, ".claim-*")
	if err != nil {
		return false, err
	}
	defer func() { _ = os.Remove(claim.Name()) }()
	_, err = claim.WriteString(req.ChallengeID)
	if closeErr := claim.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return false, err
	}
	if err := os.Link(claim.Name(), used); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return usedBy(used, req.ChallengeID)
		}
		return false, err
	}
	_ = os.Remove(filepath.Join(g.dir, tok))
	return true, nil
}

// usedBy reports whether the used-token record at path names challengeID.
func usedBy(path, challengeID string) (bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	return string(b) == challengeID, nil
}

// withoutPath drops the path from a filesystem error, since the path holds
// the token and nanoca logs gate errors.
func withoutPath(err error) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return fmt.Errorf("token store: %s: %w", pathErr.Op, pathErr.Err)
	}
	var linkErr *os.LinkError
	if errors.As(err, &linkErr) {
		return fmt.Errorf("token store: %s: %w", linkErr.Op, linkErr.Err)
	}
	return err
}

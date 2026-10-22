package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/brandonweeks/nanoca"
	nullauthorizer "github.com/brandonweeks/nanoca/authorizers/null"
	"github.com/brandonweeks/nanoca/issuers/inprocess"
	stderrobserver "github.com/brandonweeks/nanoca/observers/stderr"
	filesigner "github.com/brandonweeks/nanoca/signers/file"
	"github.com/brandonweeks/nanoca/storage/badger"
	"github.com/brandonweeks/nanoca/verifiers/apple"
	tpmverifier "github.com/brandonweeks/nanoca/verifiers/tpm"
)

// akCARootPath holds the attestation CA root whose AK certificates the TPM
// verifier accepts. The TPM format is registered only when the file is there.
const akCARootPath = "ak_ca.crt"

func main() {
	logger := slog.New(nanoca.NewContextHandler(slog.Default().Handler()))

	if err := run(logger); err != nil {
		logger.Error("Server failed", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	caCert, err := loadCertificate("rootCA.crt")
	if err != nil {
		return fmt.Errorf("loading CA certificate: %w", err)
	}

	caSigner, err := filesigner.LoadSigner("rootCA.key")
	if err != nil {
		return fmt.Errorf("loading CA signer: %w", err)
	}

	certificateIssuer, err := inprocess.New(caSigner, caCert)
	if err != nil {
		return fmt.Errorf("creating certificate issuer: %w", err)
	}

	storage, err := badger.New(badger.Options{InMemory: true})
	if err != nil {
		return fmt.Errorf("creating storage: %w", err)
	}

	opts := []nanoca.Option{
		nanoca.WithObserver(stderrobserver.New(logger)),
		nanoca.WithVerifier(apple.New(logger)),
	}
	if verifier, err := tpmVerifier(logger); err != nil {
		return err
	} else if verifier != nil {
		opts = append(opts, nanoca.WithVerifier(verifier))
		logger.Info("Registered the TPM attestation format", "ak_ca_root", akCARootPath)
	}

	ca, err := nanoca.New(
		logger,
		certificateIssuer,
		nullauthorizer.New(),
		storage,
		"https://localhost:8443",
		opts...,
	)
	if err != nil {
		return fmt.Errorf("creating CA: %w", err)
	}
	defer ca.Close()

	logger.Info("Starting server on :8443")
	logger.Info("ACME directory: https://localhost:8443/directory")

	//nolint:gosec
	return http.ListenAndServeTLS(":8443", "server.crt", "server.key", ca.Handler())
}

// tpmVerifier builds the TPM verifier from the attestation CA root, or
// returns nil when there is no root to trust.
func tpmVerifier(logger *slog.Logger) (nanoca.AttestationVerifier, error) {
	root, err := loadCertificate(akCARootPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("loading AK CA root: %w", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)
	verifier, err := tpmverifier.New(logger, roots)
	if err != nil {
		return nil, fmt.Errorf("creating TPM verifier: %w", err)
	}
	return verifier, nil
}

func loadCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	return x509.ParseCertificate(block.Bytes)
}

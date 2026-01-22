package main

import (
	"crypto/x509"
	"encoding/pem"
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
)

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

	certificateIssuer := inprocess.New(caCert, caSigner)

	storage, err := badger.New(badger.Options{InMemory: true})
	if err != nil {
		return fmt.Errorf("creating storage: %w", err)
	}

	ca, err := nanoca.New(
		logger,
		certificateIssuer,
		nullauthorizer.New(),
		storage,
		"https://localhost:8443",
		nanoca.WithObserver(stderrobserver.New(logger)),
		nanoca.WithVerifier(apple.New(logger)),
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

package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/brandonweeks/nanoca"
	nullauthorizer "github.com/brandonweeks/nanoca/authorizers/null"
	"github.com/brandonweeks/nanoca/issuers/inprocess"
	filesigner "github.com/brandonweeks/nanoca/signers/file"
	"github.com/brandonweeks/nanoca/storage/badger"
	"github.com/brandonweeks/nanoca/verifiers/apple"
	"github.com/micromdm/nanolib/log/stdlogfmt"
	"github.com/micromdm/nanomdm/http/mdm"
	"github.com/micromdm/nanomdm/service/nanomdm"
	file_storage "github.com/micromdm/nanomdm/storage/file"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	var (
		listen  = flag.String("listen", ":8443", "listen address")
		caCertF = flag.String("ca-cert", "rootCA.crt", "CA certificate")
		caKey   = flag.String("ca-key", "rootCA.key", "CA private key")
		cert    = flag.String("cert", "server.crt", "server certificate")
		key     = flag.String("key", "server.key", "server private key")
		baseURL = flag.String("base-url", "https://localhost:8443", "base URL")
	)
	flag.Parse()

	logger := slog.New(nanoca.NewContextHandler(slog.Default().Handler()))

	caCert, err := loadCertificate(*caCertF)
	if err != nil {
		return fmt.Errorf("loading CA certificate: %w", err)
	}

	signer, err := filesigner.LoadSigner(*caKey)
	if err != nil {
		return err
	}

	acmeStorage, err := badger.New(badger.Options{InMemory: true})
	if err != nil {
		return err
	}

	ca, err := nanoca.New(
		logger,
		inprocess.New(caCert, signer),
		nullauthorizer.New(),
		acmeStorage,
		*baseURL,
		nanoca.WithPrefix("/acme"),
		nanoca.WithVerifier(apple.New(logger)),
	)
	if err != nil {
		return err
	}
	defer ca.Close()

	mdmStorage, err := file_storage.New("./mdm_storage")
	if err != nil {
		return err
	}

	mdmLogger := stdlogfmt.New(stdlogfmt.WithLogger(log.Default()))
	mdmService := nanomdm.New(mdmStorage)
	mdmHandler := mdm.CheckinAndCommandHandler(mdmService, mdmLogger)

	mux := http.NewServeMux()
	mux.Handle("/", ca.Handler())
	mux.Handle("/mdm", mdm.CertExtractTLSMiddleware(mdmHandler, mdmLogger))

	log.Printf("Starting server on %s", *listen)
	log.Printf("ACME: %s/acme/directory", *baseURL)
	log.Printf("MDM: %s/mdm", *baseURL)

	//nolint:gosec
	return http.ListenAndServeTLS(*listen, *cert, *key, mux)
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

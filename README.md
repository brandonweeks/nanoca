# nanoca

A lightweight enterprise [ACME](https://datatracker.ietf.org/doc/html/rfc8555) Certificate Authority service with [device attestation](https://datatracker.ietf.org/doc/draft-ietf-acme-device-attest/) support. It provides just the HTTP handlers needed to implement ACME, it is intended to be integrated into [nanomdm](https://github.com/micromdm/nanomdm) or another service of your choosing. Storage, signing, authorization, and logging are implemented as pluggable interfaces to integrate into a wide variety of environments.

## Usage

```go
import (
	"log/slog"
	"net/http"

	"github.com/brandonweeks/nanoca"
	nullauthorizer "github.com/brandonweeks/nanoca/authorizers/null"
	"github.com/brandonweeks/nanoca/issuers/inprocess"
	"github.com/brandonweeks/nanoca/signers/file"
	"github.com/brandonweeks/nanoca/storage/badger"
	"github.com/brandonweeks/nanoca/verifiers/apple"
)

logger := slog.New(nanoca.NewContextHandler(slog.Default().Handler()))

caCert, _ := /* load your *x509.Certificate */
signer, _ := file.LoadSigner("rootCA.key")
storage, _ := badger.New(badger.Options{InMemory: true})

issuer, _ := inprocess.New(signer, caCert)
ca, _ := nanoca.New(
	logger,
	issuer,
	nullauthorizer.New(),
	storage,
	"https://localhost:8443",
	nanoca.WithPrefix("/acme"),
	nanoca.WithVerifier(apple.New(logger)),
)
defer ca.Close()

mux := http.NewServeMux()
mux.Handle("/", ca.Handler())
```

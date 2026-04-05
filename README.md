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

ca, _ := nanoca.New(
	logger,
	inprocess.New(caCert, signer),
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

### Certificate chain serving

When nanoca is deployed as an intermediate CA, ACME clients need the full certificate chain to build a trust path. Pass the chain to the in-process issuer after the signer argument:

```go
// intermCert is the issuing intermediate, rootCert is the root CA.
// Order matters: issuer of the leaf first, then its issuer, up toward the root.
issuer := inprocess.New(intermCert, intermSigner, intermCert, rootCert)
```

The ACME certificate endpoint will return the leaf followed by each chain certificate as a PEM-encoded `application/pem-certificate-chain` response per RFC 8555 Section 7.4.2. Callers that don't pass a chain get the previous behavior (leaf only).

### Remote signing oracle

The `signers/remote` package provides a `crypto.Signer` that delegates signing to an external HTTP service, allowing the CA private key to live in an HSM, cloud KMS, or any custom signing service.

```go
import "github.com/brandonweeks/nanoca/signers/remote"

signer, err := remote.New(
	"https://signer.internal:8443",  // oracle URL (must be HTTPS)
	"bearer-token",                   // Authorization header value
	publicKeyPEM,                     // PEM-encoded ECDSA public key
)
```

The oracle protocol is a single endpoint:

- `POST /sign` with `Authorization: Bearer <token>` and JSON body `{"digest": "<base64>", "hash": "SHA-256"}`
- Response: `{"signature": "<base64-DER>"}`

The signer verifies every signature returned by the oracle against the known public key before passing it to the caller. Plain HTTP is rejected unless the oracle is on a loopback address.

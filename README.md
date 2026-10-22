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

## Attestation formats

- `verifiers/apple` verifies Apple Managed Device Attestation. The device
  identity comes from the attestation certificate's Apple extensions, and the
  statement is bound to the challenge token.
- `verifiers/tpm` verifies TPM 2.0 attestation: a certification by the
  device's attestation key (AK) that the key to certify lives in its TPM. It
  takes the roots of the attestation CA that issues AK certificates to your
  devices, since there is no industry-wide root for them:
  `tpm.New(logger, roots)`. The device identity comes from the AK
  certificate's subjectAltName, the certified key comes from `pubArea`, and
  the certification is bound to the key authorization.
- `verifiers/null` accepts any statement. Never register it next to a real
  verifier: the client picks the format, so any client could then skip
  attestation.

## Deployment

- Terminate TLS on the listener or in a proxy in front of the handler. The
  JWS `url` check compares against the configured base URL, so the base URL
  must be the `https://` URL clients use.
- Rate limit the ACME endpoints at the proxy. Account creation and
  `/new-nonce` are unauthenticated, and every request stores a nonce for an
  hour, so request volume is storage volume.
- Orders, authorizations, and challenges are kept until the operator prunes
  them. The storage backend does not expire them.

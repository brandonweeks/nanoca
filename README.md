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

## Devices that cannot attest

Apple's ACME client answers `device-attest-01` with `{}`, no attestation
object, whenever the device has none to give. That covers macOS VMs and
Macs without a T2, which must use `Attest` false, and the devices Apple
[lists](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.security.acme.yaml)
as ignoring `Attest`: T2 Macs, and iPads and Apple TVs with an A10X Fusion
or earlier that still run iPadOS or tvOS 16 or later. The client orders
the payload's `ClientIdentifier` as a `permanent-identifier` either way.
By default nanoca rejects that answer as malformed.

`nanoca.WithUnattestedAuthorizer` lets your code decide those answers.
Nothing is attested and the `Authorizer` is never called for them, so with
this option set, any client that answers without an attestation is judged
by your code alone, including a device that could have attested. It is the
whole security boundary for these certificates: treat the identifier as a
one-time secret, never a serial number.

An admitted device gets a certificate for its CSR key that names no
device, and the key must be ECDSA P-256 or stronger, or RSA of at least
2048 bits. Such a certificate looks like any other without a device SAN,
so issue it from a separate CA if relying parties need to tell them apart;
issuers see `DeviceInfo.Unattested`.

[`examples/unattested`](examples/unattested) has a one-time-token gate to
copy.

## Deployment

- Terminate TLS on the listener or in a proxy in front of the handler. The
  JWS `url` check compares against the configured base URL, so the base URL
  must be the `https://` URL clients use.
- Rate limit the ACME endpoints at the proxy. Account creation and
  `/new-nonce` are unauthenticated, and every request stores a nonce for an
  hour, so request volume is storage volume.
- Orders, authorizations, and challenges are kept until the operator prunes
  them. The storage backend does not expire them.

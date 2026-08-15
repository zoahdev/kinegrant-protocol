# kinegrant-go

An independent KGP-001 verifier written in Go using only the standard library
(crypto/ed25519, crypto/sha256, encoding/json, encoding/base64).

## Install

```bash
go get github.com/zoahdev/kinegrant-protocol/implementations/kinegrant-go
```

## CLI

```bash
go run ./cmd/kinegrant-verify verify-capability <envelope.json> <request.json> <issuers.json>
go run ./cmd/kinegrant-verify verify-receipts <entries.json> <executors.json>
go run ./cmd/kinegrant-verify verify-policy-bundle <bundle.json> <authorities.json> [policy-id]
go run ./cmd/kinegrant-verify current-policy-version <bundles.json> [revoked.json]
```

## Library

```go
import kg "github.com/zoahdev/kinegrant-protocol/implementations/kinegrant-go"
```

The package verifies policy bundles, capabilities (v0.1 and 0.2/1.0), and
receipt chains, cross-tested against the Python reference implementation.

## Tests

```bash
go test ./...
```

# KineGrant Implementations

| Implementation | Language | Status | Coverage |
| --- | --- | --- | --- |
| Reference implementation (`src/kinegrant`) | Python | reference | full protocol surface, 281+ tests |
| `kinegrant-js` (`implementations/kinegrant-js`) | JavaScript (ESM, Node >= 20) | independent verifier | RFC 8785 JCS subset, Ed25519 envelopes, v0.1 and 0.2/1.0 capability verification, receipt chains |
| `kinegrant-go` (`implementations/kinegrant-go`) | Go (stdlib only) | independent verifier | JCS subset, Ed25519 envelopes, v0.1 and 0.2/1.0 capability verification, receipt chains |

## Interoperability

`tests/test_javascript_interop.py` signs a capability and receipt with the
Python reference implementation and verifies them with `kinegrant-js` and
`kinegrant-go` (and rejects tampered capabilities). Both verifiers accept
`0.2`/`1.0` scoped capabilities, so the stable wire format is cross-verified
across all three implementations.

```bash
node --test implementations/kinegrant-js/test/
python -m unittest tests.test_javascript_interop -v
go test ./implementations/kinegrant-go/...
python -m unittest tests.test_go_interop -v
```

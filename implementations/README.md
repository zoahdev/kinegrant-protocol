# KineGrant Implementations

| Implementation | Language | Status | Coverage |
| --- | --- | --- | --- |
| Reference implementation (`src/kinegrant`) | Python | reference | full protocol surface, 281+ tests |
| `kinegrant-js` (`implementations/kinegrant-js`) | JavaScript (ESM, Node >= 20) | independent verifier | RFC 8785 JCS subset, Ed25519 envelopes, v0.1 capability verification, receipt chains |
| `kinegrant-go` (`implementations/kinegrant-go`) | Go (stdlib only) | independent verifier | JCS subset, Ed25519 envelopes, v0.1 capability verification, receipt chains |

## Interoperability

`tests/test_javascript_interop.py` signs a capability and receipt with the
Python reference implementation and verifies them with `kinegrant-js` (and
rejects a tampered capability). The JavaScript verifier has no dependency
beyond Node's `crypto`, and its JCS canonicalization is asserted byte-identical
against the Python implementation on wire objects.

```bash
node --test implementations/kinegrant-js/test/
python -m unittest tests.test_javascript_interop -v
go test ./implementations/kinegrant-go/...
python -m unittest tests.test_go_interop -v
```

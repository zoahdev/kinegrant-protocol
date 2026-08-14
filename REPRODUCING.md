# Reproduce the KineGrant permission boundary

This guide produces a machine-readable packet that another developer can verify
without trusting a screenshot, a hosted demo, or a KineGrant maintainer. It tests
the software permission boundary defined by Machine Permission Test v0.5.

It does **not** prove that a physical machine moved, that a deployment is
functionally safe, or that KineGrant is production-ready.

## Five-minute path

### Zero-install Codespaces path

Open the default branch in [GitHub Codespaces](https://codespaces.new/zoahdev/kinegrant-protocol?ref=main&quickstart=1). The checked-in Dev Container installs
the test surface, generates the packet, and runs the independent verifier. A
successful terminal ends with `PASS`. The resulting files are in
`reproduction-output/`.

Codespaces is a convenience environment, not independent evidence by itself.
Publish the exact commit, environment, report, and checksum so others can check
the result. The `External Reproduction` workflow runs on changes to this test
surface; after the workflow reaches the default branch it can also be started
manually from the Actions tab. Project-owned workflow runs are reference
evidence, not third-party reproduction.

### Local path

Use Python 3.11 or newer in a fresh checkout:

```bash
git clone https://github.com/zoahdev/kinegrant-protocol.git
cd kinegrant-protocol
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
python -m pip install -e '.[test]'
python challenge/reproduce.py --output-dir reproduction-output
python challenge/verify_reproduction.py reproduction-output/reproduction-report.json
```

The last command must print `PASS` and exit with status `0`. The output directory
contains:

- `machine-permission-test.evidence.json`: results for MPT-001 through MPT-022;
- `reproduction-report.json`: source, environment, material digests, artifact
  digest, and the independently checked overall result.
- `reproduction-report.sha256`: a ready-to-publish SHA-256 checksum for the
  report.
- `sample-receipt-v0.1.json`: the committed, Schema-valid signed receipt used by
  the public browser verifier and bound into the packet by SHA-256.
- `materials/`: the exact generators, independent verifiers, Schemas, and
  receipt source named in the report, preserving repository-relative paths.

The packet is portable. After downloading and extracting it, verify it without
a KineGrant checkout by running:

```bash
python materials/challenge/verify_reproduction.py reproduction-report.json
```

Every GitHub Actions run also publishes the Python 3.12 packet as a downloadable
30-day workflow artifact named with the exact tested commit.

For a release-specific run, check out the tag before installing:

```bash
git checkout mpt-v0.2
```

For a publishable run, keep the checkout clean. The report records the exact Git
commit and whether tracked files were modified. An explicit commit is rejected
when it differs from the checked-out Git commit. CI supplies its tested commit
explicitly.

## Verify a release packet offline

Stable releases (v1.0.0 and later) publish a checksum-addressed packet:
`SHA256SUMS.txt`, the source archive, the conformance report, and the MPT
evidence. The packet can be verified without a KineGrant checkout or any
network access:

```bash
python scripts/verify_release.py <packet-directory>
```

The verifier:

- checks every file listed in `SHA256SUMS.txt` against its SHA-256 digest;
- requires the conformance report to be present and to report overall `PASS`;
- when MPT evidence is present, runs the independent evidence verifier against
  it.

It prints `RELEASE PACKET VERIFIED` and exits `0` only when every check passes.
Any missing file, checksum mismatch, non-PASS report, or invalid evidence exits
with status `2` and lists each `INVALID` reason.

To run it, download the release assets into one directory and use Python 3.11+
with `scripts/verify_release.py` from the release source archive. This checks
the packet itself; it does not claim that a physical machine moved or that a
deployment is functionally safe.

## What a PASS means

A PASS means the tested source enforced all twenty-two software assertions, including
default denial without a capability, exact request binding, single use,
concurrent single-winner consumption, replay rejection after restart, explicit
issuer trust, exact expiry rejection, and receipt integrity/trust checks.

The packet binds its evidence to SHA-256 digests of the generator, independent
verifiers, and both JSON Schemas. The verifier rejects missing files, path
traversal, changed bytes, inconsistent counts, and mismatched commits or results.

## Report a result

Use the repository's **External reproduction result** issue form for a public,
non-sensitive PASS or FAIL. Include:

- the tested commit or tag;
- operating system and Python version;
- the final verifier line;
- `reproduction-report.json` and the generated `reproduction-report.sha256`;
- the smallest relevant log excerpt if the result is FAIL.

Remove usernames, home-directory paths, credentials, device identifiers, and
personal data before publishing. Report an exploitable vulnerability through a
private GitHub Security Advisory instead of a public issue.

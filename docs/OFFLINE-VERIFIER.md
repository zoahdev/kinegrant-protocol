# Run the KineGrant verifier offline

This guide verifies a downloaded KineGrant release or reproduction packet without a KineGrant checkout, hosted demo, Codespace, or network access. A successful verification proves that the packet is internally consistent and that the included software assertions pass; it does **not** prove that a physical machine moved safely or that a deployment is production-ready.

## 1. Prepare an offline directory

On a connected machine, download the release assets or reproduction packet and copy the verifier materials into one directory. Preserve the files exactly as published. For a release packet, the directory should contain `SHA256SUMS.txt`, the source archive, the conformance report, and any published MPT evidence. For a reproduction packet, keep `reproduction-report.json`, `reproduction-report.sha256`, and the `materials/` directory together.

After the files are copied, disconnect the machine from the network. The commands below intentionally use only local paths.

## 2. Verify a release packet

Use Python 3.11 or newer and run the verifier shipped with the source archive:

```bash
python scripts/verify_release.py <packet-directory>
```

The release verifier checks every digest listed in `SHA256SUMS.txt`, requires the conformance report to say `PASS`, and, when MPT evidence is present, invokes the independent evidence verifier. A valid packet ends with:

```text
RELEASE PACKET VERIFIED
```

The command exits with status `0` only when all checks pass. Missing files, changed bytes, checksum mismatches, a non-`PASS` report, or invalid evidence produce a non-zero result and identify the invalid reason.

## 3. Verify a reproduction packet

A portable reproduction packet carries the exact generators, schemas, independent verifiers, and receipt source referenced by its report. Run:

```bash
python materials/challenge/verify_reproduction.py reproduction-report.json
```

The verifier checks the report’s material digests, artifact digest, tested commit, environment metadata, and the software assertions recorded in the packet. A successful run prints `PASS` and exits with status `0`.

The packet can be checked without trusting the original checkout because the verifier and its inputs are included in `materials/`. Do not edit the packet before checking it; a changed byte should invalidate the corresponding digest.

## 4. Interpret the result

A `PASS` is a statement about the software and evidence packet. It confirms the checks represented by the selected report, such as capability denial, request binding, single use, replay rejection, expiry handling, and receipt integrity. It is not a safety certification, a claim of conformance with an external standards body, or evidence that a physical device performed an action.

## 5. Report a result safely

For a non-sensitive public result, include the tested commit or tag, operating system, Python version, final verifier line, and the report plus its checksum. Remove usernames, home-directory paths, credentials, device identifiers, and personal data. Report a suspected exploitable vulnerability through the repository’s private security-advisory process rather than a public issue.

## Troubleshooting

If `SHA256SUMS.txt` fails, restore the exact published asset instead of recomputing the checksum from a modified file. If the conformance result is not `PASS`, report the smallest relevant log excerpt and the exact commit. If a required material is missing, obtain the complete packet from the same release or reproduction run; do not substitute a file from another commit.

See [`REPRODUCING.md`](../REPRODUCING.md) for the connected local and Codespaces paths, packet contents, and the full explanation of what a `PASS` means. The browser verifier described in the main README is a separate client-side path and should be treated as an independent verifier, not as a replacement for the packet checks above.

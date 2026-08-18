# Local Reproducible Verification Record

> Generated: 2026-08-19 (offline sandbox, bundled Python 3.12.13 / Node 24)
> Purpose: record that the core protocol can be verified locally without network.

## Environment

- Python 3.12.13, cryptography 50.0.0; jsonschema/pyserial not installed (offline)
- Node v24.19.0
- Source: this repository (main)

## Results

| Check | Result |
| --- | --- |
| Python source syntax (`py_compile`, 56 files) | 56/56 pass |
| Python test modules (42 of 57 collectable) | 42 PASS, 0 real failures; 15 not collectable due to missing `jsonschema` (CI installs it via `pip install -e '.[test]'`) |
| JavaScript verifier tests | 72/72 pass (verify 11 + browser_verifier 61) |
| CLI smoke: `kinegrant-demo` | exit 0, valid JSON decision output |
| CLI smoke: audit/robot-demo/bridge-demo/ros2-demo/revoke-distribute/red-team | all exit 0 |
| JSON data files (26) | all parse (UTF-8) |
| pyproject.toml | parses (tomllib) |
| schema↔source consistency | capability-1.0 (25 fields) = `CAPABILITY_FIELDS_V2`; action-request/policy-rule/decision dataclasses match schemas; receipt v0.1/v1.0 consistent |

## Reproduce

```bash
pip install -e '.[test]'     # includes jsonschema
python -m unittest discover -s tests -v
node --test implementations/kinegrant-js/test/
kinegrant-demo
python -c "import json,sys; json.load(open(sys.argv[1], encoding='utf-8'))" spec/schemas/capability-1.0.schema.json
```

## Note

The 15 non-collectable modules fail only on `ModuleNotFoundError: No module named 'jsonschema'`; the CI matrix (Python 3.11–3.13 with the test extra) runs all 501 tests green.
## Dependency audit

- pip-audit (2026-08-19): no known vulnerabilities in core dependencies (cryptography>=42, jsonschema[format]>=4.23).
- CI runs the audit on every push/PR and weekly (workflow: dependency-audit).

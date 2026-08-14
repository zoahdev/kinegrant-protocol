# Camera Consent Deployment Example

Scenario: a space camera may record for security, but the space owner forbids
training models on the recordings. KineGrant demonstrates the boundary with
policy and a forbidden combination.

Run:

```bash
python examples/camera-consent/camera_consent.py
```

The script prints the trace and exits nonzero if any invariant fails.

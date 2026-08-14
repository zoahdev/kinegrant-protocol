package kinegrant

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCanonicalJSON(t *testing.T) {
	got, err := CanonicalJSON(map[string]any{"b": 1, "a": 2})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":2,"b":1}` {
		t.Fatalf("unexpected canonical json: %s", got)
	}
}

func testKeyPair(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid := "kinegrant:key:ed25519:" + base64.RawURLEncoding.EncodeToString(publicKey)
	return privateKey, publicKey, kid
}

func signEnvelope(t *testing.T, privateKey ed25519.PrivateKey, kid string, payload map[string]any) map[string]any {
	t.Helper()
	protected := map[string]any{"alg": "EdDSA", "kid": kid, "payload": payload}
	canonical, err := CanonicalJSON(protected)
	if err != nil {
		t.Fatal(err)
	}
	data := append(append([]byte{}, domain...), canonical...)
	signature := ed25519.Sign(privateKey, data)
	return map[string]any{
		"alg": "EdDSA",
		"kid": kid,
		"payload": payload,
		"signature": base64.RawURLEncoding.EncodeToString(signature),
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	privateKey, _, kid := testKeyPair(t)
	envelope := signEnvelope(t, privateKey, kid, map[string]any{"hello": "world"})
	payload, err := VerifyEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if payload["hello"] != "world" {
		t.Fatal("payload mismatch")
	}
	envelope["payload"].(map[string]any)["hello"] = "tampered"
	if _, err := VerifyEnvelope(envelope); err == nil {
		t.Fatal("tampered envelope was accepted")
	}
}

func policyBundle(t *testing.T, privateKey ed25519.PrivateKey, kid string, version int, purposes []any) map[string]any {
	t.Helper()
	now := time.Now().UTC()
	rules := []any{
		map[string]any{
			"policy_id": "urn:policy:door",
			"issuer":    kid,
			"target":    "urn:space:door-1",
			"effect":    "allow",
			"actions":   []any{"open"},
			"subjects":  []any{"*"},
			"purposes":  purposes,
			"constraints": map[string]any{},
			"obligations": []any{},
			"priority":    0,
			"source":      map[string]any{},
		},
	}
	digest, err := digestObject(map[string]any{"rules": rules})
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{
		"type":                    "kinegrant:PolicyBundle",
		"schema_version":          "0.1",
		"policy_id":               "urn:policy:door",
		"issuer":                  kid,
		"version":                 float64(version),
		"previous_version_digest": nil,
		"issued_at":               now.Format(time.RFC3339Nano),
		"not_before":              now.Format(time.RFC3339Nano),
		"not_after":               now.Add(time.Hour).Format(time.RFC3339Nano),
		"policy_digest":           digest,
		"rules":                   rules,
	}
	bundleID, err := contentID("kinegrant:policy-bundle", body)
	if err != nil {
		t.Fatal(err)
	}
	body["bundle_id"] = bundleID
	return signEnvelope(t, privateKey, kid, body)
}

func TestVerifyPolicyBundle(t *testing.T) {
	privateKey, _, kid := testKeyPair(t)
	bundle := policyBundle(t, privateKey, kid, 1, []any{"delivery"})
	payload, err := VerifyPolicyBundle(bundle, map[string]bool{kid: true}, "urn:policy:door", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if payload["version"] != float64(1) {
		t.Fatal("unexpected version")
	}
	rules, _ := payload["rules"].([]any)
	rules[0].(map[string]any)["effect"] = "deny"
	if _, err := VerifyPolicyBundle(bundle, map[string]bool{kid: true}, "", time.Now()); err == nil {
		t.Fatal("tampered policy bundle was accepted")
	}
	if _, err := VerifyPolicyBundle(bundle, map[string]bool{}, "", time.Now()); err == nil {
		t.Fatal("untrusted authority was accepted")
	}
	if _, err := VerifyPolicyBundle(bundle, map[string]bool{kid: true}, "urn:policy:other", time.Now()); err == nil {
		t.Fatal("wrong policy id was accepted")
	}
}

func TestCurrentPolicyVersion(t *testing.T) {
	privateKey, _, kid := testKeyPair(t)
	v1 := policyBundle(t, privateKey, kid, 1, []any{"delivery"})
	v2 := policyBundle(t, privateKey, kid, 2, []any{"delivery", "maintenance"})
	payloads := []map[string]any{v1["payload"].(map[string]any), v2["payload"].(map[string]any)}
	current, err := CurrentPolicyVersion(payloads, map[string]bool{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if current["version"] != float64(2) {
		t.Fatal("expected version 2")
	}
	current, err = CurrentPolicyVersion(payloads, map[string]bool{"urn:policy:door:2": true}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if current["version"] != float64(1) {
		t.Fatal("expected rollback to version 1")
	}
	if _, err := CurrentPolicyVersion(payloads, map[string]bool{"urn:policy:door:1": true, "urn:policy:door:2": true}, time.Now()); err == nil {
		t.Fatal("expected fail-closed with no current version")
	}
}

func TestPolicyBundleCLICompatHelpers(t *testing.T) {
	privateKey, _, kid := testKeyPair(t)
	bundle := policyBundle(t, privateKey, kid, 1, []any{"delivery"})
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"type":"kinegrant:PolicyBundle"`) {
		t.Fatal("policy bundle encoding mismatch")
	}
}

func TestCapabilityRoundTrip(t *testing.T) {
	privateKey, publicKey, kid := testKeyPair(t)
	request := map[string]any{
		"type": "kinegrant:ActionRequest", "version": "0.1",
		"request_id": "req-1", "agent": "robot-1", "target": "door-7",
		"action": "open", "purpose": "delivery",
		"issued_at": time.Now().Format(time.RFC3339), "context": map[string]any{},
	}
	requestDigest, err := digestObject(request)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	issuedAt := now.Format(time.RFC3339)
	expiresAt := now.Add(300 * time.Second).Format(time.RFC3339)
	body := map[string]any{
		"type": "kinegrant:PhysicalActionCapability", "version": "0.1",
		"issuer": kid, "agent": "robot-1", "target": "door-7",
		"action": "open", "purpose": "delivery",
		"request_digest": requestDigest,
		"policy_digest": "sha256:" + repeat("0", 64),
		"matched_policy_ids": []any{"policy-1"},
		"obligations": []any{"emitActionReceipt"},
		"issued_at": issuedAt, "not_before": issuedAt, "expires_at": expiresAt,
		"nonce": repeat("n", 24),
	}
	unsigned := make(map[string]any, len(body))
	for key, value := range body {
		unsigned[key] = value
	}
	capabilityID, err := contentID("kinegrant:cap", unsigned)
	if err != nil {
		t.Fatal(err)
	}
	body["capability_id"] = capabilityID
	envelope := signEnvelope(t, privateKey, kid, body)
	if _, err := VerifyCapability(envelope, request, map[string]bool{kid: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCapability(envelope, request, map[string]bool{}); err == nil {
		t.Fatal("untrusted issuer was accepted")
	}
	_ = publicKey
}

func repeat(char string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += char
	}
	return result
}

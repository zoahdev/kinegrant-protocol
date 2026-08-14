package kinegrant

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
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

// Package kinegrant implements an independent KGP-001 verifier in Go.
// It uses only the Go standard library (crypto/ed25519, crypto/sha256,
// encoding/json, encoding/base64).
package kinegrant

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"path"
)

var domain = []byte("KINEGRANT-SIGNED-ENVELOPE-V1\x00")

var capabilityFields = map[string]bool{
	"type": true, "version": true, "issuer": true, "agent": true,
	"target": true, "action": true, "purpose": true,
	"request_digest": true, "policy_digest": true,
	"matched_policy_ids": true, "obligations": true,
	"issued_at": true, "not_before": true, "expires_at": true,
	"nonce": true, "capability_id": true,
}

var sha256Re = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

var capabilityFieldsV2 = map[string]bool{
	"type": true, "version": true, "issuer": true, "agent": true,
	"target": true, "actions": true, "purposes": true,
	"request_digest": true, "policy_digest": true,
	"matched_policy_ids": true, "obligations": true,
	"issued_at": true, "not_before": true, "expires_at": true,
	"nonce": true, "capability_id": true,
	"parent_capability_id": true, "constraints": true, "approval_tier": true,
	"delegation_allowed": true, "max_delegation_depth": true,
	"delegate_agent": true, "delegation_depth": true,
	"root_capability_id": true, "delegate_allowlist": true,
}

var obligationStatuses = map[string]bool{
	"satisfied": true, "pending": true, "failed": true,
}

var knownObligations = map[string]bool{
	"emitActionReceipt": true, "logAuditEvent": true, "preserveEvidence": true,
}

func jsonString(value string) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// CanonicalJSON returns the RFC 8785 JCS subset used by KineGrant wire
// objects (ASCII strings and integers; U+2028/U+2029 escaping is pending).
func CanonicalJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		encoded, err := jsonString(v)
		if err != nil {
			return err
		}
		buf.Write(encoded)
	case float64:
		if v != v || v > 1e308 || v < -1e308 {
			return errors.New("non-finite number")
		}
		encoded, err := json.Marshal(v)
		if err != nil {
			return err
		}
		buf.Write(encoded)
	case int:
		fmt.Fprintf(buf, "%d", v)
	case []any:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			encoded, err := jsonString(key)
			if err != nil {
				return err
			}
			buf.Write(encoded)
			buf.WriteByte(':')
			if err := writeCanonical(buf, v[key]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("cannot canonicalize %T", value)
	}
	return nil
}

func b64urlDecode(value string) ([]byte, error) {
	if value == "" {
		return nil, errors.New("empty base64url")
	}
	return base64.RawURLEncoding.DecodeString(value)
}

func publicKeyFromKid(kid string) (ed25519.PublicKey, error) {
	const prefix = "kinegrant:key:ed25519:"
	if !strings.HasPrefix(kid, prefix) {
		return nil, errors.New("unsupported key identifier")
	}
	raw, err := b64urlDecode(strings.TrimPrefix(kid, prefix))
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Ed25519 public key length")
	}
	return ed25519.PublicKey(raw), nil
}

// VerifyEnvelope verifies the KineGrant signed-envelope format.
func VerifyEnvelope(envelope map[string]any) (map[string]any, error) {
	alg, _ := envelope["alg"].(string)
	if alg != "EdDSA" {
		return nil, errors.New("unsupported signature algorithm")
	}
	kid, _ := envelope["kid"].(string)
	signature, _ := envelope["signature"].(string)
	payload, ok := envelope["payload"].(map[string]any)
	if kid == "" || signature == "" || !ok {
		return nil, errors.New("malformed signed envelope")
	}
	protected := map[string]any{"alg": alg, "kid": kid, "payload": payload}
	canonical, err := CanonicalJSON(protected)
	if err != nil {
		return nil, err
	}
	data := append(append([]byte{}, domain...), canonical...)
	rawSignature, err := b64urlDecode(signature)
	if err != nil {
		return nil, err
	}
	if len(rawSignature) != ed25519.SignatureSize {
		return nil, errors.New("invalid Ed25519 signature length")
	}
	publicKey, err := publicKeyFromKid(kid)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(publicKey, data, rawSignature) {
		return nil, errors.New("invalid signature")
	}
	return payload, nil
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func contentID(prefix string, value any) (string, error) {
	canonical, err := CanonicalJSON(value)
	if err != nil {
		return "", err
	}
	return prefix + ":" + sha256Hex(canonical), nil
}

func digestObject(value any) (string, error) {
	canonical, err := CanonicalJSON(value)
	if err != nil {
		return "", err
	}
	return "sha256:" + sha256Hex(canonical), nil
}

func parseTime(value string) (time.Time, error) {
	return time.Parse(time.RFC3339, value)
}

func stringField(payload map[string]any, name string) (string, error) {
	value, _ := payload[name].(string)
	if value == "" {
		return "", fmt.Errorf("missing %s", name)
	}
	return value, nil
}

// VerifyCapability verifies a v0.1 capability against a request.
func VerifyCapability(envelope map[string]any, request map[string]any, trustedIssuers map[string]bool) (map[string]any, error) {
	payload, err := VerifyEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	switch payload["version"] {
	case "0.2", "1.0":
		return verifyCapabilityV2(payload, envelope, request, trustedIssuers)
	case "0.1":
	default:
		return nil, errors.New("unsupported capability version")
	}
	if len(payload) != len(capabilityFields) {
		return nil, errors.New("capability fields do not match the v0.1 schema")
	}
	for field := range payload {
		if !capabilityFields[field] {
			return nil, errors.New("capability fields do not match the v0.1 schema")
		}
	}
	if payload["type"] != "kinegrant:PhysicalActionCapability" {
		return nil, errors.New("wrong capability type")
	}
	if payload["version"] != "0.1" {
		return nil, errors.New("unsupported capability version")
	}
	if payload["issuer"] != envelope["kid"] {
		return nil, errors.New("capability issuer does not match signing key")
	}
	issuer, _ := payload["issuer"].(string)
	if !trustedIssuers[issuer] {
		return nil, errors.New("untrusted capability issuer")
	}
	requestDigest, err := digestObject(request)
	if err != nil {
		return nil, err
	}
	if payload["request_digest"] != requestDigest {
		return nil, errors.New("capability does not authorize this request")
	}
	for _, field := range []string{"agent", "target", "action", "purpose"} {
		if payload[field] != request[field] {
			return nil, fmt.Errorf("capability %s mismatch", field)
		}
	}
	issuedAtValue, err := stringField(payload, "issued_at")
	if err != nil {
		return nil, err
	}
	notBeforeValue, err := stringField(payload, "not_before")
	if err != nil {
		return nil, err
	}
	expiresAtValue, err := stringField(payload, "expires_at")
	if err != nil {
		return nil, err
	}
	issuedAt, err := parseTime(issuedAtValue)
	if err != nil {
		return nil, errors.New("invalid capability time window")
	}
	notBefore, err := parseTime(notBeforeValue)
	if err != nil {
		return nil, errors.New("invalid capability time window")
	}
	expiresAt, err := parseTime(expiresAtValue)
	if err != nil {
		return nil, errors.New("invalid capability time window")
	}
	if notBefore.Before(issuedAt) || !expiresAt.After(notBefore) {
		return nil, errors.New("invalid capability time window")
	}
	if expiresAt.Sub(notBefore) > 300*time.Second {
		return nil, errors.New("capability lifetime exceeds protocol maximum")
	}
	now := time.Now()
	if now.Before(notBefore) {
		return nil, errors.New("capability is not active yet")
	}
	if !now.Before(expiresAt) {
		return nil, errors.New("capability has expired")
	}
	nonce, _ := payload["nonce"].(string)
	if len(nonce) < 20 {
		return nil, errors.New("capability nonce is invalid")
	}
	matched, ok := payload["matched_policy_ids"].([]any)
	if !ok || len(matched) == 0 {
		return nil, errors.New("capability has no matching policy")
	}
	obligations, ok := payload["obligations"].([]any)
	if !ok {
		return nil, errors.New("capability obligations are invalid")
	}
	for _, obligation := range obligations {
		obligationName, ok := obligation.(string)
		if !ok || !knownObligations[obligationName] {
			return nil, errors.New("capability obligations are invalid")
		}
	}
	policyDigest, _ := payload["policy_digest"].(string)
	if !sha256Re.MatchString(policyDigest) {
		return nil, errors.New("capability policy digest is invalid")
	}
	unsigned := make(map[string]any, len(payload))
	for key, value := range payload {
		if key != "capability_id" {
			unsigned[key] = value
		}
	}
	expectedID, err := contentID("kinegrant:cap", unsigned)
	if err != nil {
		return nil, err
	}
	if payload["capability_id"] != expectedID {
		return nil, errors.New("capability identifier is inconsistent")
	}
	return payload, nil
}

func globMatch(pattern, value string) bool {
	matched, err := path.Match(pattern, value)
	return err == nil && matched
}

func verifyCapabilityV2(payload map[string]any, envelope map[string]any, request map[string]any, trustedIssuers map[string]bool) (map[string]any, error) {
	if len(payload) != len(capabilityFieldsV2) {
		return nil, errors.New("capability fields do not match the scoped schema")
	}
	for field := range payload {
		if !capabilityFieldsV2[field] {
			return nil, errors.New("capability fields do not match the scoped schema")
		}
	}
	if payload["type"] != "kinegrant:PhysicalActionCapability" {
		return nil, errors.New("wrong capability type")
	}
	if payload["issuer"] != envelope["kid"] {
		return nil, errors.New("capability issuer does not match signing key")
	}
	issuer, _ := payload["issuer"].(string)
	if !trustedIssuers[issuer] {
		return nil, errors.New("untrusted capability issuer")
	}
	requestDigest, err := digestObject(request)
	if err != nil {
		return nil, err
	}
	if payload["request_digest"] != requestDigest {
		return nil, errors.New("capability does not authorize this request")
	}
	if payload["agent"] != request["agent"] {
		return nil, errors.New("capability agent mismatch")
	}
	targetPattern, _ := payload["target"].(string)
	requestTarget, _ := request["target"].(string)
	if !globMatch(targetPattern, requestTarget) {
		return nil, errors.New("capability target scope mismatch")
	}
	actions, ok := payload["actions"].([]any)
	if !ok || !containsString(actions, request["action"]) {
		return nil, errors.New("capability action scope mismatch")
	}
	purposes, ok := payload["purposes"].([]any)
	if !ok || !containsString(purposes, request["purpose"]) {
		return nil, errors.New("capability purpose scope mismatch")
	}
	if parentID, present := payload["parent_capability_id"]; present && parentID != nil {
		if _, ok := parentID.(string); !ok {
			return nil, errors.New("capability parent id must be a string or null")
		}
	}
	constraints, ok := payload["constraints"].(map[string]any)
	if !ok {
		return nil, errors.New("capability constraints must be an object")
	}
	for _, name := range []string{"max_force_newtons", "max_velocity_mps"} {
		if value, present := constraints[name]; present {
			number, ok := value.(float64)
			if !ok || number < 0 {
				return nil, fmt.Errorf("capability %s must be a non-negative number", name)
			}
		}
	}
	if zones, present := constraints["allowed_zones"]; present {
		zoneList, ok := zones.([]any)
		if !ok || len(zoneList) == 0 {
			return nil, errors.New("capability allowed_zones must be a non-empty list")
		}
		for _, zone := range zoneList {
			if _, ok := zone.(string); !ok {
				return nil, errors.New("capability allowed_zones must contain strings")
			}
		}
	}
	tier, ok := payload["approval_tier"].(float64)
	if !ok || tier != float64(int(tier)) || tier < 0 || tier > 2 {
		return nil, errors.New("capability approval_tier must be an integer between 0 and 2")
	}
	if _, ok := payload["delegation_allowed"].(bool); !ok {
		return nil, errors.New("capability delegation_allowed must be a boolean")
	}
	maxDepth, ok := payload["max_delegation_depth"].(float64)
	if !ok || maxDepth < 0 || maxDepth > 3 {
		return nil, errors.New("capability max_delegation_depth must be between 0 and 3")
	}
	depth, ok := payload["delegation_depth"].(float64)
	if !ok || depth < 0 || depth > 3 {
		return nil, errors.New("capability delegation_depth must be between 0 and 3")
	}
	if delegate, present := payload["delegate_agent"]; present && delegate != nil {
		if _, ok := delegate.(string); !ok {
			return nil, errors.New("capability delegate_agent must be a non-empty string or null")
		}
	}
	rootID, _ := payload["root_capability_id"].(string)
	if rootID == "" {
		return nil, errors.New("capability root_capability_id must be a non-empty string")
	}
	if allowlist, present := payload["delegate_allowlist"]; present && allowlist != nil {
		items, ok := allowlist.([]any)
		if !ok {
			return nil, errors.New("capability delegate_allowlist must be a list or null")
		}
		for _, item := range items {
			if _, ok := item.(string); !ok {
				return nil, errors.New("capability delegate_allowlist must contain strings")
			}
		}
	}
	if err := validateCommonCapability(payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func containsString(items []any, value any) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func validateCommonCapability(payload map[string]any) error {
	issuedAtValue, err := stringField(payload, "issued_at")
	if err != nil {
		return err
	}
	notBeforeValue, err := stringField(payload, "not_before")
	if err != nil {
		return err
	}
	expiresAtValue, err := stringField(payload, "expires_at")
	if err != nil {
		return err
	}
	issuedAt, err := parseTime(issuedAtValue)
	if err != nil {
		return errors.New("invalid capability time window")
	}
	notBefore, err := parseTime(notBeforeValue)
	if err != nil {
		return errors.New("invalid capability time window")
	}
	expiresAt, err := parseTime(expiresAtValue)
	if err != nil {
		return errors.New("invalid capability time window")
	}
	if notBefore.Before(issuedAt) || !expiresAt.After(notBefore) {
		return errors.New("invalid capability time window")
	}
	if expiresAt.Sub(notBefore) > 300*time.Second {
		return errors.New("capability lifetime exceeds protocol maximum")
	}
	now := time.Now()
	if now.Before(notBefore) {
		return errors.New("capability is not active yet")
	}
	if !now.Before(expiresAt) {
		return errors.New("capability has expired")
	}
	nonce, _ := payload["nonce"].(string)
	if len(nonce) < 20 {
		return errors.New("capability nonce is invalid")
	}
	matched, ok := payload["matched_policy_ids"].([]any)
	if !ok || len(matched) == 0 {
		return errors.New("capability has no matching policy")
	}
	obligations, ok := payload["obligations"].([]any)
	if !ok {
		return errors.New("capability obligations are invalid")
	}
	for _, obligation := range obligations {
		obligationName, ok := obligation.(string)
		if !ok || !knownObligations[obligationName] {
			return errors.New("capability obligations are invalid")
		}
	}
	policyDigest, _ := payload["policy_digest"].(string)
	if !sha256Re.MatchString(policyDigest) {
		return errors.New("capability policy digest is invalid")
	}
	unsigned := make(map[string]any, len(payload))
	for key, value := range payload {
		if key != "capability_id" && key != "root_capability_id" {
			unsigned[key] = value
		}
	}
	expectedID, err := contentID("kinegrant:cap", unsigned)
	if err != nil {
		return err
	}
	if payload["capability_id"] != expectedID {
		return errors.New("capability identifier is inconsistent")
	}
	return nil
}

// VerifyReceiptChain verifies a KGP receipt hash chain.
func VerifyReceiptChain(entries []map[string]any, trustedExecutors map[string]bool) error {
	var previous any
	seen := make(map[string]bool)
	for _, envelope := range entries {
		payload, err := VerifyEnvelope(envelope)
		if err != nil {
			return err
		}
		if payload["type"] != "kinegrant:PhysicalActionReceipt" {
			return errors.New("wrong receipt type")
		}
		switch payload["version"] {
		case "0.1":
		case "1.0":
			if err := validateReceiptV10(payload); err != nil {
				return err
			}
		default:
			return errors.New("unsupported receipt version")
		}
		if payload["executor"] != envelope["kid"] {
			return errors.New("receipt executor does not match signing key")
		}
		executor, _ := payload["executor"].(string)
		if trustedExecutors != nil && !trustedExecutors[executor] {
			return errors.New("untrusted executor")
		}
		capabilityID, _ := payload["capability_id"].(string)
		if capabilityID == "" || seen[capabilityID] {
			return errors.New("duplicate terminal receipt")
		}
		seen[capabilityID] = true
		unsigned := make(map[string]any, len(payload))
		for key, value := range payload {
			if key != "receipt_id" {
				unsigned[key] = value
			}
		}
		expectedID, err := contentID("kinegrant:receipt", unsigned)
		if err != nil {
			return err
		}
		if payload["receipt_id"] != expectedID {
			return errors.New("receipt identifier is inconsistent")
		}
		var expected any
		if previous == nil {
			expected = nil
		} else {
			canonical, err := CanonicalJSON(previous)
			if err != nil {
				return err
			}
			expected = "sha256:" + sha256Hex(canonical)
		}
		if payload["previous_receipt_hash"] != expected {
			return errors.New("receipt chain is inconsistent")
		}
		previous = envelope
	}
	return nil
}

func validateReceiptV10(payload map[string]any) error {
	_, hasObligations := payload["obligation_results"]
	_, hasFailureReason := payload["failure_reason"]
	if !hasObligations && !hasFailureReason {
		return errors.New("receipt 1.0 requires an additive extension")
	}
	if hasFailureReason {
		reason, _ := payload["failure_reason"].(string)
		if reason == "" {
			return errors.New("receipt failure_reason is invalid")
		}
	}
	if hasObligations {
		results, ok := payload["obligation_results"].([]any)
		if !ok || len(results) == 0 {
			return errors.New("receipt obligation_results are invalid")
		}
		for _, raw := range results {
			item, ok := raw.(map[string]any)
			if !ok {
				return errors.New("receipt obligation result must be an object")
			}
			for field := range item {
				if field != "obligation" && field != "status" && field != "failure_reason" {
					return errors.New("receipt obligation result has unknown fields")
				}
			}
			obligation, _ := item["obligation"].(string)
			if !knownObligations[obligation] {
				return errors.New("receipt obligation is unknown")
			}
			status, _ := item["status"].(string)
			if !obligationStatuses[status] {
				return errors.New("receipt obligation status is invalid")
			}
			reason, _ := item["failure_reason"].(string)
			hasReason := item["failure_reason"] != nil
			if hasReason && reason == "" {
				return errors.New("receipt obligation failure_reason is invalid")
			}
			if status == "failed" && (reason == "" || !hasReason) {
				return errors.New("a failed obligation requires a failure_reason")
			}
		}
	}
	return nil
}

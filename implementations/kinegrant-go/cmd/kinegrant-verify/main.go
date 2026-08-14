package main

import (
	"encoding/json"
	"fmt"
	"os"

	kg "github.com/zoahdev/kinegrant-protocol/implementations/kinegrant-go"
)

func load(path string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, err
	}
	return value, nil
}

func mapOf(value any) (map[string]any, error) {
	result, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("expected an object")
	}
	return result, nil
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: kinegrant-verify verify-capability <envelope.json> <request.json> <issuers.json>")
		fmt.Fprintln(os.Stderr, "       kinegrant-verify verify-receipts <entries.json> <executors.json>")
		os.Exit(2)
	}
	command := os.Args[1]
	var err error
	switch command {
	case "verify-capability":
		envelopeValue, loadErr := load(os.Args[2])
		if loadErr != nil {
			err = loadErr
			break
		}
		requestValue, loadErr := load(os.Args[3])
		if loadErr != nil {
			err = loadErr
			break
		}
		issuersValue, loadErr := load(os.Args[4])
		if loadErr != nil {
			err = loadErr
			break
		}
		var envelope, request map[string]any
		envelope, err = mapOf(envelopeValue)
		if err != nil {
			break
		}
		request, err = mapOf(requestValue)
		if err != nil {
			break
		}
		issuerList, ok := issuersValue.([]any)
		if !ok {
			err = fmt.Errorf("issuers must be an array")
			break
		}
		trusted := make(map[string]bool)
		for _, item := range issuerList {
			if name, ok := item.(string); ok {
				trusted[name] = true
			}
		}
		_, err = kg.VerifyCapability(envelope, request, trusted)
		if err == nil {
			fmt.Println("CAPABILITY VALID")
		}
	case "verify-receipts":
		entriesValue, loadErr := load(os.Args[2])
		if loadErr != nil {
			err = loadErr
			break
		}
		entriesList, ok := entriesValue.([]any)
		if !ok {
			err = fmt.Errorf("entries must be an array")
			break
		}
		entries := make([]map[string]any, 0, len(entriesList))
		for _, item := range entriesList {
			entry, mapErr := mapOf(item)
			if mapErr != nil {
				err = mapErr
				break
			}
			entries = append(entries, entry)
		}
		if err != nil {
			break
		}
		var trusted map[string]bool
		if len(os.Args) >= 4 {
			executorsValue, loadErr := load(os.Args[3])
			if loadErr != nil {
				err = loadErr
				break
			}
			executorList, ok := executorsValue.([]any)
			if !ok {
				err = fmt.Errorf("executors must be an array")
				break
			}
			trusted = make(map[string]bool)
			for _, item := range executorList {
				if name, ok := item.(string); ok {
					trusted[name] = true
				}
			}
		}
		err = kg.VerifyReceiptChain(entries, trusted)
		if err == nil {
			fmt.Println("RECEIPT CHAIN VALID")
		}
	default:
		err = fmt.Errorf("unknown command %s", command)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "INVALID: %v\n", err)
		os.Exit(2)
	}
}

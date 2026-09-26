// SPDX-License-Identifier: MIT
// OphirPay webhook signature verification — reference implementation (Go)
//
// Signed material (must match `buildSignedPayload` in `src/lib/webhook-deliver.ts`):
//
//   `<timestamp>.<canonicalBody>`
//
//   1. Take the timestamp: the `X-OphirPay-Timestamp` header value, falling
//      back to the (also-signed) `timestamp` field of the body when absent.
//   2. Parse the received JSON body.
//   3. Set the `signature` field to "" — keep the key, empty the value.
//      (Do NOT delete the key; the canonical string contains `"signature":""`.)
//   4. Re-serialize with stable key order: `{"event":...,"timestamp":...,"data":...,"signature":""}`.
//   5. Compute HMAC-SHA256 (hex) over `<timestamp>.<canonicalBody>` using your webhook secret.
//   6. Compare against the `X-OphirPay-Signature` header with a constant-time comparison.
//   7. Reject a timestamp outside the freshness window (replay protection).

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"time"
)

const defaultMaxAgeSeconds = 300 // replay-protection window

// Payload defines the webhook body structure preserving key order.
type Payload struct {
	Event     string          `json:"event"`
	Timestamp string          `json:"timestamp"`
	Data      json.RawMessage `json:"data"`
	Test      *bool           `json:"test,omitempty"`
	Signature string          `json:"signature"`
}

// Canonicalize builds the canonical string for signature calculation.
func Canonicalize(body []byte) (string, string, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return "", "", fmt.Errorf("body must be a JSON object: %w", err)
	}

	var p Payload
	if err := json.Unmarshal(body, &p); err != nil {
		return "", "", fmt.Errorf("invalid body: %w", err)
	}

	p.Signature = ""
	canonicalBytes, err := json.Marshal(p)
	if err != nil {
		return "", "", fmt.Errorf("canonicalization failed: %w", err)
	}

	return string(canonicalBytes), p.Timestamp, nil
}

// VerifyWebhookSignature verifies an OphirPay webhook delivery.
func VerifyWebhookSignature(body []byte, signature, secret, timestamp string, maxAgeSeconds int, now time.Time) (bool, string) {
	canonical, bodyTimestamp, err := Canonicalize(body)
	if err != nil {
		return false, err.Error()
	}

	signedTimestamp := timestamp
	if signedTimestamp == "" {
		signedTimestamp = bodyTimestamp
	}

	signedInput := fmt.Sprintf("%s.%s", signedTimestamp, canonical)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signedInput))
	expected := hex.EncodeToString(mac.Sum(nil))

	providedBytes := []byte(strings.TrimSpace(signature))
	expectedBytes := []byte(expected)

	if subtle.ConstantTimeCompare(providedBytes, expectedBytes) != 1 {
		return false, "signature mismatch"
	}

	if maxAgeSeconds > 0 {
		ts, err := time.Parse(time.RFC3339, signedTimestamp)
		if err != nil {
			ts, err = time.Parse("2006-01-02T15:04:05Z07:00", signedTimestamp)
			if err != nil {
				return false, "missing or invalid timestamp"
			}
		}

		ageSeconds := now.Sub(ts).Seconds()
		if ageSeconds > float64(maxAgeSeconds) {
			return false, fmt.Sprintf("payload too old (%ds > %ds) — possible replay", int(math.Round(ageSeconds)), maxAgeSeconds)
		}
		if ageSeconds < -float64(maxAgeSeconds) {
			return false, fmt.Sprintf("payload timestamp is in the future (%ds ahead)", int(math.Round(-ageSeconds)))
		}
	}

	return true, "valid"
}

func main() {
	secret := flag.String("secret", "", "your webhook signing secret")
	signature := flag.String("signature", "", "value of the X-OphirPay-Signature header")
	timestamp := flag.String("timestamp", "", "value of the X-OphirPay-Timestamp header")
	bodyFile := flag.String("body-file", "", "path to the received JSON body")
	maxAge := flag.Int("max-age", defaultMaxAgeSeconds, "replay window in seconds (0 disables)")
	nowStr := flag.String("now", "", "reference timestamp (ISO 8601); defaults to current time")

	flag.Parse()

	if *secret == "" || *signature == "" {
		fmt.Fprintln(os.Stderr, "usage: go run verify.go --secret <secret> --signature <hex> [--timestamp <iso>] [--body-file <path>] [--max-age <seconds>] [--now <iso>]")
		os.Exit(2)
	}

	var body []byte
	var err error
	if *bodyFile != "" {
		body, err = os.ReadFile(*bodyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "INVALID: failed to read body-file: %v\n", err)
			os.Exit(1)
		}
	} else {
		body, err = io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "INVALID: failed to read stdin: %v\n", err)
			os.Exit(1)
		}
	}

	now := time.Now().UTC()
	if *nowStr != "" {
		parsedNow, err := time.Parse(time.RFC3339, *nowStr)
		if err != nil {
			parsedNow, err = time.Parse("2006-01-02T15:04:05Z07:00", *nowStr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "INVALID: invalid --now timestamp: %v\n", err)
				os.Exit(2)
			}
		}
		now = parsedNow
	}

	valid, reason := VerifyWebhookSignature(body, *signature, *secret, *timestamp, *maxAge, now)
	if valid {
		fmt.Println("VALID")
		os.Exit(0)
	}

	fmt.Fprintf(os.Stderr, "INVALID: %s\n", reason)
	os.Exit(1)
}

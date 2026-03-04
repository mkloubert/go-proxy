// Copyright © 2026 Marcel Joachim Kloubert <marcel@kloubert.dev>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

package crypto

import (
	"encoding/base64"
	"testing"
)

func testSecretFromBytes(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func TestHTTPHandshake_Roundtrip(t *testing.T) {
	secret := testSecretFromBytes(make([]byte, 32)) // 32 zero bytes

	// Client generates handshake payload
	payload, challengePlain, keys, err := ClientHandshakePayload(secret)
	if err != nil {
		t.Fatalf("ClientHandshakePayload failed: %v", err)
	}

	if len(payload) == 0 {
		t.Fatal("expected non-empty payload")
	}
	if len(challengePlain) != challengeSize {
		t.Fatalf("expected challenge of size %d, got %d", challengeSize, len(challengePlain))
	}
	if keys == nil {
		t.Fatal("expected non-nil keys")
	}

	// Server processes the payload and generates a response
	response, serverKeys, err := ServerHandshakePayload(payload, secret)
	if err != nil {
		t.Fatalf("ServerHandshakePayload failed: %v", err)
	}

	if len(response) == 0 {
		t.Fatal("expected non-empty response")
	}
	if serverKeys == nil {
		t.Fatal("expected non-nil server keys")
	}

	// Client verifies the server's response
	if err := ClientVerifyHandshake(response, challengePlain, keys); err != nil {
		t.Fatalf("ClientVerifyHandshake failed: %v", err)
	}
}

func TestHTTPHandshake_WrongSecret(t *testing.T) {
	secretA := testSecretFromBytes(make([]byte, 32)) // 32 zero bytes

	differentBytes := make([]byte, 32)
	differentBytes[0] = 0xFF // ensure it differs from secretA
	secretB := testSecretFromBytes(differentBytes)

	// Client generates handshake payload with secretA
	payload, _, _, err := ClientHandshakePayload(secretA)
	if err != nil {
		t.Fatalf("ClientHandshakePayload failed: %v", err)
	}

	// Server tries to process with secretB — should fail during decryption
	_, _, err = ServerHandshakePayload(payload, secretB)
	if err == nil {
		t.Fatal("expected ServerHandshakePayload to fail with wrong secret, but it succeeded")
	}
}

func TestHTTPHandshake_TamperedResponse(t *testing.T) {
	secret := testSecretFromBytes(make([]byte, 32))

	// Complete a successful handshake up to the server response
	payload, challengePlain, keys, err := ClientHandshakePayload(secret)
	if err != nil {
		t.Fatalf("ClientHandshakePayload failed: %v", err)
	}

	response, _, err := ServerHandshakePayload(payload, secret)
	if err != nil {
		t.Fatalf("ServerHandshakePayload failed: %v", err)
	}

	// Tamper with the response by flipping a byte
	if len(response) == 0 {
		t.Fatal("response is empty, cannot tamper")
	}
	tampered := make([]byte, len(response))
	copy(tampered, response)
	tampered[0] ^= 0xFF

	// Client verification should fail
	if err := ClientVerifyHandshake(tampered, challengePlain, keys); err == nil {
		t.Fatal("expected ClientVerifyHandshake to fail with tampered response, but it succeeded")
	}
}

func TestHTTPHandshake_TruncatedPayload(t *testing.T) {
	secret := testSecretFromBytes(make([]byte, 32))

	// Send only 10 bytes — way too short (needs at least 32 for salt + ciphertext)
	truncatedPayload := make([]byte, 10)

	_, _, err := ServerHandshakePayload(truncatedPayload, secret)
	if err == nil {
		t.Fatal("expected ServerHandshakePayload to fail with truncated payload, but it succeeded")
	}
}

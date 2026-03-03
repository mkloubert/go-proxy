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
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func generateTestSecret(t *testing.T) string {
	t.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("failed to generate test secret: %v", err)
	}
	return base64.StdEncoding.EncodeToString(secret)
}

func generateTestSalt(t *testing.T) []byte {
	t.Helper()
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("failed to generate test salt: %v", err)
	}
	return salt
}

func TestDeriveKeys(t *testing.T) {
	secret := generateTestSecret(t)
	salt := generateTestSalt(t)

	keys, err := DeriveKeys(secret, salt)
	if err != nil {
		t.Fatalf("DeriveKeys returned error: %v", err)
	}

	if len(keys.EncryptionKey) != EncryptionKeySize {
		t.Errorf("expected encryption key size %d, got %d", EncryptionKeySize, len(keys.EncryptionKey))
	}

	if len(keys.NoncePrefix) != NoncePrefixSize {
		t.Errorf("expected nonce prefix size %d, got %d", NoncePrefixSize, len(keys.NoncePrefix))
	}
}

func TestDeriveKeysDeterministic(t *testing.T) {
	secret := generateTestSecret(t)
	salt := generateTestSalt(t)

	keys1, err := DeriveKeys(secret, salt)
	if err != nil {
		t.Fatalf("first DeriveKeys call returned error: %v", err)
	}

	keys2, err := DeriveKeys(secret, salt)
	if err != nil {
		t.Fatalf("second DeriveKeys call returned error: %v", err)
	}

	if !bytes.Equal(keys1.EncryptionKey, keys2.EncryptionKey) {
		t.Error("encryption keys differ for same inputs")
	}

	if !bytes.Equal(keys1.NoncePrefix, keys2.NoncePrefix) {
		t.Error("nonce prefixes differ for same inputs")
	}
}

func TestDeriveKeysInvalidBase64(t *testing.T) {
	salt := generateTestSalt(t)

	_, err := DeriveKeys("not-valid-base64!!!", salt)
	if err == nil {
		t.Error("expected error for invalid base64, got nil")
	}
}

func TestDeriveKeysDifferentSalt(t *testing.T) {
	secret := generateTestSecret(t)
	salt1 := generateTestSalt(t)
	salt2 := generateTestSalt(t)

	// Ensure salts are actually different
	if bytes.Equal(salt1, salt2) {
		t.Fatal("generated salts are identical, test is invalid")
	}

	keys1, err := DeriveKeys(secret, salt1)
	if err != nil {
		t.Fatalf("first DeriveKeys call returned error: %v", err)
	}

	keys2, err := DeriveKeys(secret, salt2)
	if err != nil {
		t.Fatalf("second DeriveKeys call returned error: %v", err)
	}

	if bytes.Equal(keys1.EncryptionKey, keys2.EncryptionKey) {
		t.Error("encryption keys should differ for different salts")
	}

	if bytes.Equal(keys1.NoncePrefix, keys2.NoncePrefix) {
		t.Error("nonce prefixes should differ for different salts")
	}
}

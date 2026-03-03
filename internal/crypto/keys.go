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
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
)

const (
	// EncryptionKeySize is the size of the AES-256 encryption key in bytes.
	EncryptionKeySize = 32

	// NoncePrefixSize is the size of the nonce prefix in bytes.
	NoncePrefixSize = 4

	// SaltSize is the size of the salt in bytes.
	SaltSize = 32

	// tunnelSecretEnvVar is the environment variable name for the tunnel secret.
	tunnelSecretEnvVar = "GOPROXY_TUNNEL_SECRET"
)

// DerivedKeys holds the encryption key and nonce prefix derived from a shared secret.
type DerivedKeys struct {
	EncryptionKey []byte
	NoncePrefix   []byte
}

// DeriveKeys derives an encryption key and nonce prefix from a base64-encoded
// secret and a salt using HKDF with SHA-256.
func DeriveKeys(secretBase64 string, salt []byte) (*DerivedKeys, error) {
	secret, err := base64.StdEncoding.DecodeString(secretBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 secret: %w", err)
	}

	encryptionKey, err := hkdf.Key(sha256.New, secret, salt, "go-proxy-encryption-key", EncryptionKeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}

	noncePrefix, err := hkdf.Key(sha256.New, secret, salt, "go-proxy-nonce-prefix", NoncePrefixSize)
	if err != nil {
		return nil, fmt.Errorf("failed to derive nonce prefix: %w", err)
	}

	return &DerivedKeys{
		EncryptionKey: encryptionKey,
		NoncePrefix:   noncePrefix,
	}, nil
}

// LoadSecret reads the tunnel secret from the GOPROXY_TUNNEL_SECRET environment
// variable and validates that it is valid base64.
func LoadSecret() (string, error) {
	secret := os.Getenv(tunnelSecretEnvVar)
	if secret == "" {
		return "", errors.New("environment variable GOPROXY_TUNNEL_SECRET is not set or empty")
	}

	if _, err := base64.StdEncoding.DecodeString(secret); err != nil {
		return "", fmt.Errorf("GOPROXY_TUNNEL_SECRET contains invalid base64: %w", err)
	}

	return secret, nil
}

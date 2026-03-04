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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
)

const (
	// challengeSize is the size of the handshake challenge in bytes.
	challengeSize = 32
)

// ClientHandshake performs the client side of the tunnel handshake.
//
// The client proves knowledge of the shared secret first, so the server
// never sends data to unauthenticated connections (blackhole behavior).
//
// Protocol:
//  1. Generate 32 random bytes (salt) and send them over the raw connection.
//  2. Derive encryption keys from the shared secret and salt.
//  3. Wrap the connection with EncryptedConn.
//  4. Generate a 32-byte random challenge and send it (encrypted) to the server.
//  5. Read the server's echo response (encrypted).
//  6. Verify the response matches the challenge using constant-time comparison.
//  7. Return the encrypted connection.
func ClientHandshake(conn net.Conn, secretBase64 string) (net.Conn, error) {
	// Step 1: Generate and send salt
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	if _, err := conn.Write(salt); err != nil {
		return nil, fmt.Errorf("failed to send salt: %w", err)
	}

	// Step 2: Derive keys
	keys, err := DeriveKeys(secretBase64, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to derive keys: %w", err)
	}

	// Step 3: Create encrypted connection (client writes with ClientNoncePrefix)
	encConn, err := NewEncryptedConn(conn, keys.EncryptionKey, keys.ClientNoncePrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to create encrypted connection: %w", err)
	}

	// Step 4: Generate and send challenge (client proves knowledge first)
	challenge := make([]byte, challengeSize)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}

	if _, err := encConn.Write(challenge); err != nil {
		return nil, fmt.Errorf("failed to send challenge: %w", err)
	}

	// Step 5: Read response from server
	response := make([]byte, challengeSize)
	if _, err := io.ReadFull(encConn, response); err != nil {
		return nil, fmt.Errorf("failed to read challenge response: %w", err)
	}

	// Step 6: Verify response using constant-time comparison
	if subtle.ConstantTimeCompare(challenge, response) != 1 {
		return nil, errors.New("handshake failed: challenge response mismatch")
	}

	// Step 7: Return encrypted connection
	return encConn, nil
}

// ServerHandshake performs the server side of the tunnel handshake.
//
// The server never sends data until the client has proven knowledge of the
// shared secret. If decryption of the client's challenge fails, the connection
// is closed immediately without any response — the port appears dead to
// unauthorized clients.
//
// Protocol:
//  1. Read 32-byte salt from the raw connection.
//  2. Derive encryption keys from the shared secret and salt.
//  3. Wrap the connection with EncryptedConn.
//  4. Read the client's encrypted challenge. If decryption fails, the client
//     does not know the secret — return error immediately (zero bytes sent).
//  5. Echo the challenge back (encrypted) to prove server also knows the secret.
//  6. Return the encrypted connection.
func ServerHandshake(conn net.Conn, secretBase64 string) (net.Conn, error) {
	// Step 1: Read salt
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(conn, salt); err != nil {
		return nil, fmt.Errorf("failed to read salt: %w", err)
	}

	// Step 2: Derive keys
	keys, err := DeriveKeys(secretBase64, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to derive keys: %w", err)
	}

	// Step 3: Create encrypted connection (server writes with ServerNoncePrefix)
	encConn, err := NewEncryptedConn(conn, keys.EncryptionKey, keys.ServerNoncePrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to create encrypted connection: %w", err)
	}

	// Step 4: Read challenge from client (AES-GCM decryption validates the secret)
	challenge := make([]byte, challengeSize)
	if _, err := io.ReadFull(encConn, challenge); err != nil {
		// Decryption failed = client does not know the secret.
		// Return error immediately — zero bytes were sent (blackhole).
		return nil, fmt.Errorf("failed to read client challenge: %w", err)
	}

	// Step 5: Echo challenge back (proves server also knows the secret)
	if _, err := encConn.Write(challenge); err != nil {
		return nil, fmt.Errorf("failed to send challenge response: %w", err)
	}

	// Step 6: Return encrypted connection
	return encConn, nil
}

// buildNonce constructs a 12-byte AES-GCM nonce from a 4-byte prefix
// followed by 8 zero bytes.
func buildNonce(prefix []byte) []byte {
	nonce := make([]byte, 12)
	copy(nonce, prefix)
	return nonce
}

// newGCM creates an AES-256-GCM cipher from the given 32-byte key.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	return gcm, nil
}

// ClientHandshakePayload generates the client-side handshake payload for
// HTTP-based tunneling. Unlike ClientHandshake, this function does not
// operate on a streaming connection but returns discrete byte slices
// suitable for embedding in HTTP request/response bodies.
//
// Returns:
//   - payload: salt(32) || encryptedChallenge (including GCM auth tag)
//   - challengePlain: the original 32-byte challenge for later verification
//   - keys: the derived keys for subsequent operations
func ClientHandshakePayload(secretBase64 string) (payload []byte, challengePlain []byte, keys *DerivedKeys, err error) {
	// Generate random salt
	salt := make([]byte, SaltSize)
	if _, err = rand.Read(salt); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive keys from shared secret and salt
	keys, err = DeriveKeys(secretBase64, salt)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to derive keys: %w", err)
	}

	// Create AES-256-GCM cipher
	gcm, err := newGCM(keys.EncryptionKey)
	if err != nil {
		return nil, nil, nil, err
	}

	// Generate random challenge
	challengePlain = make([]byte, challengeSize)
	if _, err = rand.Read(challengePlain); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate challenge: %w", err)
	}

	// Encrypt challenge using client nonce prefix + 8 zero bytes
	nonce := buildNonce(keys.ClientNoncePrefix)
	encryptedChallenge := gcm.Seal(nil, nonce, challengePlain, nil)

	// Build payload: salt || encryptedChallenge
	payload = make([]byte, 0, SaltSize+len(encryptedChallenge))
	payload = append(payload, salt...)
	payload = append(payload, encryptedChallenge...)

	return payload, challengePlain, keys, nil
}

// ServerHandshakePayload processes the client's handshake payload and
// produces a response for HTTP-based tunneling. It decrypts the client's
// challenge to verify the shared secret, then re-encrypts it with the
// server nonce to prove the server also knows the secret.
//
// Returns:
//   - response: the re-encrypted challenge (including GCM auth tag)
//   - keys: the derived keys for subsequent operations
func ServerHandshakePayload(payload []byte, secretBase64 string) (response []byte, keys *DerivedKeys, err error) {
	// Validate minimum payload size: salt + at least 1 byte of ciphertext + GCM tag
	if len(payload) <= SaltSize {
		return nil, nil, errors.New("handshake payload too short")
	}

	// Split payload into salt and encrypted challenge
	salt := payload[:SaltSize]
	encryptedChallenge := payload[SaltSize:]

	// Derive keys from shared secret and salt
	keys, err = DeriveKeys(secretBase64, salt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive keys: %w", err)
	}

	// Create AES-256-GCM cipher
	gcm, err := newGCM(keys.EncryptionKey)
	if err != nil {
		return nil, nil, err
	}

	// Decrypt challenge using client nonce
	clientNonce := buildNonce(keys.ClientNoncePrefix)
	challengePlain, err := gcm.Open(nil, clientNonce, encryptedChallenge, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt challenge: %w", err)
	}

	// Re-encrypt challenge using server nonce to prove knowledge of secret
	serverNonce := buildNonce(keys.ServerNoncePrefix)
	response = gcm.Seal(nil, serverNonce, challengePlain, nil)

	return response, keys, nil
}

// ClientVerifyHandshake verifies the server's handshake response for
// HTTP-based tunneling. It decrypts the server's response and compares
// it with the original challenge using constant-time comparison.
func ClientVerifyHandshake(response []byte, challengePlain []byte, keys *DerivedKeys) error {
	// Create AES-256-GCM cipher
	gcm, err := newGCM(keys.EncryptionKey)
	if err != nil {
		return err
	}

	// Decrypt response using server nonce
	serverNonce := buildNonce(keys.ServerNoncePrefix)
	decrypted, err := gcm.Open(nil, serverNonce, response, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt handshake response: %w", err)
	}

	// Constant-time comparison
	if subtle.ConstantTimeCompare(decrypted, challengePlain) != 1 {
		return errors.New("handshake verification failed: challenge mismatch")
	}

	return nil
}

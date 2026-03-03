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
// Protocol:
//  1. Generate 32 random bytes (salt) and send them over the raw connection.
//  2. Derive encryption keys from the shared secret and salt.
//  3. Wrap the connection with EncryptedConn.
//  4. Read a 32-byte challenge from the server (over encrypted conn).
//  5. Echo the challenge back (over encrypted conn).
//  6. Return the encrypted connection.
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

	// Step 3: Create encrypted connection
	encConn, err := NewEncryptedConn(conn, keys.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create encrypted connection: %w", err)
	}

	// Step 4: Read challenge from server
	challenge := make([]byte, challengeSize)
	if _, err := io.ReadFull(encConn, challenge); err != nil {
		return nil, fmt.Errorf("failed to read challenge: %w", err)
	}

	// Step 5: Echo challenge back
	if _, err := encConn.Write(challenge); err != nil {
		return nil, fmt.Errorf("failed to send challenge response: %w", err)
	}

	// Step 6: Return encrypted connection
	return encConn, nil
}

// ServerHandshake performs the server side of the tunnel handshake.
//
// Protocol:
//  1. Read 32-byte salt from the raw connection.
//  2. Derive encryption keys from the shared secret and salt.
//  3. Wrap the connection with EncryptedConn.
//  4. Generate a 32-byte random challenge and send it (over encrypted conn).
//  5. Read the response (over encrypted conn).
//  6. Verify the response matches the challenge using constant-time comparison.
//  7. Return the encrypted connection (or error if mismatch).
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

	// Step 3: Create encrypted connection
	encConn, err := NewEncryptedConn(conn, keys.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create encrypted connection: %w", err)
	}

	// Step 4: Generate and send challenge
	challenge := make([]byte, challengeSize)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}

	if _, err := encConn.Write(challenge); err != nil {
		return nil, fmt.Errorf("failed to send challenge: %w", err)
	}

	// Step 5: Read response
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

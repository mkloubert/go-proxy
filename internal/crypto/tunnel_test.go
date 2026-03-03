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
	"io"
	"net"
	"testing"
)

// createEncryptedPipe creates a pair of EncryptedConn instances connected via
// net.Pipe, using the same derived keys (simulating both ends sharing a secret).
func createEncryptedPipe(t *testing.T) (*EncryptedConn, *EncryptedConn) {
	t.Helper()

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("failed to generate secret: %v", err)
	}
	secretB64 := base64.StdEncoding.EncodeToString(secret)

	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("failed to generate salt: %v", err)
	}

	keys, err := DeriveKeys(secretB64, salt)
	if err != nil {
		t.Fatalf("failed to derive keys: %v", err)
	}

	connA, connB := net.Pipe()

	encA, err := NewEncryptedConn(connA, keys.EncryptionKey)
	if err != nil {
		t.Fatalf("failed to create EncryptedConn A: %v", err)
	}

	encB, err := NewEncryptedConn(connB, keys.EncryptionKey)
	if err != nil {
		t.Fatalf("failed to create EncryptedConn B: %v", err)
	}

	return encA, encB
}

func TestEncryptedConnRoundtrip(t *testing.T) {
	encA, encB := createEncryptedPipe(t)
	defer encA.Close()
	defer encB.Close()

	message := []byte("Hello, encrypted world!")

	// Write from A, read from B
	errCh := make(chan error, 1)
	go func() {
		_, err := encA.Write(message)
		errCh <- err
	}()

	buf := make([]byte, 1024)
	n, err := encB.Read(buf)
	if err != nil {
		t.Fatalf("Read returned error: %v", err)
	}

	if writeErr := <-errCh; writeErr != nil {
		t.Fatalf("Write returned error: %v", writeErr)
	}

	if !bytes.Equal(buf[:n], message) {
		t.Errorf("expected %q, got %q", message, buf[:n])
	}
}

func TestEncryptedConnLargePayload(t *testing.T) {
	encA, encB := createEncryptedPipe(t)
	defer encA.Close()
	defer encB.Close()

	// Create a 60000-byte payload
	payload := make([]byte, 60000)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("failed to generate payload: %v", err)
	}

	// Write from A in a goroutine
	errCh := make(chan error, 1)
	go func() {
		_, err := encA.Write(payload)
		errCh <- err
	}()

	// Read all data from B
	received := make([]byte, 0, len(payload))
	buf := make([]byte, 4096)
	for len(received) < len(payload) {
		n, err := encB.Read(buf)
		if err != nil {
			t.Fatalf("Read returned error after %d bytes: %v", len(received), err)
		}
		received = append(received, buf[:n]...)
	}

	if writeErr := <-errCh; writeErr != nil {
		t.Fatalf("Write returned error: %v", writeErr)
	}

	if !bytes.Equal(received, payload) {
		t.Error("received payload does not match sent payload")
	}
}

func TestEncryptedConnWrongKey(t *testing.T) {
	// Create two different keys
	keyA := make([]byte, EncryptionKeySize)
	keyB := make([]byte, EncryptionKeySize)
	if _, err := rand.Read(keyA); err != nil {
		t.Fatalf("failed to generate key A: %v", err)
	}
	if _, err := rand.Read(keyB); err != nil {
		t.Fatalf("failed to generate key B: %v", err)
	}

	connA, connB := net.Pipe()

	encA, err := NewEncryptedConn(connA, keyA)
	if err != nil {
		t.Fatalf("failed to create EncryptedConn A: %v", err)
	}
	defer encA.Close()

	encB, err := NewEncryptedConn(connB, keyB)
	if err != nil {
		t.Fatalf("failed to create EncryptedConn B: %v", err)
	}
	defer encB.Close()

	// Write from A
	go func() {
		encA.Write([]byte("secret message"))
	}()

	// Read from B should fail because keys don't match
	buf := make([]byte, 1024)
	_, err = encB.Read(buf)
	if err == nil {
		t.Error("expected decryption error with wrong key, got nil")
	}
}

func TestEncryptedConnMultipleMessages(t *testing.T) {
	encA, encB := createEncryptedPipe(t)
	defer encA.Close()
	defer encB.Close()

	messages := []string{
		"first message",
		"second message",
		"third message with more data",
	}

	// Send and receive each message sequentially
	for i, msg := range messages {
		errCh := make(chan error, 1)
		go func() {
			_, err := encA.Write([]byte(msg))
			errCh <- err
		}()

		buf := make([]byte, 1024)
		n, err := encB.Read(buf)
		if err != nil {
			t.Fatalf("message %d: Read returned error: %v", i, err)
		}

		if writeErr := <-errCh; writeErr != nil {
			t.Fatalf("message %d: Write returned error: %v", i, writeErr)
		}

		if string(buf[:n]) != msg {
			t.Errorf("message %d: expected %q, got %q", i, msg, string(buf[:n]))
		}
	}

	// Also test sending from B to A
	reply := []byte("reply from B")
	errCh := make(chan error, 1)
	go func() {
		_, err := encB.Write(reply)
		errCh <- err
	}()

	buf := make([]byte, 1024)
	n, err := encA.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("Read reply returned error: %v", err)
	}

	if writeErr := <-errCh; writeErr != nil {
		t.Fatalf("Write reply returned error: %v", writeErr)
	}

	if !bytes.Equal(buf[:n], reply) {
		t.Errorf("expected reply %q, got %q", reply, buf[:n])
	}
}

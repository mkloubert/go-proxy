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
	"net"
	"testing"
)

func generateTestSecretB64(t *testing.T) string {
	t.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("failed to generate secret: %v", err)
	}
	return base64.StdEncoding.EncodeToString(secret)
}

func TestHandshakeSuccess(t *testing.T) {
	secret := generateTestSecretB64(t)

	clientConn, serverConn := net.Pipe()

	var clientEncConn net.Conn
	var serverEncConn net.Conn
	clientErr := make(chan error, 1)
	serverErr := make(chan error, 1)

	go func() {
		var err error
		clientEncConn, err = ClientHandshake(clientConn, secret)
		clientErr <- err
	}()

	go func() {
		var err error
		serverEncConn, err = ServerHandshake(serverConn, secret)
		serverErr <- err
	}()

	if err := <-clientErr; err != nil {
		t.Fatalf("ClientHandshake failed: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("ServerHandshake failed: %v", err)
	}

	defer clientEncConn.Close()
	defer serverEncConn.Close()

	// Verify both sides got EncryptedConn
	if _, ok := clientEncConn.(*EncryptedConn); !ok {
		t.Error("client did not receive an EncryptedConn")
	}
	if _, ok := serverEncConn.(*EncryptedConn); !ok {
		t.Error("server did not receive an EncryptedConn")
	}
}

func TestHandshakeWrongSecret(t *testing.T) {
	clientSecret := generateTestSecretB64(t)
	serverSecret := generateTestSecretB64(t)

	clientConn, serverConn := net.Pipe()

	clientErr := make(chan error, 1)
	serverErr := make(chan error, 1)

	go func() {
		_, err := ClientHandshake(clientConn, clientSecret)
		if err != nil {
			// Close the underlying connection so the other side unblocks
			clientConn.Close()
		}
		clientErr <- err
	}()

	go func() {
		_, err := ServerHandshake(serverConn, serverSecret)
		if err != nil {
			// Close the underlying connection so the other side unblocks
			serverConn.Close()
		}
		serverErr <- err
	}()

	// At least one side should fail
	cErr := <-clientErr
	sErr := <-serverErr

	if cErr == nil && sErr == nil {
		t.Error("expected at least one side to fail with mismatched secrets")
	}
}

func TestHandshakeDataAfterHandshake(t *testing.T) {
	secret := generateTestSecretB64(t)

	clientConn, serverConn := net.Pipe()

	var clientEncConn net.Conn
	var serverEncConn net.Conn
	clientErr := make(chan error, 1)
	serverErr := make(chan error, 1)

	go func() {
		var err error
		clientEncConn, err = ClientHandshake(clientConn, secret)
		clientErr <- err
	}()

	go func() {
		var err error
		serverEncConn, err = ServerHandshake(serverConn, secret)
		serverErr <- err
	}()

	if err := <-clientErr; err != nil {
		t.Fatalf("ClientHandshake failed: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("ServerHandshake failed: %v", err)
	}

	defer clientEncConn.Close()
	defer serverEncConn.Close()

	// Send data from client to server
	clientMsg := []byte("Hello from client after handshake!")
	writeErr := make(chan error, 1)
	go func() {
		_, err := clientEncConn.Write(clientMsg)
		writeErr <- err
	}()

	buf := make([]byte, 1024)
	n, err := serverEncConn.Read(buf)
	if err != nil {
		t.Fatalf("server Read failed: %v", err)
	}
	if wErr := <-writeErr; wErr != nil {
		t.Fatalf("client Write failed: %v", wErr)
	}
	if !bytes.Equal(buf[:n], clientMsg) {
		t.Errorf("expected %q, got %q", clientMsg, buf[:n])
	}

	// Send data from server to client
	serverMsg := []byte("Hello from server after handshake!")
	go func() {
		_, err := serverEncConn.Write(serverMsg)
		writeErr <- err
	}()

	n, err = clientEncConn.Read(buf)
	if err != nil {
		t.Fatalf("client Read failed: %v", err)
	}
	if wErr := <-writeErr; wErr != nil {
		t.Fatalf("server Write failed: %v", wErr)
	}
	if !bytes.Equal(buf[:n], serverMsg) {
		t.Errorf("expected %q, got %q", serverMsg, buf[:n])
	}
}

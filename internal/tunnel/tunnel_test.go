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

package tunnel

import (
	"bytes"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// makeTestSecret generates a valid base64-encoded 32-byte secret for testing.
func makeTestSecret(seed byte) string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(key)
}

// startEchoServer starts a TCP echo server that echoes all received data
// back to the sender. It returns the listener and a cleanup function.
func startEchoServer(t *testing.T) (net.Listener, func()) {
	t.Helper()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start echo server: %v", err)
	}

	var wg sync.WaitGroup

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	cleanup := func() {
		ln.Close()
		wg.Wait()
	}

	return ln, cleanup
}

// startTunnelHTTPServer starts a tunnel server as an HTTP test server
// with the given secret. It returns the httptest.Server and a cleanup function.
func startTunnelHTTPServer(t *testing.T, secret string) (*httptest.Server, func()) {
	t.Helper()

	srv := NewServer(secret)
	srv.SetAllowPrivateIPs(true)

	ts := httptest.NewServer(srv.Handler())

	cleanup := func() {
		srv.Close()
		ts.Close()
	}

	return ts, cleanup
}

// startTunnelHTTPServerRaw starts a tunnel server and returns it along
// with its HTTP test server for more fine-grained test control.
func startTunnelHTTPServerRaw(t *testing.T, secret string) (*Server, *httptest.Server, func()) {
	t.Helper()

	srv := NewServer(secret)
	srv.SetAllowPrivateIPs(true)

	ts := httptest.NewServer(srv.Handler())

	cleanup := func() {
		srv.Close()
		ts.Close()
	}

	return srv, ts, cleanup
}

func TestServerHandlerRouting(t *testing.T) {
	secret := makeTestSecret(0xAA)

	srv := NewServer(secret)
	defer srv.Close()

	handler := srv.Handler()

	// Test that GET requests return 405 or similar (method not allowed)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/galleries/test-uuid/pictures", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Go 1.22+ ServeMux returns 405 for wrong method
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for GET, got %d", w.Code)
	}

	// Test that POST to wrong path returns 404
	req = httptest.NewRequest(http.MethodPost, "/api/v1/wrong/path", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for wrong path, got %d", w.Code)
	}
}

func TestServerHandleInvalidPNG(t *testing.T) {
	secret := makeTestSecret(0xBB)

	srv := NewServer(secret)
	defer srv.Close()

	handler := srv.Handler()

	// Send invalid PNG data — should return 404 (stego.Extract fails)
	garbage := []byte("this is not a valid PNG file")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/galleries/test-uuid/pictures", bytes.NewReader(garbage))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Invalid PNG will fail stego.Extract
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for invalid PNG, got %d", w.Code)
	}
}

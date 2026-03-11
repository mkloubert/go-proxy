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

	ts := httptest.NewServer(srv.Handler("/ws"))

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

	ts := httptest.NewServer(srv.Handler("/ws"))

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

	handler := srv.Handler("/ws")

	// Test that GET request to /ws returns non-404 (WebSocket upgrade fails
	// gracefully but the route exists)
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// WebSocket upgrade will fail in a non-WebSocket context, but route exists.
	// The handler should not return 404 for the correct path.
	if w.Code == http.StatusNotFound {
		t.Fatal("expected /ws route to exist")
	}

	// Test that request to wrong path returns 404
	req = httptest.NewRequest(http.MethodGet, "/api/v1/wrong/path", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for wrong path, got %d", w.Code)
	}
}

func TestNormalizeWSURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com:9876", "ws://example.com:9876"},
		{"ws://example.com:9876", "ws://example.com:9876"},
		{"wss://example.com:9876", "wss://example.com:9876"},
		{"http://example.com:80", "ws://example.com:80"},
		{"https://example.com:443", "wss://example.com:443"},
		{"http://example.com:80/", "ws://example.com:80"},
		{"example.com:9876/", "ws://example.com:9876"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeWSURL(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeWSURL(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

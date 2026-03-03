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

package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	xproxy "golang.org/x/net/proxy"
)

// startEchoServer starts a TCP server that echoes back anything it receives.
// Returns the listener and its address.
func startEchoServer(t *testing.T) (net.Listener, string) {
	t.Helper()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start echo server: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	return ln, ln.Addr().String()
}

// startHTTPServer starts a simple HTTP server that responds with "hello".
// Returns the test server and its address (host:port).
func startHTTPServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "hello")
	}))

	// Extract host:port from the server URL
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL: %v", err)
	}

	return srv, u.Host
}

func TestHTTPProxyCONNECT(t *testing.T) {
	// Start an echo TCP server
	echoLn, echoAddr := startEchoServer(t)
	defer echoLn.Close()

	// Create HTTPProxy with dial func that connects to the echo server
	proxy := NewHTTPProxy(func(target string) (net.Conn, error) {
		return net.Dial("tcp4", echoAddr)
	})

	// Start an HTTP server with the proxy as handler
	proxyLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for proxy: %v", err)
	}
	defer proxyLn.Close()

	proxyAddr := proxyLn.Addr().String()

	go http.Serve(proxyLn, proxy) //nolint:errcheck

	// Connect to the proxy and send a CONNECT request
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	// Send CONNECT request
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echoAddr, echoAddr)
	_, err = conn.Write([]byte(connectReq))
	if err != nil {
		t.Fatalf("failed to write CONNECT request: %v", err)
	}

	// Read the CONNECT response status line manually.
	// We cannot use http.ReadResponse because it tries to read a body
	// for CONNECT 200 responses, which would block on the tunneled stream.
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read status line: %v", err)
	}

	if !strings.Contains(statusLine, "200") {
		t.Fatalf("expected 200 in status line, got %q", statusLine)
	}

	// Read remaining headers until blank line
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("failed to read header line: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	// Now the connection is tunneled - send data and verify echo
	testData := "hello tunnel"
	_, err = conn.Write([]byte(testData))
	if err != nil {
		t.Fatalf("failed to write test data: %v", err)
	}

	buf := make([]byte, len(testData))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadFull(br, buf)
	if err != nil {
		t.Fatalf("failed to read echo response: %v", err)
	}

	if string(buf) != testData {
		t.Fatalf("echo mismatch: got %q, want %q", string(buf), testData)
	}
}

func TestHTTPProxyPlainHTTP(t *testing.T) {
	// Start a simple HTTP server
	httpSrv, httpAddr := startHTTPServer(t)
	defer httpSrv.Close()

	// Create HTTPProxy with real net.Dial
	proxy := NewHTTPProxy(func(target string) (net.Conn, error) {
		return net.Dial("tcp4", target)
	})

	// Start the proxy server
	proxyLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for proxy: %v", err)
	}
	defer proxyLn.Close()

	proxyAddr := proxyLn.Addr().String()

	go http.Serve(proxyLn, proxy) //nolint:errcheck

	// Connect to the proxy and send a plain HTTP request through it
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	// Send an absolute-form GET request (as a proxy client would)
	reqStr := fmt.Sprintf("GET http://%s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", httpAddr, httpAddr)
	_, err = conn.Write([]byte(reqStr))
	if err != nil {
		t.Fatalf("failed to write HTTP request: %v", err)
	}

	// Read the response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("failed to read HTTP response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	if string(body) != "hello" {
		t.Fatalf("body mismatch: got %q, want %q", string(body), "hello")
	}
}

func TestProtocolDetectionSOCKS5(t *testing.T) {
	// Start an echo TCP server for the SOCKS5 test to connect to
	echoLn, echoAddr := startEchoServer(t)
	defer echoLn.Close()

	// Create ProxyHandler with real net.Dial
	handler := NewProxyHandler(func(target string) (net.Conn, error) {
		return net.Dial("tcp4", target)
	})

	// Start serving on a random port
	proxyLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for proxy handler: %v", err)
	}
	defer proxyLn.Close()

	proxyAddr := proxyLn.Addr().String()

	go handler.Serve(proxyLn) //nolint:errcheck

	// Use golang.org/x/net/proxy to connect via SOCKS5
	dialer, err := xproxy.SOCKS5("tcp", proxyAddr, nil, xproxy.Direct)
	if err != nil {
		t.Fatalf("failed to create SOCKS5 dialer: %v", err)
	}

	// Dial the echo server through SOCKS5
	conn, err := dialer.Dial("tcp", echoAddr)
	if err != nil {
		t.Fatalf("failed to dial through SOCKS5: %v", err)
	}
	defer conn.Close()

	// Send test data and verify echo
	testData := "socks5 echo test"
	_, err = conn.Write([]byte(testData))
	if err != nil {
		t.Fatalf("failed to write test data through SOCKS5: %v", err)
	}

	buf := make([]byte, len(testData))
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("failed to read echo through SOCKS5: %v", err)
	}

	if string(buf) != testData {
		t.Fatalf("SOCKS5 echo mismatch: got %q, want %q", string(buf), testData)
	}
}

func TestProtocolDetectionHTTP(t *testing.T) {
	// Start a simple HTTP server
	httpSrv, httpAddr := startHTTPServer(t)
	defer httpSrv.Close()

	// Create ProxyHandler with real net.Dial
	handler := NewProxyHandler(func(target string) (net.Conn, error) {
		return net.Dial("tcp4", target)
	})

	// Start serving on a random port
	proxyLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for proxy handler: %v", err)
	}
	defer proxyLn.Close()

	proxyAddr := proxyLn.Addr().String()

	go handler.Serve(proxyLn) //nolint:errcheck

	// Create an HTTP client configured to use the proxy
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("failed to parse proxy URL: %v", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	// Make a request through the proxy
	resp, err := client.Get("http://" + httpAddr + "/")
	if err != nil {
		t.Fatalf("failed to GET through proxy: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	if strings.TrimSpace(string(body)) != "hello" {
		t.Fatalf("body mismatch: got %q, want %q", string(body), "hello")
	}
}

func TestHostWithDefaultPort(t *testing.T) {
	tests := []struct {
		host        string
		defaultPort string
		want        string
	}{
		{"example.com", "80", "example.com:80"},
		{"example.com:8080", "80", "example.com:8080"},
		{"127.0.0.1", "443", "127.0.0.1:443"},
		{"127.0.0.1:9090", "443", "127.0.0.1:9090"},
		{"[::1]", "80", "[::1]:80"},
		{"[::1]:8080", "80", "[::1]:8080"},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := hostWithDefaultPort(tt.host, tt.defaultPort)
			if got != tt.want {
				t.Errorf("hostWithDefaultPort(%q, %q) = %q, want %q", tt.host, tt.defaultPort, got, tt.want)
			}
		})
	}
}

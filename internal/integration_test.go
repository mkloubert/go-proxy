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

package internal

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mkloubert/go-proxy/internal/proxy"
	"github.com/mkloubert/go-proxy/internal/tunnel"
	xproxy "golang.org/x/net/proxy"
)

// testSecret is a base64-encoded 32-byte secret used in integration tests.
var testSecret = base64.StdEncoding.EncodeToString([]byte("my-32-byte-secret-key-for-tests!"))

// startTargetHTTPServer starts a simple HTTP server that responds with
// "hello from target" for any request. Returns the listener and its address.
func startTargetHTTPServer(t *testing.T) (net.Listener, string) {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "hello from target")
	})

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start target HTTP server: %v", err)
	}

	srv := &http.Server{Handler: mux}
	go srv.Serve(ln) //nolint:errcheck

	t.Cleanup(func() {
		srv.Close()
		ln.Close()
	})

	return ln, ln.Addr().String()
}

// startEchoServer starts a TCP echo server that echoes all received data
// back to the sender. Returns the listener and its address.
func startEchoServer(t *testing.T) (net.Listener, string) {
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

	t.Cleanup(func() {
		ln.Close()
		wg.Wait()
	})

	return ln, ln.Addr().String()
}

// startTunnelRemote starts a tunnel server on a random port.
// Returns the listener address.
func startTunnelRemote(t *testing.T, secret string) string {
	t.Helper()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start tunnel server listener: %v", err)
	}

	srv := tunnel.NewServer(secret)
	srv.AllowPrivateIPs = true
	go srv.Serve(ln) //nolint:errcheck

	t.Cleanup(func() {
		srv.Close()
		ln.Close()
	})

	return ln.Addr().String()
}

// startTunnelClient creates a tunnel client, connects it to the remote,
// and returns the client.
func startTunnelClient(t *testing.T, remoteAddr, secret string) *tunnel.Client {
	t.Helper()

	client := tunnel.NewClient(remoteAddr, secret)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("tunnel client connect failed: %v", err)
	}

	t.Cleanup(func() {
		client.Close()
	})

	return client
}

// startLocalProxy starts a local proxy using the given tunnel client.
// Returns the proxy listener address.
func startLocalProxy(t *testing.T, client *tunnel.Client) string {
	t.Helper()

	dial := func(target string) (net.Conn, error) {
		return client.OpenStream(target)
	}

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start local proxy listener: %v", err)
	}

	handler := proxy.NewProxyHandler(dial)
	go handler.Serve(ln) //nolint:errcheck

	t.Cleanup(func() {
		ln.Close()
	})

	return ln.Addr().String()
}

// TestIntegrationHTTPProxy exercises the full path:
// HTTP client -> local proxy -> encrypted tunnel -> remote server -> target HTTP server -> response back.
func TestIntegrationHTTPProxy(t *testing.T) {
	// 1. Start a target HTTP server (simulates the "internet")
	_, targetAddr := startTargetHTTPServer(t)

	// 2. Start tunnel remote server
	tunnelAddr := startTunnelRemote(t, testSecret)

	// 3. Start tunnel client connecting to remote
	client := startTunnelClient(t, tunnelAddr, testSecret)

	// 4. Start local proxy
	proxyAddr := startLocalProxy(t, client)

	// 5. Create http.Client with proxy configured
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("failed to parse proxy URL: %v", err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 10 * time.Second,
	}

	// 6. Make HTTP GET to the target server through the proxy
	resp, err := httpClient.Get("http://" + targetAddr + "/")
	if err != nil {
		t.Fatalf("HTTP GET through proxy failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	// 7. Verify response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	if strings.TrimSpace(string(body)) != "hello from target" {
		t.Fatalf("body mismatch: got %q, want %q", string(body), "hello from target")
	}
}

// TestIntegrationHTTPSConnect tests the CONNECT method for HTTPS tunneling
// through the full encrypted tunnel path.
func TestIntegrationHTTPSConnect(t *testing.T) {
	// 1. Start target TCP echo server
	_, echoAddr := startEchoServer(t)

	// 2. Start tunnel remote + client
	tunnelAddr := startTunnelRemote(t, testSecret)
	client := startTunnelClient(t, tunnelAddr, testSecret)

	// 3. Start local proxy
	proxyAddr := startLocalProxy(t, client)

	// 4. Connect to proxy with CONNECT method (manually)
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	// Send CONNECT request
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echoAddr, echoAddr)
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		t.Fatalf("failed to write CONNECT request: %v", err)
	}

	// Read the CONNECT response
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

	// 5. Send data and verify echo
	testData := "hello through CONNECT tunnel"
	if _, err := conn.Write([]byte(testData)); err != nil {
		t.Fatalf("failed to write test data: %v", err)
	}

	buf := make([]byte, len(testData))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("failed to read echo response: %v", err)
	}

	if string(buf) != testData {
		t.Fatalf("echo mismatch: got %q, want %q", string(buf), testData)
	}
}

// TestIntegrationSOCKS5 tests SOCKS5 through the full encrypted tunnel path.
func TestIntegrationSOCKS5(t *testing.T) {
	// 1. Start target echo server
	_, echoAddr := startEchoServer(t)

	// 2. Start tunnel remote + client
	tunnelAddr := startTunnelRemote(t, testSecret)
	client := startTunnelClient(t, tunnelAddr, testSecret)

	// 3. Start local proxy
	proxyAddr := startLocalProxy(t, client)

	// 4. Connect via SOCKS5
	dialer, err := xproxy.SOCKS5("tcp", proxyAddr, nil, xproxy.Direct)
	if err != nil {
		t.Fatalf("failed to create SOCKS5 dialer: %v", err)
	}

	conn, err := dialer.Dial("tcp", echoAddr)
	if err != nil {
		t.Fatalf("failed to dial through SOCKS5: %v", err)
	}
	defer conn.Close()

	// 5. Send data and verify echo
	testData := "hello through SOCKS5 tunnel"
	if _, err := conn.Write([]byte(testData)); err != nil {
		t.Fatalf("failed to write test data through SOCKS5: %v", err)
	}

	buf := make([]byte, len(testData))
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("failed to read echo through SOCKS5: %v", err)
	}

	if string(buf) != testData {
		t.Fatalf("SOCKS5 echo mismatch: got %q, want %q", string(buf), testData)
	}
}

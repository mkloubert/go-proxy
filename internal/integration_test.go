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
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mkloubert/go-proxy/internal/proxy"
	"github.com/mkloubert/go-proxy/internal/tunnel"
	xproxy "golang.org/x/net/proxy"
)

// testSecret is a base64-encoded 32-byte key used across all integration tests.
var testSecret = base64.StdEncoding.EncodeToString([]byte("my-32-byte-secret-key-for-tests!"))

// tcpAddrConn wraps a net.Conn and overrides LocalAddr/RemoteAddr to return
// valid *net.TCPAddr values. This is needed because the go-socks5 library
// requires the dialed connection's LocalAddr() to be a *net.TCPAddr when
// building the SOCKS5 success reply. The yamux streams returned by
// tunnel.Client.OpenStream() have a dummyAddr that is not a *net.TCPAddr,
// causing the SOCKS5 server to reply with "address type not supported".
type tcpAddrConn struct {
	net.Conn
}

func (c *tcpAddrConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

func (c *tcpAddrConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

// startTargetHTTPServer starts a simple HTTP server that responds with
// "hello from target" for any request. It returns the listener and the
// server address (host:port).
func startTargetHTTPServer(t *testing.T) (net.Listener, string) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "hello from target")
	}))

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("failed to parse target server URL: %v", err)
	}

	t.Cleanup(func() { srv.Close() })

	// Return the underlying listener (nil, since httptest manages it)
	// and the host:port address for dialing.
	return nil, u.Host
}

// startEchoServer starts a TCP echo server that echoes all received data
// back to the sender. It returns the listener and the server address.
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

	t.Cleanup(func() { ln.Close() })

	return ln, ln.Addr().String()
}

// startTunnelRemote starts a tunnel server wrapped in httptest.NewServer.
// It returns the base URL of the HTTP test server (e.g., "http://127.0.0.1:xxxxx").
func startTunnelRemote(t *testing.T, secret string) string {
	t.Helper()

	srv := tunnel.NewServer(secret)
	srv.SetAllowPrivateIPs(true)

	httpSrv := httptest.NewServer(srv.Handler())

	t.Cleanup(func() {
		srv.Close()
		httpSrv.Close()
	})

	return httpSrv.URL
}

// startTunnelClient creates a tunnel client, connects it to the remote URL,
// and returns it. The client is closed automatically when the test finishes.
func startTunnelClient(t *testing.T, remoteURL, secret string) *tunnel.Client {
	t.Helper()

	client := tunnel.NewClient(remoteURL, secret)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("tunnel client connect failed: %v", err)
	}

	t.Cleanup(func() { client.Close() })
	return client
}

// startLocalProxy starts the local proxy handler (HTTP + SOCKS5) using the
// tunnel client's OpenStream as the dial function. It returns the proxy
// address (host:port).
func startLocalProxy(t *testing.T, client *tunnel.Client) string {
	t.Helper()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for local proxy: %v", err)
	}

	handler := proxy.NewProxyHandler(func(target string) (net.Conn, error) {
		conn, err := client.OpenStream(target)
		if err != nil {
			return nil, err
		}
		// Wrap with tcpAddrConn so that the go-socks5 library gets a
		// valid *net.TCPAddr from LocalAddr() in its SOCKS5 reply.
		return &tcpAddrConn{Conn: conn}, nil
	})

	go handler.Serve(ln) //nolint:errcheck

	t.Cleanup(func() { ln.Close() })

	return ln.Addr().String()
}

// TestIntegrationHTTPProxy exercises the full path:
//
//	HTTP client -> local proxy -> yamux -> EncryptedConn -> StegoConn ->
//	HTTP POST/Response -> tunnel server -> target HTTP server
func TestIntegrationHTTPProxy(t *testing.T) {
	// 1. Start target HTTP server
	_, targetAddr := startTargetHTTPServer(t)

	// 2. Start tunnel remote (httptest)
	remoteURL := startTunnelRemote(t, testSecret)

	// 3. Connect tunnel client
	client := startTunnelClient(t, remoteURL, testSecret)

	// Allow yamux session to stabilize
	time.Sleep(500 * time.Millisecond)

	// 4. Start local proxy
	proxyAddr := startLocalProxy(t, client)

	// 5. Make HTTP GET through proxy to target
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("failed to parse proxy URL: %v", err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 30 * time.Second,
	}

	resp, err := httpClient.Get("http://" + targetAddr + "/")
	if err != nil {
		t.Fatalf("HTTP GET through proxy failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	if strings.TrimSpace(string(body)) != "hello from target" {
		t.Fatalf("body mismatch: got %q, want %q", string(body), "hello from target")
	}
}

// TestIntegrationHTTPSConnect exercises the HTTPS CONNECT tunnel path:
//
//	CONNECT request -> local proxy -> yamux -> EncryptedConn -> StegoConn ->
//	HTTP POST/Response -> tunnel server -> echo server
func TestIntegrationHTTPSConnect(t *testing.T) {
	// 1. Start echo server
	_, echoAddr := startEchoServer(t)

	// 2. Start tunnel remote + client + proxy
	remoteURL := startTunnelRemote(t, testSecret)
	client := startTunnelClient(t, remoteURL, testSecret)

	// Allow yamux session to stabilize
	time.Sleep(500 * time.Millisecond)

	proxyAddr := startLocalProxy(t, client)

	// 3. Send CONNECT request to proxy
	conn, err := net.DialTimeout("tcp", proxyAddr, 30*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echoAddr, echoAddr)
	_, err = conn.Write([]byte(connectReq))
	if err != nil {
		t.Fatalf("failed to write CONNECT request: %v", err)
	}

	// 4. Read and verify 200 response
	br := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

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
	_, err = conn.Write([]byte(testData))
	if err != nil {
		t.Fatalf("failed to write test data: %v", err)
	}

	buf := make([]byte, len(testData))
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	_, err = io.ReadFull(br, buf)
	if err != nil {
		t.Fatalf("failed to read echo response: %v", err)
	}

	if string(buf) != testData {
		t.Fatalf("echo mismatch: got %q, want %q", string(buf), testData)
	}
}

// TestIntegrationSOCKS5 exercises the SOCKS5 tunnel path:
//
//	SOCKS5 client -> local proxy -> yamux -> EncryptedConn -> StegoConn ->
//	HTTP POST/Response -> tunnel server -> echo server
func TestIntegrationSOCKS5(t *testing.T) {
	// 1. Start echo server
	_, echoAddr := startEchoServer(t)

	// 2. Start tunnel remote + client + proxy
	remoteURL := startTunnelRemote(t, testSecret)
	client := startTunnelClient(t, remoteURL, testSecret)

	// Allow yamux session to stabilize
	time.Sleep(500 * time.Millisecond)

	proxyAddr := startLocalProxy(t, client)

	// 3. Connect via SOCKS5
	dialer, err := xproxy.SOCKS5("tcp", proxyAddr, nil, xproxy.Direct)
	if err != nil {
		t.Fatalf("failed to create SOCKS5 dialer: %v", err)
	}

	conn, err := dialer.Dial("tcp", echoAddr)
	if err != nil {
		t.Fatalf("failed to dial through SOCKS5: %v", err)
	}
	defer conn.Close()

	// 4. Send data and verify echo
	testData := "hello through SOCKS5 tunnel"
	_, err = conn.Write([]byte(testData))
	if err != nil {
		t.Fatalf("failed to write test data through SOCKS5: %v", err)
	}

	buf := make([]byte, len(testData))
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("failed to read echo through SOCKS5: %v", err)
	}

	if string(buf) != testData {
		t.Fatalf("SOCKS5 echo mismatch: got %q, want %q", string(buf), testData)
	}
}

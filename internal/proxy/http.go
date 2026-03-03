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
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
)

// DialFunc is a function that dials a target address and returns a net.Conn.
// It is used to abstract the connection mechanism (e.g., direct TCP or tunnel).
type DialFunc func(target string) (net.Conn, error)

// HTTPProxy handles HTTP and HTTPS proxy requests.
// For CONNECT requests (HTTPS tunneling), it establishes a bidirectional tunnel.
// For plain HTTP requests, it forwards the request to the target and relays the response.
type HTTPProxy struct {
	dial DialFunc
}

// NewHTTPProxy creates a new HTTPProxy that uses the given dial function
// to establish connections to target servers.
func NewHTTPProxy(dial DialFunc) *HTTPProxy {
	return &HTTPProxy{
		dial: dial,
	}
}

// ServeHTTP implements http.Handler. It dispatches between CONNECT (HTTPS)
// and plain HTTP methods.
func (p *HTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

// handleConnect handles HTTPS tunneling via the CONNECT method.
// It dials the target, sends a 200 response to the client, hijacks the
// connection, and relays data bidirectionally.
func (p *HTTPProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	slog.Debug("CONNECT request", "target", target)

	// Dial the target through the tunnel
	targetConn, err := p.dial(target)
	if err != nil {
		slog.Error("failed to dial target for CONNECT", "target", target, "error", err)
		http.Error(w, "Failed to connect to target", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// Send 200 Connection Established to the client
	w.WriteHeader(http.StatusOK)

	// Flush the response so the client sees the 200 immediately
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	// Hijack the client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		slog.Error("hijacking not supported")
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		slog.Error("failed to hijack connection", "error", err)
		return
	}
	defer clientConn.Close()

	// Bidirectional relay
	relay(clientConn, targetConn)
}

// handleHTTP handles plain HTTP proxy requests by forwarding them to the target
// and relaying the response back to the client.
func (p *HTTPProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Validate that this is an absolute URL (proxy request)
	if r.URL.Host == "" {
		slog.Error("plain HTTP request missing host", "url", r.URL.String())
		http.Error(w, "Missing host in request URL", http.StatusBadRequest)
		return
	}

	// Determine target address with default port 80
	host := r.URL.Host
	target := hostWithDefaultPort(host, "80")

	slog.Debug("plain HTTP request", "method", r.Method, "target", target, "url", r.URL.String())

	// Dial the target
	targetConn, err := p.dial(target)
	if err != nil {
		slog.Error("failed to dial target for HTTP", "target", target, "error", err)
		http.Error(w, "Failed to connect to target", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// Required by Go's Request.Write: RequestURI must be empty
	r.RequestURI = ""

	// Strip hop-by-hop headers that must not be forwarded
	for _, h := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive",
		"Proxy-Authenticate", "Proxy-Authorization",
		"Te", "Trailers", "Transfer-Encoding", "Upgrade",
	} {
		r.Header.Del(h)
	}

	// Write the HTTP request to the target connection
	if err := r.Write(targetConn); err != nil {
		slog.Error("failed to write request to target", "target", target, "error", err)
		http.Error(w, "Failed to forward request", http.StatusBadGateway)
		return
	}

	// Hijack the client connection to relay the raw response
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		slog.Error("hijacking not supported for plain HTTP")
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		slog.Error("failed to hijack connection for plain HTTP", "error", err)
		return
	}
	defer clientConn.Close()

	// Relay the response from target back to client
	io.Copy(clientConn, targetConn)
}

// hostWithDefaultPort returns host:port, adding the default port if none is specified.
func hostWithDefaultPort(host, defaultPort string) string {
	_, _, err := net.SplitHostPort(host)
	if err != nil {
		// No port specified, add the default.
		// Strip brackets from IPv6 addresses before calling JoinHostPort,
		// since JoinHostPort adds its own brackets.
		h := host
		if len(h) > 2 && h[0] == '[' && h[len(h)-1] == ']' {
			h = h[1 : len(h)-1]
		}
		return net.JoinHostPort(h, defaultPort)
	}
	return host
}

// relay copies data bidirectionally between two connections.
// It launches two goroutines and waits for both to complete.
func relay(a, b net.Conn) {
	var once sync.Once
	done := make(chan struct{})

	closeAll := func() {
		a.Close()
		b.Close()
	}

	go func() {
		io.Copy(a, b)
		once.Do(closeAll)
		done <- struct{}{}
	}()

	go func() {
		io.Copy(b, a)
		once.Do(closeAll)
		done <- struct{}{}
	}()

	<-done
	<-done
}

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
	"log/slog"
	"net"
	"net/http"

	socks5 "github.com/things-go/go-socks5"
)

// socks5VersionByte is the first byte sent in a SOCKS5 handshake.
const socks5VersionByte = 0x05

// ProxyHandler detects the incoming protocol (HTTP/HTTPS or SOCKS5)
// and dispatches the connection to the appropriate handler.
type ProxyHandler struct {
	httpProxy *HTTPProxy
	socks5Srv *socks5.Server
}

// NewProxyHandler creates a new ProxyHandler that routes connections
// through the given dial function.
func NewProxyHandler(dial DialFunc) *ProxyHandler {
	return &ProxyHandler{
		httpProxy: NewHTTPProxy(dial),
		socks5Srv: NewSOCKS5Server(dial),
	}
}

// Serve accepts connections on the listener and dispatches them based
// on protocol detection. It blocks until the listener is closed.
func (h *ProxyHandler) Serve(ln net.Listener) error {
	slog.Info("proxy handler listening", "addr", ln.Addr().String())

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}

		go h.handleConn(conn)
	}
}

// handleConn detects the protocol of an incoming connection and dispatches
// it to the appropriate handler.
func (h *ProxyHandler) handleConn(conn net.Conn) {
	// Wrap with buffered reader for peeking
	br := bufio.NewReader(conn)

	// Peek at the first byte to determine the protocol
	firstByte, err := br.Peek(1)
	if err != nil {
		slog.Error("failed to peek first byte", "remote", conn.RemoteAddr().String(), "error", err)
		conn.Close()
		return
	}

	wrapped := &bufferedConn{Reader: br, Conn: conn}

	if firstByte[0] == socks5VersionByte {
		// SOCKS5 protocol detected
		slog.Debug("SOCKS5 connection detected", "remote", conn.RemoteAddr().String())
		if err := h.socks5Srv.ServeConn(wrapped); err != nil {
			slog.Error("socks5 serve error", "remote", conn.RemoteAddr().String(), "error", err)
		}
	} else {
		// HTTP/HTTPS protocol detected
		slog.Debug("HTTP connection detected", "remote", conn.RemoteAddr().String())
		h.serveHTTP(wrapped)
	}
}

// serveHTTP serves a single HTTP connection using a singleConnListener.
func (h *ProxyHandler) serveHTTP(conn net.Conn) {
	srv := &http.Server{
		Handler: h.httpProxy,
	}

	ln := &singleConnListener{conn: conn}

	// Serve will return after handling the single connection
	srv.Serve(ln) //nolint:errcheck
}

// bufferedConn wraps a net.Conn with a bufio.Reader so that peeked bytes
// are not lost when the connection is handed off to a handler.
type bufferedConn struct {
	*bufio.Reader
	net.Conn
}

// Read reads from the buffered reader, which includes any peeked bytes.
func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.Reader.Read(p)
}

// singleConnListener is a net.Listener that serves exactly one connection.
// It is used to feed a single connection to http.Server.Serve().
type singleConnListener struct {
	conn net.Conn
	done bool
}

// Accept returns the single connection on the first call, and net.ErrClosed
// on subsequent calls.
func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.done {
		return nil, net.ErrClosed
	}
	l.done = true
	return l.conn, nil
}

// Close is a no-op since the connection lifecycle is managed elsewhere.
func (l *singleConnListener) Close() error {
	return nil
}

// Addr returns the local address of the wrapped connection.
func (l *singleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

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
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
	"github.com/mkloubert/go-proxy/internal/crypto"
)

const (
	// initialBackoff is the initial retry delay for connection attempts.
	initialBackoff = 1 * time.Second

	// maxBackoff is the maximum retry delay for connection attempts.
	maxBackoff = 30 * time.Second
)

// Client is the local side of the tunnel. It connects to a remote tunnel
// server over WebSocket, performs an encrypted handshake, and multiplexes
// streams via yamux over EncryptedConn.
type Client struct {
	remoteURL string // e.g., "ws://example.com:9876"
	wsPath    string // e.g., "/ws"
	secret    string
	mu        sync.RWMutex
	session   *yamux.Session
	wsConn    *websocket.Conn
	ctx       context.Context
	ctxCancel context.CancelFunc // cancels the long-lived connection context
}

// NewClient creates a new tunnel Client that will connect to the given
// remote address using the given base64-encoded secret.
// The remoteURL can be "host:port", "ws://host:port", or "wss://host:port".
// The wsPath is the WebSocket endpoint path on the server (e.g., "/ws").
func NewClient(remoteURL, secret, wsPath string) *Client {
	return &Client{
		remoteURL: normalizeWSURL(remoteURL),
		wsPath:    wsPath,
		secret:    secret,
	}
}

// normalizeWSURL converts various URL formats to a WebSocket URL.
// Accepted formats:
//   - "host:port" → "ws://host:port"
//   - "http://host:port" → "ws://host:port"
//   - "https://host:port" → "wss://host:port"
//   - "ws://host:port" → unchanged
//   - "wss://host:port" → unchanged
func normalizeWSURL(raw string) string {
	raw = strings.TrimRight(raw, "/")

	switch {
	case strings.HasPrefix(raw, "ws://") || strings.HasPrefix(raw, "wss://"):
		return raw
	case strings.HasPrefix(raw, "https://"):
		return "wss://" + strings.TrimPrefix(raw, "https://")
	case strings.HasPrefix(raw, "http://"):
		return "ws://" + strings.TrimPrefix(raw, "http://")
	default:
		// Bare host:port
		return "ws://" + raw
	}
}

// Connect establishes a connection to the remote tunnel server with
// exponential backoff retry. It respects context cancellation.
// After the initial connection succeeds, a background goroutine
// monitors the session and automatically reconnects if it dies.
//
// The provided ctx controls the retry loop: if it is canceled, Connect
// stops retrying and returns. The WebSocket connections use a long-lived
// context that is only canceled when Close() is called.
func (c *Client) Connect(ctx context.Context) error {
	// Create a long-lived context for the WebSocket connections.
	// This is independent of the caller's ctx (which may have a short timeout).
	connCtx, connCancel := context.WithCancel(context.Background())
	c.ctx = connCtx
	c.ctxCancel = connCancel

	backoff := initialBackoff

	for {
		err := c.connect()
		if err == nil {
			slog.Info("tunnel connection established", "remote", c.remoteURL)
			go c.maintainSession()
			return nil
		}

		slog.Error("tunnel connection attempt failed", "remote", c.remoteURL, "error", err, "retry_in", backoff)

		select {
		case <-ctx.Done():
			return fmt.Errorf("connection cancelled: %w", ctx.Err())
		case <-time.After(backoff):
		}

		// Exponential backoff: double the delay, cap at maxBackoff
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// maintainSession monitors the yamux session and automatically reconnects
// when it closes. This ensures the tunnel survives transient failures.
func (c *Client) maintainSession() {
	for {
		c.mu.RLock()
		session := c.session
		c.mu.RUnlock()

		if session == nil {
			return
		}

		// Wait for session to close or context cancellation
		select {
		case <-c.ctx.Done():
			return
		case <-session.CloseChan():
			slog.Warn("tunnel session closed, reconnecting...", "remote", c.remoteURL)
		}

		// Reconnect with exponential backoff
		backoff := initialBackoff
		for {
			select {
			case <-c.ctx.Done():
				return
			default:
			}

			err := c.connect()
			if err == nil {
				slog.Info("tunnel reconnected", "remote", c.remoteURL)
				break
			}

			slog.Error("reconnect failed", "remote", c.remoteURL, "error", err, "retry_in", backoff)

			select {
			case <-c.ctx.Done():
				return
			case <-time.After(backoff):
			}

			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// connect performs a single connection attempt to the remote server.
func (c *Client) connect() error {
	dialCtx, dialCancel := context.WithTimeout(c.ctx, 30*time.Second)
	defer dialCancel()

	// Step 1: Dial WebSocket
	// Force HTTP/1.1 — WebSocket upgrade does not work over HTTP/2.
	// Corporate proxies may negotiate HTTP/2 via ALPN which causes 426 errors.
	wsURL := c.remoteURL + c.wsPath
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 15 * time.Second,
			}).DialContext,
			TLSClientConfig: &tls.Config{
				NextProtos: []string{"http/1.1"}, // Prevent HTTP/2 ALPN negotiation
			},
			TLSHandshakeTimeout: 15 * time.Second,
			ForceAttemptHTTP2:   false,
		},
	}
	wsConn, _, err := websocket.Dial(dialCtx, wsURL, &websocket.DialOptions{
		HTTPClient: httpClient,
	})
	if err != nil {
		return fmt.Errorf("websocket dial failed: %w", err)
	}

	// Disable read limit — yamux manages flow control
	wsConn.SetReadLimit(-1)

	// Step 2: Get a net.Conn from the WebSocket
	netConn := websocket.NetConn(c.ctx, wsConn, websocket.MessageBinary)

	// Step 3: Perform streaming handshake over the WebSocket net.Conn
	encConn, err := crypto.ClientHandshake(netConn, c.secret)
	if err != nil {
		wsConn.Close(websocket.StatusInternalError, "handshake failed")
		return fmt.Errorf("handshake failed: %w", err)
	}

	// Step 4: Start WebSocket ping/pong keepalive
	go startPing(c.ctx, wsConn)

	// Step 5: Create yamux client session
	yamuxCfg := yamux.DefaultConfig()
	yamuxCfg.AcceptBacklog = 128
	yamuxCfg.StreamCloseTimeout = 60 * time.Second
	yamuxCfg.StreamOpenTimeout = 30 * time.Second
	yamuxCfg.MaxStreamWindowSize = 512 * 1024
	yamuxCfg.LogOutput = io.Discard

	session, err := yamux.Client(encConn, yamuxCfg)
	if err != nil {
		wsConn.Close(websocket.StatusInternalError, "yamux failed")
		return fmt.Errorf("yamux session creation failed: %w", err)
	}

	// Step 6: Store new session, close old one if it exists
	c.mu.Lock()
	oldSession := c.session
	oldWsConn := c.wsConn
	c.session = session
	c.wsConn = wsConn
	c.mu.Unlock()

	if oldSession != nil {
		oldSession.Close()
	}
	if oldWsConn != nil {
		oldWsConn.Close(websocket.StatusGoingAway, "reconnecting")
	}

	return nil
}

// OpenStream opens a new multiplexed stream through the tunnel and sends the
// target address header. The returned net.Conn can be used to communicate
// with the target as if it were a direct TCP connection.
func (c *Client) OpenStream(target string) (net.Conn, error) {
	c.mu.RLock()
	session := c.session
	c.mu.RUnlock()

	if session == nil {
		return nil, errors.New("no active tunnel session")
	}

	// Step 1: Open a yamux stream
	stream, err := session.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open stream: %w", err)
	}

	// Step 2: Write target address header [2 bytes length][N bytes address]
	addrBytes := []byte(target)
	if len(addrBytes) > 65535 {
		stream.Close()
		return nil, errors.New("target address too long")
	}

	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(addrBytes)))

	if _, err := stream.Write(lenBuf); err != nil {
		stream.Close()
		return nil, fmt.Errorf("failed to write target address length: %w", err)
	}

	if _, err := stream.Write(addrBytes); err != nil {
		stream.Close()
		return nil, fmt.Errorf("failed to write target address: %w", err)
	}

	slog.Debug("stream opened", "target", target)

	return stream, nil
}

// Close closes the tunnel client, its yamux session, and the underlying WebSocket.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Cancel the long-lived context to stop reconnection and close WebSocket NetConns
	if c.ctxCancel != nil {
		c.ctxCancel()
	}

	var firstErr error

	if c.session != nil {
		if err := c.session.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		c.session = nil
	}

	if c.wsConn != nil {
		if err := c.wsConn.Close(websocket.StatusNormalClosure, "closing"); err != nil && firstErr == nil {
			firstErr = err
		}
		c.wsConn = nil
	}

	return firstErr
}

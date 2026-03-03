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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

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
// server, performs an encrypted handshake, and multiplexes streams via yamux.
type Client struct {
	remoteAddr string
	secret     string
	mu         sync.RWMutex
	session    *yamux.Session
}

// NewClient creates a new tunnel Client that will connect to the given
// remote address using the given base64-encoded secret.
func NewClient(remoteAddr, secret string) *Client {
	return &Client{
		remoteAddr: remoteAddr,
		secret:     secret,
	}
}

// Connect establishes a connection to the remote tunnel server with
// exponential backoff retry. It respects context cancellation.
func (c *Client) Connect(ctx context.Context) error {
	backoff := initialBackoff

	for {
		err := c.connect()
		if err == nil {
			slog.Info("tunnel connection established", "remote", c.remoteAddr)
			return nil
		}

		slog.Error("tunnel connection attempt failed", "remote", c.remoteAddr, "error", err, "retry_in", backoff)

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

// connect performs a single connection attempt to the remote server.
func (c *Client) connect() error {
	// Step 1: Dial the remote server
	conn, err := net.Dial("tcp4", c.remoteAddr)
	if err != nil {
		return fmt.Errorf("failed to dial remote: %w", err)
	}

	// Step 2: Perform encrypted handshake
	encConn, err := crypto.ClientHandshake(conn, c.secret)
	if err != nil {
		conn.Close()
		return fmt.Errorf("handshake failed: %w", err)
	}

	// Step 3: Create yamux client session with hardened config
	yamuxCfg := yamux.DefaultConfig()
	yamuxCfg.AcceptBacklog = 128
	yamuxCfg.StreamCloseTimeout = 60 * time.Second
	yamuxCfg.StreamOpenTimeout = 30 * time.Second
	yamuxCfg.MaxStreamWindowSize = 512 * 1024
	yamuxCfg.LogOutput = io.Discard

	session, err := yamux.Client(encConn, yamuxCfg)
	if err != nil {
		encConn.Close()
		return fmt.Errorf("yamux session creation failed: %w", err)
	}

	// Step 4: Store new session, close old one if it exists
	c.mu.Lock()
	oldSession := c.session
	c.session = session
	c.mu.Unlock()

	if oldSession != nil {
		oldSession.Close()
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

// Close closes the tunnel client and its underlying yamux session.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.session != nil {
		err := c.session.Close()
		c.session = nil
		return err
	}

	return nil
}

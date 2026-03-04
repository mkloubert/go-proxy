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
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/yamux"
	"github.com/mkloubert/go-proxy/internal/crypto"
	"github.com/mkloubert/go-proxy/internal/stego"
)

const (
	// initialBackoff is the initial retry delay for connection attempts.
	initialBackoff = 1 * time.Second

	// maxBackoff is the maximum retry delay for connection attempts.
	maxBackoff = 30 * time.Second

	// maxConsecutiveErrors is the number of consecutive roundTrip failures
	// before the StegoConn is closed.
	maxConsecutiveErrors = 10
)

// maxStegoPayload is the maximum payload that can be embedded in the
// largest supported carrier image (1024x1024).
var maxStegoPayload = stego.Capacity(1024, 1024)

// StegoConn implements net.Conn over HTTP POST requests with PNG steganography.
// Write() buffers data. A background sendLoop goroutine periodically flushes
// the buffer by encoding it into a PNG and POSTing it to the server.
// The response PNG contains downstream data which is pushed to a read channel.
// Read() blocks on the read channel.
type StegoConn struct {
	remoteURL  string       // base URL of the remote server
	token      string       // session token from handshake
	httpClient *http.Client // HTTP client for POST requests

	// Write side: buffered data waiting to be sent
	writeMu  sync.Mutex
	writeBuf []byte

	// Read side: channel of received data chunks
	readCh  chan []byte
	readBuf []byte
	readMu  sync.Mutex

	closeCh   chan struct{}
	closeOnce sync.Once

	sendInterval      time.Duration // how often to flush (e.g., 50ms)
	consecutiveErrors int           // tracks consecutive roundTrip failures

	readDeadline atomicTime
}

// Verify StegoConn implements net.Conn at compile time.
var _ net.Conn = (*StegoConn)(nil)

// Read reads data from the downstream channel. If readBuf has leftover data
// from a previous read, it is returned first. Otherwise, Read blocks until
// data arrives on readCh or the connection is closed. If a read deadline is
// set, the read will fail with os.ErrDeadlineExceeded when the deadline expires.
func (sc *StegoConn) Read(p []byte) (int, error) {
	sc.readMu.Lock()
	defer sc.readMu.Unlock()

	// Return leftover data from a previous read
	if len(sc.readBuf) > 0 {
		n := copy(p, sc.readBuf)
		sc.readBuf = sc.readBuf[n:]
		return n, nil
	}

	deadline := sc.readDeadline.Load()
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case data, ok := <-sc.readCh:
			if !ok || len(data) == 0 {
				return 0, io.EOF
			}
			n := copy(p, data)
			if n < len(data) {
				sc.readBuf = make([]byte, len(data)-n)
				copy(sc.readBuf, data[n:])
			}
			return n, nil
		case <-timer.C:
			return 0, os.ErrDeadlineExceeded
		case <-sc.closeCh:
			return 0, io.EOF
		}
	}

	// No deadline set — block until data arrives or connection is closed
	select {
	case data, ok := <-sc.readCh:
		if !ok || len(data) == 0 {
			return 0, io.EOF
		}
		n := copy(p, data)
		if n < len(data) {
			sc.readBuf = make([]byte, len(data)-n)
			copy(sc.readBuf, data[n:])
		}
		return n, nil
	case <-sc.closeCh:
		return 0, io.EOF
	}
}

// Write appends data to the write buffer. The data will be flushed by the
// background sendLoop goroutine on the next tick.
func (sc *StegoConn) Write(p []byte) (int, error) {
	select {
	case <-sc.closeCh:
		return 0, io.ErrClosedPipe
	default:
	}

	sc.writeMu.Lock()
	sc.writeBuf = append(sc.writeBuf, p...)
	sc.writeMu.Unlock()

	return len(p), nil
}

// Close closes the StegoConn exactly once. It performs a best-effort final
// flush of any buffered write data before closing.
func (sc *StegoConn) Close() error {
	sc.closeOnce.Do(func() {
		// Best-effort final flush
		sc.writeMu.Lock()
		data := sc.writeBuf
		sc.writeBuf = nil
		sc.writeMu.Unlock()

		if len(data) > 0 {
			sc.roundTrip(data) //nolint:errcheck
		}

		close(sc.closeCh)
	})
	return nil
}

// LocalAddr returns a dummy address (pipe).
func (sc *StegoConn) LocalAddr() net.Addr { return dummyAddr{} }

// RemoteAddr returns a dummy address (pipe).
func (sc *StegoConn) RemoteAddr() net.Addr { return dummyAddr{} }

// SetDeadline sets the read deadline. Write deadlines are not meaningful
// for StegoConn since writes are buffered and flushed asynchronously.
func (sc *StegoConn) SetDeadline(t time.Time) error {
	sc.readDeadline.Store(t)
	return nil
}

// SetReadDeadline sets the read deadline.
func (sc *StegoConn) SetReadDeadline(t time.Time) error {
	sc.readDeadline.Store(t)
	return nil
}

// SetWriteDeadline is a no-op for StegoConn since writes are buffered
// and flushed asynchronously by sendLoop.
func (sc *StegoConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// sendLoop runs as a background goroutine. On each tick it grabs the buffered
// write data, embeds it in a PNG, POSTs it to the server, extracts the
// response PNG, and pushes any downstream data to readCh.
func (sc *StegoConn) sendLoop() {
	ticker := time.NewTicker(sc.sendInterval)
	defer ticker.Stop()

	for {
		select {
		case <-sc.closeCh:
			return
		case <-ticker.C:
			// Grab buffered write data, capped to max stego capacity
			sc.writeMu.Lock()
			data := sc.writeBuf
			if len(data) > maxStegoPayload {
				data = sc.writeBuf[:maxStegoPayload]
				sc.writeBuf = sc.writeBuf[maxStegoPayload:]
			} else {
				sc.writeBuf = nil
			}
			sc.writeMu.Unlock()

			// Even if data is empty, POST to poll for downstream data
			if data == nil {
				data = []byte{}
			}

			downstream, err := sc.roundTrip(data)
			if err != nil {
				slog.Debug("stego roundtrip error", "error", err)

				// Prepend unsent data back to writeBuf so it is retried
				if len(data) > 0 {
					sc.writeMu.Lock()
					sc.writeBuf = append(data, sc.writeBuf...)
					sc.writeMu.Unlock()
				}

				sc.consecutiveErrors++
				if sc.consecutiveErrors > maxConsecutiveErrors {
					slog.Error("too many consecutive roundtrip errors, closing connection", "count", sc.consecutiveErrors)
					sc.Close()
					return
				}

				continue
			}

			sc.consecutiveErrors = 0

			// Push non-empty downstream data to readCh
			if len(downstream) > 0 {
				select {
				case sc.readCh <- downstream:
				case <-sc.closeCh:
					return
				}
			}
		}
	}
}

// roundTrip performs a single HTTP POST with steganographically encoded data
// and returns the decoded downstream data from the response PNG.
func (sc *StegoConn) roundTrip(data []byte) ([]byte, error) {
	// Embed data in a PNG carrier image
	w, h := stego.RequiredImageSize(len(data))
	carrier := stego.GenerateCarrier(w, h)
	pngBytes, err := stego.Embed(carrier, data)
	if err != nil {
		return nil, fmt.Errorf("stego embed failed: %w", err)
	}

	// Build request URL with a fresh random UUID
	url := sc.remoteURL + "/api/v1/galleries/" + uuid.New().String() + "/pictures"

	req, err := http.NewRequest("POST", url, bytes.NewReader(pngBytes))
	if err != nil {
		return nil, fmt.Errorf("request creation failed: %w", err)
	}
	req.Header.Set("Content-Type", "image/png")
	req.Header.Set("Authorization", "Bearer "+sc.token)

	// Execute the request
	resp, err := sc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP POST failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("unexpected response status: %d", resp.StatusCode)
	}

	// Read and decode the response PNG
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	downstream, err := stego.Extract(respBody)
	if err != nil {
		return nil, fmt.Errorf("stego extract failed: %w", err)
	}

	return downstream, nil
}

// Client is the local side of the tunnel. It connects to a remote tunnel
// server over HTTP, performs a steganographic handshake, and multiplexes
// streams via yamux over EncryptedConn over StegoConn.
type Client struct {
	remoteURL string // e.g., "http://example.com:80"
	secret    string
	mu        sync.RWMutex
	session   *yamux.Session
	stegoConn *StegoConn
	ctx       context.Context
}

// NewClient creates a new tunnel Client that will connect to the given
// remote URL using the given base64-encoded secret.
func NewClient(remoteURL, secret string) *Client {
	return &Client{
		remoteURL: strings.TrimRight(remoteURL, "/"),
		secret:    secret,
	}
}

// Connect establishes a connection to the remote tunnel server with
// exponential backoff retry. It respects context cancellation.
// After the initial connection succeeds, a background goroutine
// monitors the session and automatically reconnects if it dies.
func (c *Client) Connect(ctx context.Context) error {
	c.ctx = ctx

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
	httpClient := &http.Client{Timeout: 30 * time.Second}

	// Step 1: Generate handshake payload
	hsPayload, challengePlain, keys, err := crypto.ClientHandshakePayload(c.secret)
	if err != nil {
		return fmt.Errorf("handshake payload generation failed: %w", err)
	}

	// Step 2: Embed handshake payload in PNG
	w, h := stego.RequiredImageSize(len(hsPayload))
	carrier := stego.GenerateCarrier(w, h)
	pngBytes, err := stego.Embed(carrier, hsPayload)
	if err != nil {
		return fmt.Errorf("stego embed failed: %w", err)
	}

	// Step 3: POST to gallery API (no Authorization header = handshake)
	url := c.remoteURL + "/api/v1/galleries/" + uuid.New().String() + "/pictures"
	req, err := http.NewRequest("POST", url, bytes.NewReader(pngBytes))
	if err != nil {
		return fmt.Errorf("request creation failed: %w", err)
	}
	req.Header.Set("Content-Type", "image/png")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("handshake request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("handshake rejected: status %d", resp.StatusCode)
	}

	// Step 4: Get token from response
	authHeader := resp.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return errors.New("handshake response missing Bearer token")
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	// Step 5: Extract handshake response from response PNG
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read handshake response: %w", err)
	}
	hsResponse, err := stego.Extract(respBody)
	if err != nil {
		return fmt.Errorf("failed to extract handshake response: %w", err)
	}

	// Step 6: Verify handshake
	if err := crypto.ClientVerifyHandshake(hsResponse, challengePlain, keys); err != nil {
		return fmt.Errorf("handshake verification failed: %w", err)
	}

	// Step 7: Create StegoConn
	sc := &StegoConn{
		remoteURL:    c.remoteURL,
		token:        token,
		httpClient:   httpClient,
		readCh:       make(chan []byte, 64),
		closeCh:      make(chan struct{}),
		sendInterval: 50 * time.Millisecond,
	}
	go sc.sendLoop()

	// Step 8: Wrap with EncryptedConn (client uses ClientNoncePrefix for writes)
	encConn, err := crypto.NewEncryptedConn(sc, keys.EncryptionKey, keys.ClientNoncePrefix)
	if err != nil {
		sc.Close()
		return fmt.Errorf("encrypted connection failed: %w", err)
	}

	// Step 9: Create yamux client session
	yamuxCfg := yamux.DefaultConfig()
	yamuxCfg.AcceptBacklog = 128
	yamuxCfg.StreamCloseTimeout = 60 * time.Second
	yamuxCfg.StreamOpenTimeout = 30 * time.Second
	yamuxCfg.MaxStreamWindowSize = 512 * 1024
	yamuxCfg.LogOutput = io.Discard

	session, err := yamux.Client(encConn, yamuxCfg)
	if err != nil {
		sc.Close()
		return fmt.Errorf("yamux session creation failed: %w", err)
	}

	// Step 10: Store new session, close old one if it exists
	c.mu.Lock()
	oldSession := c.session
	c.session = session
	if c.stegoConn != nil {
		c.stegoConn.Close()
	}
	c.stegoConn = sc
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

// Close closes the tunnel client, its yamux session, and the underlying StegoConn.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var firstErr error

	if c.session != nil {
		if err := c.session.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		c.session = nil
	}

	if c.stegoConn != nil {
		if err := c.stegoConn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		c.stegoConn = nil
	}

	return firstErr
}

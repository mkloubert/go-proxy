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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/mkloubert/go-proxy/internal/crypto"
	"github.com/mkloubert/go-proxy/internal/security"
	"github.com/mkloubert/go-proxy/internal/stego"
)

const (
	streamHeaderTimeout     = 10 * time.Second
	relayIdleTimeout        = 5 * time.Minute
	yamuxAcceptBacklog      = 128
	yamuxStreamCloseTimeout = 60 * time.Second
	yamuxStreamOpenTimeout  = 30 * time.Second
	yamuxMaxStreamWindow    = 512 * 1024 // 512KB per stream

	maxRequestBodySize  = 2 * 1024 * 1024 // 2MB
	sessionIdleTimeout  = 5 * time.Minute
	sessionCleanupEvery = 30 * time.Second
	downstreamDrainWait = 200 * time.Millisecond
	maxDrainSize        = 512 * 1024 // 512KB
	upstreamSendTimeout = 5 * time.Second
	pipeWriteTimeout    = 10 * time.Second
)

// dummyAddr implements net.Addr for pipeConn.
type dummyAddr struct{}

func (dummyAddr) Network() string { return "pipe" }
func (dummyAddr) String() string  { return "pipe" }

// atomicTime provides goroutine-safe access to a time.Time value.
type atomicTime struct {
	mu sync.Mutex
	t  time.Time
}

func (a *atomicTime) Store(t time.Time) {
	a.mu.Lock()
	a.t = t
	a.mu.Unlock()
}

func (a *atomicTime) Load() time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.t
}

// pipeConn implements net.Conn over channels, bridging HTTP handlers
// and yamux/EncryptedConn. The HTTP handler writes incoming data to
// upstream and reads outgoing data from downstream.
type pipeConn struct {
	upstream   chan []byte // HTTP handler writes here, Read() pulls from here
	readBuf    []byte     // leftover from partial reads
	readMu     sync.Mutex
	downstream chan []byte // Write() pushes here, HTTP handler drains this
	closeCh    chan struct{}
	closeOnce  sync.Once

	// Deadline support
	readDeadline  atomicTime
	writeDeadline atomicTime
}

// newPipeConn creates a pipeConn with buffered channels.
func newPipeConn() *pipeConn {
	return &pipeConn{
		upstream:   make(chan []byte, 64),
		downstream: make(chan []byte, 64),
		closeCh:    make(chan struct{}),
	}
}

// Read blocks on the upstream channel and returns data to the caller
// (yamux/EncryptedConn). Leftover data from a previous read is returned
// first. If a read deadline is set, the read will fail with
// os.ErrDeadlineExceeded when the deadline expires.
func (p *pipeConn) Read(buf []byte) (int, error) {
	p.readMu.Lock()
	defer p.readMu.Unlock()

	if len(p.readBuf) > 0 {
		n := copy(buf, p.readBuf)
		p.readBuf = p.readBuf[n:]
		return n, nil
	}

	deadline := p.readDeadline.Load()
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case data, ok := <-p.upstream:
			if !ok || len(data) == 0 {
				return 0, io.EOF
			}
			n := copy(buf, data)
			if n < len(data) {
				p.readBuf = make([]byte, len(data)-n)
				copy(p.readBuf, data[n:])
			}
			return n, nil
		case <-timer.C:
			return 0, os.ErrDeadlineExceeded
		case <-p.closeCh:
			return 0, io.EOF
		}
	}

	// No deadline set
	select {
	case data, ok := <-p.upstream:
		if !ok || len(data) == 0 {
			return 0, io.EOF
		}
		n := copy(buf, data)
		if n < len(data) {
			p.readBuf = make([]byte, len(data)-n)
			copy(p.readBuf, data[n:])
		}
		return n, nil
	case <-p.closeCh:
		return 0, io.EOF
	}
}

// Write sends data to the downstream channel for the HTTP handler to
// pick up. A copy of the data is made to prevent aliasing.
func (p *pipeConn) Write(data []byte) (int, error) {
	cp := make([]byte, len(data))
	copy(cp, data)
	select {
	case p.downstream <- cp:
		return len(data), nil
	case <-p.closeCh:
		return 0, io.ErrClosedPipe
	case <-time.After(pipeWriteTimeout):
		return 0, fmt.Errorf("pipeConn: write timeout")
	}
}

// Close closes the pipeConn exactly once.
func (p *pipeConn) Close() error {
	p.closeOnce.Do(func() { close(p.closeCh) })
	return nil
}

// LocalAddr returns a dummy address (pipe).
func (p *pipeConn) LocalAddr() net.Addr { return dummyAddr{} }

// RemoteAddr returns a dummy address (pipe).
func (p *pipeConn) RemoteAddr() net.Addr { return dummyAddr{} }

// SetDeadline sets both the read and write deadlines.
func (p *pipeConn) SetDeadline(t time.Time) error {
	p.readDeadline.Store(t)
	p.writeDeadline.Store(t)
	return nil
}

// SetReadDeadline sets the read deadline.
func (p *pipeConn) SetReadDeadline(t time.Time) error {
	p.readDeadline.Store(t)
	return nil
}

// SetWriteDeadline sets the write deadline.
func (p *pipeConn) SetWriteDeadline(t time.Time) error {
	p.writeDeadline.Store(t)
	return nil
}

// Verify pipeConn implements net.Conn at compile time.
var _ net.Conn = (*pipeConn)(nil)

// tunnelSession holds state for one active tunnel connection.
type tunnelSession struct {
	keys     *crypto.DerivedKeys
	pipe     *pipeConn
	yamuxSes *yamux.Session
	lastSeen time.Time
	mu       sync.Mutex
}

// Server is the remote side of the tunnel. It serves an HTTP gallery API
// where data is hidden inside PNG images via LSB steganography.
// Handshakes create new sessions; subsequent requests exchange data
// through the session's pipeConn, which feeds yamux/EncryptedConn.
type Server struct {
	secret          string
	rateLimiter     *security.RateLimiter
	ipFilter        *security.IPFilter
	allowPrivateIPs bool

	sessionMu sync.RWMutex
	sessions  map[string]*tunnelSession

	stopCh   chan struct{}
	stopOnce sync.Once

	cleanupOnce sync.Once
}

// NewServer creates a new tunnel Server with the given base64-encoded secret.
func NewServer(secret string) *Server {
	return &Server{
		secret:      secret,
		rateLimiter: security.NewRateLimiter(10, 5, 5, 5*time.Minute),
		sessions:    make(map[string]*tunnelSession),
		stopCh:      make(chan struct{}),
	}
}

// Close stops background goroutines, the rate limiter, and all active sessions.
func (s *Server) Close() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
	s.rateLimiter.Stop()

	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	for token, sess := range s.sessions {
		sess.yamuxSes.Close()
		sess.pipe.Close()
		delete(s.sessions, token)
	}
}

// SetIPFilter assigns an IPFilter to the server. When set, incoming
// requests from blocked IPs are rejected before any further processing.
func (s *Server) SetIPFilter(f *security.IPFilter) {
	s.ipFilter = f
}

// SetAllowPrivateIPs disables SSRF protection. Only use in tests.
func (s *Server) SetAllowPrivateIPs(allow bool) {
	s.allowPrivateIPs = allow
}

// Handler returns an http.Handler that serves the gallery API.
// Requests must be POST /api/v1/galleries/{uuid}/pictures with a PNG
// body containing steganographically hidden data.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/galleries/{uuid}/pictures", s.handlePicture)
	return mux
}

// handlePicture is the main request handler. It extracts hidden data
// from the PNG body and routes to either handshake or data exchange
// based on the presence of an Authorization header.
func (s *Server) handlePicture(w http.ResponseWriter, r *http.Request) {
	// 1. Get client IP from r.RemoteAddr
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)

	// 2. IP filter check
	if s.ipFilter != nil && s.ipFilter.IsBlocked(ip) {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// 3. Rate limiter check
	if !s.rateLimiter.Allow(ip) {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// 4. Read request body (limit to 2MB)
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBodySize))
	if err != nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// 5. Extract hidden data from PNG
	data, err := stego.Extract(body)
	if err != nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// 6. Check Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		// Handshake flow
		s.handleHandshake(w, data, ip)
	} else {
		// Data exchange flow
		token := strings.TrimPrefix(authHeader, "Bearer ")
		s.handleDataExchange(w, data, token)
	}
}

// handleHandshake processes a handshake request: verifies the shared secret,
// creates a new tunnel session with pipeConn + EncryptedConn + yamux, and
// returns the handshake response embedded in a PNG.
func (s *Server) handleHandshake(w http.ResponseWriter, payload []byte, ip string) {
	// 1. Process handshake
	response, keys, err := crypto.ServerHandshakePayload(payload, s.secret)
	if err != nil {
		s.rateLimiter.RecordFailure(ip)
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// 2. Create pipeConn
	pipe := newPipeConn()

	// 3. Wrap with EncryptedConn (server uses ServerNoncePrefix for writes)
	encConn, err := crypto.NewEncryptedConn(pipe, keys.EncryptionKey, keys.ServerNoncePrefix)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// 4. Create yamux server session
	yamuxCfg := yamux.DefaultConfig()
	yamuxCfg.AcceptBacklog = yamuxAcceptBacklog
	yamuxCfg.StreamCloseTimeout = yamuxStreamCloseTimeout
	yamuxCfg.StreamOpenTimeout = yamuxStreamOpenTimeout
	yamuxCfg.MaxStreamWindowSize = yamuxMaxStreamWindow
	yamuxCfg.LogOutput = io.Discard

	yamuxSes, err := yamux.Server(encConn, yamuxCfg)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// 5. Generate session token and derive auth tag
	token := generateToken()
	authTag := deriveAuthTag(keys.EncryptionKey, token)

	// 6. Store session (keyed by authTag so raw token never appears on the wire)
	sess := &tunnelSession{
		keys:     keys,
		pipe:     pipe,
		yamuxSes: yamuxSes,
		lastSeen: time.Now(),
	}
	s.sessionMu.Lock()
	s.sessions[authTag] = sess
	s.sessionMu.Unlock()

	// 7. Start yamux stream accept goroutine
	go s.acceptStreams(sess, authTag)

	// 8. Start session cleanup goroutine (only once)
	s.cleanupOnce.Do(func() {
		go s.sessionCleanupLoop()
	})

	// 9. Embed response in PNG
	w2, h2 := stego.RequiredImageSize(len(response))
	carrier := stego.GenerateCarrier(w2, h2)
	pngBytes, err := stego.Embed(carrier, response)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// 10. Send response
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Authorization", "Bearer "+authTag)
	w.WriteHeader(http.StatusCreated)
	w.Write(pngBytes)

	slog.Info("handshake completed, session created", "token_prefix", authTag[:8])
}

// handleDataExchange processes a data exchange request: pushes upstream
// data into the session's pipeConn and drains downstream data back as
// a steganographic PNG response.
func (s *Server) handleDataExchange(w http.ResponseWriter, upstreamData []byte, token string) {
	// 1. Get session
	s.sessionMu.RLock()
	sess := s.sessions[token]
	s.sessionMu.RUnlock()

	if sess == nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// 2. Touch session
	sess.mu.Lock()
	sess.lastSeen = time.Now()
	sess.mu.Unlock()

	// 3. Push upstream data to pipeConn (close-aware with timeout)
	if len(upstreamData) > 0 {
		select {
		case sess.pipe.upstream <- upstreamData:
			// OK
		case <-sess.pipe.closeCh:
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		case <-time.After(upstreamSendTimeout):
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}
	}

	// 4. Wait briefly for downstream data, then drain
	downstreamData := s.drainDownstream(sess.pipe, downstreamDrainWait)

	// 5. Embed in response PNG (even if empty)
	w2, h2 := stego.RequiredImageSize(len(downstreamData))
	carrier := stego.GenerateCarrier(w2, h2)
	pngBytes, err := stego.Embed(carrier, downstreamData)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// 6. Send response
	w.Header().Set("Content-Type", "image/png")
	w.WriteHeader(http.StatusCreated)
	w.Write(pngBytes)
}

// drainDownstream waits up to timeout for the first chunk of downstream
// data, then drains any additional immediately available chunks up to
// maxDrainSize bytes.
func (s *Server) drainDownstream(pipe *pipeConn, timeout time.Duration) []byte {
	var buf []byte
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	// Wait for first chunk or timeout
	select {
	case data := <-pipe.downstream:
		buf = append(buf, data...)
	case <-timer.C:
		return buf
	case <-pipe.closeCh:
		return buf
	}

	// Drain any additional immediately available chunks
	for len(buf) < maxDrainSize {
		select {
		case data := <-pipe.downstream:
			buf = append(buf, data...)
		default:
			return buf
		}
	}
	return buf
}

// acceptStreams accepts yamux streams and dispatches each one to
// handleStream. When the yamux session ends, the tunnel session is
// cleaned up.
func (s *Server) acceptStreams(sess *tunnelSession, token string) {
	defer func() {
		sess.yamuxSes.Close()
		sess.pipe.Close()
		s.sessionMu.Lock()
		delete(s.sessions, token)
		s.sessionMu.Unlock()
	}()

	for {
		stream, err := sess.yamuxSes.Accept()
		if err != nil {
			if err != io.EOF {
				slog.Debug("stream accept ended", "error", err)
			}
			return
		}
		go s.handleStream(stream)
	}
}

// handleStream reads the target address from the stream, dials the target,
// and relays data bidirectionally.
func (s *Server) handleStream(stream net.Conn) {
	defer stream.Close()

	// Deadline for reading the target address header
	stream.SetDeadline(time.Now().Add(streamHeaderTimeout))

	// Step 1: Read target address length (2 bytes big-endian)
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		slog.Error("failed to read target address length", "error", err)
		return
	}

	addrLen := binary.BigEndian.Uint16(lenBuf)
	if addrLen == 0 {
		slog.Error("target address length is zero")
		return
	}

	// Step 2: Read target address
	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(stream, addrBuf); err != nil {
		slog.Error("failed to read target address", "error", err)
		return
	}

	target := string(addrBuf)

	// Clear deadline for relay phase
	stream.SetDeadline(time.Time{})

	// Step 3: Dial the target (with SSRF protection unless disabled)
	var targetConn net.Conn
	var err error

	if s.allowPrivateIPs {
		targetConn, err = net.DialTimeout("tcp4", target, 30*time.Second)
	} else {
		targetConn, err = security.SafeDial(target)
	}

	if err != nil {
		slog.Debug("failed to dial target", "target", target, "error", err)
		return
	}
	defer targetConn.Close()

	slog.Debug("connected to target", "target", target)

	// Step 4: Bidirectional relay with idle timeout
	relay(&activityConn{Conn: stream, timeout: relayIdleTimeout},
		&activityConn{Conn: targetConn, timeout: relayIdleTimeout})
}

// activityConn wraps a net.Conn and refreshes deadlines on each Read/Write,
// ensuring idle connections are closed after the configured timeout.
type activityConn struct {
	net.Conn
	timeout time.Duration
}

func (c *activityConn) Read(p []byte) (int, error) {
	c.Conn.SetReadDeadline(time.Now().Add(c.timeout))
	return c.Conn.Read(p)
}

func (c *activityConn) Write(p []byte) (int, error) {
	c.Conn.SetWriteDeadline(time.Now().Add(c.timeout))
	return c.Conn.Write(p)
}

// relay copies data bidirectionally between two connections.
// It launches two goroutines and waits for the first one to complete,
// then closes both connections to unblock the other goroutine.
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

	// Wait for both goroutines to finish
	<-done
	<-done
}

// generateToken generates a cryptographically random session token
// (32 random bytes, hex-encoded to 64 characters).
func generateToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("tunnel: failed to generate token: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// deriveAuthTag computes HMAC-SHA256(key, token) and returns it as a hex string.
// This prevents network observers from forging session tokens.
func deriveAuthTag(key []byte, token string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(token))
	return hex.EncodeToString(mac.Sum(nil))
}

// sessionCleanupLoop periodically removes idle sessions.
func (s *Server) sessionCleanupLoop() {
	ticker := time.NewTicker(sessionCleanupEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.cleanupSessions(sessionIdleTimeout)
		case <-s.stopCh:
			return
		}
	}
}

// cleanupSessions removes sessions that have been idle for longer than
// maxIdle.
func (s *Server) cleanupSessions(maxIdle time.Duration) {
	now := time.Now()
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	for token, sess := range s.sessions {
		sess.mu.Lock()
		idle := now.Sub(sess.lastSeen)
		sess.mu.Unlock()
		if idle > maxIdle {
			sess.yamuxSes.Close()
			sess.pipe.Close()
			delete(s.sessions, token)
		}
	}
}

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
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
	"github.com/mkloubert/go-proxy/internal/crypto"
	"github.com/mkloubert/go-proxy/internal/security"
)

const (
	streamHeaderTimeout     = 10 * time.Second
	relayIdleTimeout        = 5 * time.Minute
	yamuxAcceptBacklog      = 128
	yamuxStreamCloseTimeout = 60 * time.Second
	yamuxStreamOpenTimeout  = 30 * time.Second
	yamuxMaxStreamWindow    = 512 * 1024 // 512KB per stream

	// wsPingInterval is how often WebSocket pings are sent to keep the
	// connection alive through firewalls that kill idle connections.
	wsPingInterval = 30 * time.Second

	// wsPingTimeout is how long to wait for a pong response.
	wsPingTimeout = 10 * time.Second
)

// Server is the remote side of the tunnel. It serves an HTTP endpoint
// that upgrades connections to WebSocket for encrypted tunnel communication.
type Server struct {
	secret          string
	rateLimiter     *security.RateLimiter
	ipFilter        *security.IPFilter
	allowPrivateIPs bool

	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewServer creates a new tunnel Server with the given base64-encoded secret.
func NewServer(secret string) *Server {
	return &Server{
		secret:      secret,
		rateLimiter: security.NewRateLimiter(10, 5, 5, 5*time.Minute),
		stopCh:      make(chan struct{}),
	}
}

// Close stops background goroutines and the rate limiter.
func (s *Server) Close() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
	s.rateLimiter.Stop()
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

// Handler returns an http.Handler that serves the WebSocket tunnel endpoint
// at the given path. The path should start with "/".
func (s *Server) Handler(wsPath string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(wsPath, s.handleWebSocket)
	return mux
}

// handleWebSocket upgrades the HTTP connection to a WebSocket and runs
// the encrypted tunnel protocol over it.
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// 1. Get client IP
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

	// 4. Accept WebSocket upgrade
	wsConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// No origin check needed — this is not a browser API
		InsecureSkipVerify: true,
	})
	if err != nil {
		slog.Debug("websocket accept failed", "error", err, "ip", ip)
		return
	}

	// Disable read limit — yamux manages flow control
	wsConn.SetReadLimit(-1)

	// 5. Convert WebSocket to net.Conn.
	// Use a context derived from stopCh rather than r.Context(), because
	// r.Context() may be canceled after WebSocket hijack completes.
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-s.stopCh:
			cancel()
		case <-ctx.Done():
		}
	}()
	netConn := websocket.NetConn(ctx, wsConn, websocket.MessageBinary)

	// 6. Perform streaming handshake
	encConn, err := crypto.ServerHandshake(netConn, s.secret)
	if err != nil {
		s.rateLimiter.RecordFailure(ip)
		wsConn.Close(websocket.StatusPolicyViolation, "handshake failed")
		return
	}

	slog.Info("tunnel session established", "ip", ip)

	// 7. Create yamux server session
	yamuxCfg := yamux.DefaultConfig()
	yamuxCfg.AcceptBacklog = yamuxAcceptBacklog
	yamuxCfg.StreamCloseTimeout = yamuxStreamCloseTimeout
	yamuxCfg.StreamOpenTimeout = yamuxStreamOpenTimeout
	yamuxCfg.MaxStreamWindowSize = yamuxMaxStreamWindow
	yamuxCfg.LogOutput = io.Discard

	yamuxSes, err := yamux.Server(encConn, yamuxCfg)
	if err != nil {
		wsConn.Close(websocket.StatusInternalError, "yamux failed")
		return
	}

	// 8. Start WebSocket ping/pong keepalive to prevent firewall idle-timeout disconnects
	go startPing(ctx, wsConn)

	// 9. Accept streams (blocks until session ends)
	s.acceptStreams(yamuxSes, wsConn, cancel)
}

// acceptStreams accepts yamux streams and dispatches each one to
// handleStream. When the yamux session ends, the WebSocket is closed.
func (s *Server) acceptStreams(yamuxSes *yamux.Session, wsConn *websocket.Conn, cancelCtx context.CancelFunc) {
	defer func() {
		cancelCtx()
		yamuxSes.Close()
		wsConn.Close(websocket.StatusNormalClosure, "session ended")
	}()

	for {
		stream, err := yamuxSes.Accept()
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

	if s.allowPrivateIPs {
		var err error
		targetConn, err = net.DialTimeout("tcp4", target, 30*time.Second)
		if err != nil {
			slog.Debug("failed to dial target", "target", target, "error", err)
			return
		}
	} else {
		var err error
		targetConn, err = security.SafeDial(target)
		if err != nil {
			slog.Debug("failed to dial target", "target", target, "error", err)
			return
		}
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

// halfCloser is implemented by connections that support closing
// the write side independently (TCP half-close).
type halfCloser interface {
	CloseWrite() error
}

// relayBufPool reuses 32KB buffers to avoid per-relay allocations.
var relayBufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 32*1024)
		return &buf
	},
}

// relay copies data bidirectionally between two connections.
// It uses half-close to signal end-of-stream per direction, which
// prevents ECONNRESET errors that occur when one side finishes but
// the other is still writing.
func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	copyDir := func(dst, src net.Conn, label string) {
		defer wg.Done()
		bufPtr := relayBufPool.Get().(*[]byte)
		defer relayBufPool.Put(bufPtr)

		_, err := io.CopyBuffer(dst, src, *bufPtr)
		classifyRelayError(label, err)

		// Signal end-of-stream via half-close if supported
		if hc, ok := dst.(halfCloser); ok {
			hc.CloseWrite()
		}
	}

	go copyDir(a, b, "remote→local")
	go copyDir(b, a, "local→remote")

	wg.Wait()
	a.Close()
	b.Close()
}

// classifyRelayError logs relay errors with appropriate severity.
// Normal termination conditions (EOF, context cancelled, connection closed)
// are logged at debug level; unexpected errors at warn level.
func classifyRelayError(label string, err error) {
	if err == nil {
		return
	}

	switch {
	case errors.Is(err, io.EOF):
		slog.Debug("relay: connection closed normally", "direction", label)
	case errors.Is(err, syscall.ECONNRESET):
		slog.Debug("relay: connection reset by peer", "direction", label)
	case errors.Is(err, context.Canceled):
		slog.Debug("relay: context cancelled", "direction", label)
	case errors.Is(err, net.ErrClosed):
		slog.Debug("relay: connection already closed", "direction", label)
	default:
		slog.Warn("relay error", "direction", label, "error", err)
	}
}

// startPing sends periodic WebSocket pings to keep the connection alive
// through firewalls and proxies that kill idle connections.
// Stops when ctx is cancelled or a ping fails.
func startPing(ctx context.Context, wsConn *websocket.Conn) {
	ticker := time.NewTicker(wsPingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pingCtx, pingCancel := context.WithTimeout(ctx, wsPingTimeout)
			err := wsConn.Ping(pingCtx)
			pingCancel()
			if err != nil {
				slog.Debug("websocket ping failed", "error", err)
				return
			}
		}
	}
}

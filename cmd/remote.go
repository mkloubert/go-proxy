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

package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mkloubert/go-proxy/internal/crypto"
	"github.com/mkloubert/go-proxy/internal/security"
	"github.com/mkloubert/go-proxy/internal/tunnel"
	"github.com/spf13/cobra"
)

var remoteCmd = &cobra.Command{
	Use:   "remote",
	Short: "Start the remote proxy server",
	Long: `Start the remote proxy server that listens for encrypted tunnel
connections from the local proxy instance and handles the actual
internet requests.

The tunnel secret must be set via the GOPROXY_TUNNEL_SECRET
environment variable (base64-encoded).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// 1. Load secret
		secret, err := crypto.LoadSecret()
		if err != nil {
			return err
		}

		// 1b. Set up IP filter (ipsum.txt + GeoLite2 country blocking)
		ipFilter, err := security.NewIPFilter()
		if err != nil {
			return fmt.Errorf("ip filter setup failed: %w", err)
		}
		defer ipFilter.Close()

		// 2. Read flags
		port, _ := cmd.Flags().GetInt("port")
		wsPath, _ := cmd.Flags().GetString("path")

		// 3. Create tunnel server and HTTP server
		srv := tunnel.NewServer(secret)
		srv.SetIPFilter(ipFilter)

		httpServer := &http.Server{
			Addr:              fmt.Sprintf("0.0.0.0:%d", port),
			Handler:           srv.Handler(wsPath),
			ReadHeaderTimeout: 10 * time.Second, // Limit time to read HTTP headers
			ReadTimeout:       0,                // No read timeout — WebSocket connections are long-lived
			WriteTimeout:      0,                // No write timeout — WebSocket connections are long-lived
			IdleTimeout:       0,                // No idle timeout — ping/pong handles keepalive
		}

		// 4. Graceful shutdown
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		go func() {
			<-ctx.Done()
			slog.Info("shutting down remote server")
			httpServer.Shutdown(context.Background())
			srv.Close()
		}()

		// 5. Start HTTP server
		slog.Info("remote server started", "address", httpServer.Addr, "path", wsPath)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	},
}

func init() {
	remoteCmd.Flags().IntP("port", "p", 9876, "Port for the remote server to listen on")
	remoteCmd.Flags().String("path", envOrDefault("GOPROXY_TUNNEL_PATH", "/ws"), "WebSocket endpoint path")

	rootCmd.AddCommand(remoteCmd)
}

// envOrDefault returns the value of the environment variable key,
// or fallback if the variable is empty or unset.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

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
	"net"
	"os"
	"os/signal"
	"syscall"

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

		// 3. Start TCP listener
		ln, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", port))
		if err != nil {
			return fmt.Errorf("listen failed: %w", err)
		}
		defer ln.Close()

		slog.Info("remote server started", "address", ln.Addr().String())

		// 4. Graceful shutdown
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		go func() {
			<-ctx.Done()
			slog.Info("shutting down remote server")
			ln.Close()
		}()

		// 5. Serve
		srv := tunnel.NewServer(secret)
		srv.SetIPFilter(ipFilter)
		if err := srv.Serve(ln); err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		return nil
	},
}

func init() {
	remoteCmd.Flags().IntP("port", "p", 9876, "Port for the remote server to listen on")

	rootCmd.AddCommand(remoteCmd)
}

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
	"github.com/mkloubert/go-proxy/internal/proxy"
	"github.com/mkloubert/go-proxy/internal/tunnel"
	"github.com/spf13/cobra"
)

var localCmd = &cobra.Command{
	Use:   "local",
	Short: "Start the local proxy server",
	Long: `Start the local proxy server that accepts HTTP, HTTPS, and SOCKS5
connections and forwards all traffic through an encrypted tunnel
to the remote instance.

The tunnel secret must be set via the GOPROXY_TUNNEL_SECRET
environment variable (base64-encoded).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// 1. Load secret
		secret, err := crypto.LoadSecret()
		if err != nil {
			return err
		}

		// 2. Read flags
		port, _ := cmd.Flags().GetInt("port")
		connectTo, _ := cmd.Flags().GetString("connect-to")
		bindAddr, _ := cmd.Flags().GetString("bind")

		// 3. Create tunnel client and connect
		client := tunnel.NewClient(connectTo, secret)
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		if err := client.Connect(ctx); err != nil {
			return fmt.Errorf("tunnel connect failed: %w", err)
		}
		defer client.Close()

		// 4. Create dial function that opens tunnel streams
		dial := func(target string) (net.Conn, error) {
			return client.OpenStream(target)
		}

		// 5. Start local proxy listener
		ln, err := net.Listen("tcp4", fmt.Sprintf("%s:%d", bindAddr, port))
		if err != nil {
			return fmt.Errorf("listen failed: %w", err)
		}
		defer ln.Close()

		slog.Info("local proxy started", "address", ln.Addr().String(), "remote", connectTo)

		// 6. Graceful shutdown
		go func() {
			<-ctx.Done()
			ln.Close()
		}()

		// 7. Serve
		handler := proxy.NewProxyHandler(dial)
		if err := handler.Serve(ln); err != nil {
			select {
			case <-ctx.Done():
				return nil // normal shutdown
			default:
				return err
			}
		}
		return nil
	},
}

func init() {
	localCmd.Flags().IntP("port", "p", 8080, "Port for the local proxy to listen on")
	localCmd.Flags().StringP("bind", "b", "127.0.0.1", "Address to bind the local proxy to")
	localCmd.Flags().StringP("connect-to", "c", "", "Remote server URL (e.g., http://example.com:80)")
	_ = localCmd.MarkFlagRequired("connect-to")

	rootCmd.AddCommand(localCmd)
}

# go-proxy MVP Design

## Overview

`go-proxy` is a CLI tool that provides a fully compatible HTTP/HTTPS/SOCKS5 proxy running locally, tunneled through an AES-256-GCM encrypted connection to a remote server. The goal is to prevent MITM attacks in untrusted corporate networks.

## Architecture

```
+-------------------+          +--------------------+
|   Local Machine   |          |   Remote Server    |
|                   |          |   (Trusted Network) |
|  Browser/App      |          |                    |
|      |            |          |                    |
|  [HTTP/HTTPS/     |  AES-256 |                    |
|   SOCKS5 Proxy]   |<-------->| [Tunnel Server]    |
|  127.0.0.1:12345  |  yamux   |  0.0.0.0:9876      |
|                   |  over    |       |             |
+-------------------+  TCP     |   [Internet]       |
                               +--------------------+
```

## Components

### CLI (Cobra)

- `go-proxy local --port=12345 --connect-to="host:port"` -- Starts local proxy
- `go-proxy remote --port=9876` -- Starts remote server
- `GOPROXY_TUNNEL_SECRET` env var for encryption key (base64-encoded)
- `--verbose` flag for debug logging

### Project Structure

```
go-proxy/
  cmd/
    root.go          # Root command, version info
    local.go         # "go-proxy local" subcommand
    remote.go        # "go-proxy remote" subcommand
  internal/
    crypto/
      tunnel.go      # AES-256-GCM encrypted connection (framing)
      keys.go        # HKDF key derivation from GOPROXY_TUNNEL_SECRET
    proxy/
      handler.go     # HTTP/HTTPS/SOCKS5 protocol detection and routing
      http.go        # HTTP forward proxy (plain HTTP + CONNECT tunneling)
      socks5.go      # SOCKS5 proxy (via things-go/go-socks5)
    tunnel/
      client.go      # Tunnel client (local -> remote yamux session)
      server.go      # Tunnel server (remote, accepts yamux streams)
  main.go            # Entrypoint
```

### Encryption Layer (AES-256-GCM)

**Key Derivation:**
1. `GOPROXY_TUNNEL_SECRET` is read from env and base64-decoded
2. HKDF (SHA-256) derives:
   - Encryption Key (32 bytes for AES-256)
   - Nonce prefix for extra entropy
3. Salt is exchanged during connection handshake (randomly generated)

**Framing Protocol:**
Each frame over TCP:
```
[4 bytes: length of encrypted payload (big-endian)]
[12 bytes: nonce]
[N bytes: AES-256-GCM encrypted payload + 16-byte auth tag]
```

- Nonce: combination of counter + random prefix (prevents nonce reuse)
- Max frame size: 64KB
- `crypto/rand` for all random values

**Handshake:**
1. Client connects via TCP to remote
2. Client sends: `[32 bytes random salt]`
3. Server receives salt, derives keys via HKDF
4. Both sides now have identical keys
5. First encrypted message: challenge/response for key verification

Implemented as a `net.Conn` wrapper (reads/writes encrypted, transparent to yamux).

### Tunnel and Multiplexing

**Local (Client):**
1. Establishes TCP connection to remote
2. Performs handshake (salt exchange)
3. Wraps connection in AES-256-GCM `net.Conn` wrapper
4. Creates `yamux.Client` session over encrypted connection
5. For each proxy request: opens new `yamux.Stream`
6. Sends target address as header over stream
7. Relays data bidirectionally (`io.Copy`)

**Remote (Server):**
1. Listens on TCP port
2. Accepts connections, performs handshake
3. Wraps in AES-256-GCM wrapper
4. Creates `yamux.Server` session
5. For each incoming stream:
   - Reads target address
   - Opens TCP connection to target (internet)
   - Relays data bidirectionally

**Stream Protocol:**
```
[2 bytes: length of target address]
[N bytes: target address string, e.g. "example.com:443"]
[... then: raw TCP data stream bidirectional ...]
```

**Reconnect Logic:**
- If tunnel drops, client reconnects automatically
- Exponential backoff (1s, 2s, 4s, max 30s)
- Running proxy connections are closed on reconnect

### Local Proxy (Protocol Detection)

**Protocol Detection:**
- Peeks at first byte using `bufio.Reader.Peek(1)`
- `0x05` = SOCKS5 (version byte)
- Anything else = HTTP/HTTPS (ASCII method names)

**HTTP Proxy:**
- Plain HTTP: parse request, extract target, relay through tunnel
- HTTPS (CONNECT): client sends `CONNECT host:port`, proxy responds `200 OK`, then bidirectional relay through tunnel

**SOCKS5 Proxy:**
- `things-go/go-socks5` with custom `WithDial` function
- Dial function opens a new yamux stream instead of a direct TCP connection
- Every SOCKS5 connection is automatically routed through the encrypted tunnel

### Error Handling and Logging

**Logging:**
- Go stdlib `log/slog` for structured logging
- Log level via `--verbose` flag (default: Info, verbose: Debug)

**Error Handling:**
- Tunnel errors: reconnect with exponential backoff
- Proxy errors: individual failed connections are closed, others continue
- Invalid keys: clear error message at startup
- Graceful shutdown: SIGINT/SIGTERM caught, all connections closed cleanly

### Security

- Local proxy listens only on `127.0.0.1` (not `0.0.0.0`)
- Key material is never logged
- `crypto/rand` for all random values
- HKDF with context-specific info strings

## Dependencies

| Component | Library |
|---|---|
| CLI | `github.com/spf13/cobra` v1.10.2 |
| SOCKS5 | `github.com/things-go/go-socks5` (latest) |
| Multiplexing | `github.com/hashicorp/yamux` (latest) |
| Key Derivation | `crypto/hkdf` (Go stdlib) |
| Encryption | `crypto/aes` + `crypto/cipher` (Go stdlib) |
| Logging | `log/slog` (Go stdlib) |

## Decisions

- **Yamux over AES-256-GCM** chosen over per-connection encryption (efficiency, firewall-friendly) and TLS 1.3 PSK (matches CLAUDE.md requirements better)
- **things-go/go-socks5** chosen over armon/go-socks5 (actively maintained fork with more features)
- **All three protocols on same port** via protocol detection (first byte peek)
- **HKDF for key derivation** instead of using raw key (security best practice)

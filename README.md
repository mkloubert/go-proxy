# go-proxy

A CLI tool that provides a local HTTP/HTTPS/SOCKS5 proxy with an encrypted tunnel to a remote server. It prevents man-in-the-middle attacks in untrusted networks by tunneling all traffic over an encrypted WebSocket connection.

## How It Works

`go-proxy` has two modes:

- **Remote mode**: Runs on a trusted server with direct internet access. It serves a WebSocket endpoint that accepts encrypted tunnel connections.
- **Local mode**: Runs on your machine in the untrusted network. It accepts proxy connections (HTTP, HTTPS, SOCKS5) and sends all traffic through the encrypted WebSocket tunnel to the remote server.

All data between local and remote is encrypted with AES-256-GCM and compressed with zstd, transported over a WebSocket connection. WebSocket is used because it works through corporate proxies and firewalls that allow standard HTTP/HTTPS traffic.

```
Your Machine (untrusted network)        Trusted Server
+---------------------------+           +---------------------------+
| Browser / App             |           |                           |
|       |                   |           |                           |
| [go-proxy local]          | WebSocket | [go-proxy remote]         |
| HTTP/HTTPS/SOCKS5 proxy   |<--------->| WebSocket tunnel server   |
| 127.0.0.1:12345           | encrypted |       |                   |
+---------------------------+  tunnel   |   Internet                |
                                        +---------------------------+
```

## How the Tunnel Works

1. The local proxy connects to the remote server over WebSocket (default path: `/ws`).
2. A cryptographic handshake (challenge/response) verifies both sides share the same secret.
3. All data is encrypted with AES-256-GCM and compressed with zstd before being sent over the WebSocket.
4. Multiple streams are multiplexed over a single connection using yamux.
5. Each proxy request opens a new stream through the tunnel to reach its target.

## Build

```bash
go build -o go-proxy .
```

## Setup

### 1. Create a Shared Secret

Generate a random secret and encode it as base64:

```bash
# Generate a 32-byte random key and encode as base64
openssl rand -base64 32
```

Set this value as an environment variable on both machines:

```bash
export GOPROXY_TUNNEL_SECRET="your-base64-encoded-secret-here"
```

### 2. Start the Remote Server

On the trusted server (with direct internet access):

```bash
export GOPROXY_TUNNEL_SECRET="your-base64-encoded-secret-here"
./go-proxy remote --port=9876
```

You can change the WebSocket endpoint path with `--path` (default: `/ws`):

```bash
./go-proxy remote --port=9876 --path="/api/v2/events"
```

### 3. Start the Local Proxy

On your local machine (in the untrusted network):

```bash
export GOPROXY_TUNNEL_SECRET="your-base64-encoded-secret-here"
./go-proxy local --port=12345 --connect-to="example.com:9876"
```

The `--connect-to` flag accepts these formats:
- `host:port` (plain WebSocket)
- `ws://host:port` (explicit WebSocket)
- `wss://host:port` (WebSocket over TLS)

If you changed `--path` on the remote, set the same on the local side:

```bash
./go-proxy local --port=12345 --connect-to="example.com:9876" --path="/api/v2/events"
```

### 4. Configure Your Applications

Point your browser or application to use the local proxy:

- **HTTP/HTTPS proxy**: `http://127.0.0.1:12345`
- **SOCKS5 proxy**: `socks5://127.0.0.1:12345`

#### Example with curl

```bash
# HTTP proxy
curl -x http://127.0.0.1:12345 https://example.com

# SOCKS5 proxy
curl --socks5 127.0.0.1:12345 https://example.com
```

#### Example with environment variables

```bash
export HTTP_PROXY=http://127.0.0.1:12345
export HTTPS_PROXY=http://127.0.0.1:12345
```

## CLI Reference

### `go-proxy local`

Start the local proxy.

| Flag           | Short | Default    | Description                                                          |
| -------------- | ----- | ---------- | -------------------------------------------------------------------- |
| `--port`       | `-p`  | 8080       | Port for the local proxy                                             |
| `--connect-to` | `-c`  | (required) | Remote server address (e.g., `example.com:9876` or `ws://host:port`) |
| `--path`       |       | `/ws`      | WebSocket endpoint path (must match remote)                          |
| `--verbose`    | `-v`  | false      | Enable debug logging                                                 |

### `go-proxy remote`

Start the remote tunnel server.

| Flag        | Short | Default | Description                  |
| ----------- | ----- | ------- | ---------------------------- |
| `--port`    | `-p`  | 9876    | Port for the remote server   |
| `--path`    |       | `/ws`   | WebSocket endpoint path      |
| `--verbose` | `-v`  | false   | Enable debug logging         |

### Environment Variables

| Variable                    | Description                                                                                                                |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `GOPROXY_TUNNEL_SECRET`     | Base64-encoded shared secret for AES-256 tunnel encryption (required)                                                      |
| `GOPROXY_TUNNEL_PATH`       | WebSocket endpoint path (default: `/ws`). Must match on both sides.                                                        |
| `GOPROXY_BLOCKED_COUNTRIES` | Comma-separated ISO country codes to block (e.g. `CN,RU,IR`). Only used when `GeoLite2.mmdb` is present. Case-insensitive. |

## IP Blocking (Remote Server)

The remote server can block incoming connections based on IP reputation and geolocation. Both features are optional and activate automatically when their data files are present in the working directory.

### ipsum.txt (Threat Intelligence)

Place an `ipsum.txt` file (from [stamparm/ipsum](https://github.com/stamparm/ipsum)) in the working directory of the remote server. IPs with a threat level of 3 or higher are blocked automatically.

```bash
# Download the latest ipsum.txt
curl -o ipsum.txt https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt
```

### GeoLite2 Country Blocking

Place a `GeoLite2.mmdb` file (from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/)) in the working directory and set the `GOPROXY_BLOCKED_COUNTRIES` environment variable.

```bash
export GOPROXY_BLOCKED_COUNTRIES="CN,RU,IR"
./go-proxy remote --port=9876
```

Country codes are [ISO 3166-1 alpha-2](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2), case-insensitive, and whitespace is trimmed.

## NGINX Reverse Proxy

In production you usually put `go-proxy remote` behind NGINX with a TLS certificate. This way the tunnel looks like normal HTTPS traffic to any firewall or corporate proxy. Pick a path that looks like a real API endpoint so the WebSocket upgrade does not stand out.

### Basic Setup

```
Client (untrusted network)        NGINX (public)         go-proxy remote (localhost)
                                  ┌──────────────┐
go-proxy local ──── WSS/443 ────▶ │  TLS termination  │──── WS/9876 ────▶ 127.0.0.1:9876
                                  │  reverse proxy     │
                                  └──────────────┘
```

### Example Configuration

```nginx
server {
    listen 443 ssl;
    server_name app.example.com;

    ssl_certificate     /etc/letsencrypt/live/app.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/app.example.com/privkey.pem;

    # Tunnel endpoint — pick any path that looks normal
    location /api/v2/events {
        proxy_pass http://127.0.0.1:9876;

        # Required for WebSocket upgrade
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # No timeouts — tunnel connections are long-lived,
        # keepalive is handled by WebSocket ping/pong
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;

        # Forward client IP
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $host;

        # Do not buffer — pass data through immediately
        proxy_buffering off;
    }

    # Everything else returns 404 (no hint that a tunnel exists here)
    location / {
        return 404;
    }
}
```

### Start the Services

On the server:

```bash
export GOPROXY_TUNNEL_SECRET="your-base64-encoded-secret-here"
./go-proxy remote --port=9876 --path="/api/v2/events"
```

On the client (in the untrusted network):

```bash
export GOPROXY_TUNNEL_SECRET="your-base64-encoded-secret-here"
./go-proxy local --port=12345 --connect-to="wss://app.example.com" --path="/api/v2/events"
```

Note that the client uses `wss://` (WebSocket over TLS) since NGINX terminates TLS. The `--path` must match on both sides.

### What a Network Observer Sees

| Layer     | Visible to firewall / corporate proxy            |
| --------- | ------------------------------------------------ |
| DNS       | `app.example.com` — looks like a normal web app  |
| TLS       | Standard TLS 1.3 to port 443                     |
| HTTP      | `GET /api/v2/events` with `Upgrade: websocket`   |
| Payload   | Opaque binary WebSocket frames (AES-256-GCM)     |

There is no way to tell this apart from a normal web application that uses WebSocket for real-time events.

## Security

- All tunnel traffic is encrypted with AES-256-GCM before being sent over WebSocket.
- Data is compressed with zstd for better throughput.
- Keys are derived using HKDF (SHA-256) with a random salt per session.
- A challenge/response handshake verifies both sides share the same secret.
- The encryption key is never logged.
- IP blocking via threat intelligence feeds and GeoIP country filtering (remote server).
- SSRF protection prevents the remote server from connecting to private/internal IPs.

## License

[MIT License](./LICENSE)

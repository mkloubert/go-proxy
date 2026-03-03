# go-proxy

A CLI tool that provides a local HTTP/HTTPS/SOCKS5 proxy with an encrypted tunnel to a remote server. It prevents man-in-the-middle attacks in untrusted networks.

## How It Works

`go-proxy` has two modes:

- **Remote mode**: Runs on a trusted server with direct internet access. It listens for encrypted tunnel connections and forwards traffic to the internet.
- **Local mode**: Runs on your machine in the untrusted network. It accepts proxy connections (HTTP, HTTPS, SOCKS5) and sends all traffic through an encrypted tunnel to the remote server.

All traffic between local and remote is encrypted with AES-256-GCM. The encryption key is shared via an environment variable.

```
Your Machine (untrusted network)        Trusted Server
+---------------------------+           +---------------------------+
| Browser / App             |           |                           |
|       |                   |           |                           |
| [go-proxy local]          |  AES-256  | [go-proxy remote]         |
| HTTP/HTTPS/SOCKS5 proxy   |<--------->| Tunnel server             |
| 127.0.0.1:12345           |  encrypted|       |                   |
+---------------------------+   tunnel  |   Internet                |
                                        +---------------------------+
```

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

### 3. Start the Local Proxy

On your local machine (in the untrusted network):

```bash
export GOPROXY_TUNNEL_SECRET="your-base64-encoded-secret-here"
./go-proxy local --port=12345 --connect-to="your-server.com:9876"
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

| Flag           | Short | Default    | Description                       |
| -------------- | ----- | ---------- | --------------------------------- |
| `--port`       | `-p`  | 8080       | Port for the local proxy          |
| `--connect-to` | `-c`  | (required) | Remote server address (host:port) |
| `--verbose`    | `-v`  | false      | Enable debug logging              |

### `go-proxy remote`

Start the remote tunnel server.

| Flag        | Short | Default | Description                |
| ----------- | ----- | ------- | -------------------------- |
| `--port`    | `-p`  | 9876    | Port for the remote server |
| `--verbose` | `-v`  | false   | Enable debug logging       |

### Environment Variables

| Variable                | Description                                                           |
| ----------------------- | --------------------------------------------------------------------- |
| `GOPROXY_TUNNEL_SECRET` | Base64-encoded shared secret for AES-256 tunnel encryption (required) |

## Security

- Both local and remote listen on `0.0.0.0` (all interfaces) by default.
- All traffic between local and remote is encrypted with AES-256-GCM.
- Keys are derived using HKDF (SHA-256) with a random salt per connection.
- A challenge/response handshake verifies both sides share the same secret.
- The encryption key is never logged.

## License

[MIT License](./LICENSE)
